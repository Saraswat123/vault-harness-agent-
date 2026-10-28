"""Model selection. Both providers speak the OpenAI wire format, so one client class covers them.

LLM_PROVIDER forces one provider. Otherwise every provider with a key is chained
(OpenRouter first, then Groq) so a free-tier 429 falls through to the next.
No key at all -> the offline scripted model passed in by the caller.

LLM_TIMEOUT_S is the per-attempt HTTP timeout (default 90 s). With one retry a provider can block for about
twice that, and a fallback adds a second provider. Empty, non-numeric or non-positive values use the default.
"""
import os

GROQ_DEFAULT = "openai/gpt-oss-120b"
OPENROUTER_DEFAULT = "nvidia/nemotron-3-super-120b-a12b:free"
DEFAULT_TIMEOUT_S = 90.0
PROVIDERS = {   # name -> (base_url, key env var, model env var, default model)
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY", "GROQ_MODEL", GROQ_DEFAULT),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY", "OPENROUTER_MODEL", OPENROUTER_DEFAULT),
}


def _timeout() -> float:
    try:
        v = float(os.environ.get("LLM_TIMEOUT_S", "").strip())
    except ValueError:
        return DEFAULT_TIMEOUT_S
    return v if v > 0 else DEFAULT_TIMEOUT_S


def _chat(provider: str):
    from langchain_openai import ChatOpenAI
    base_url, key_env, model_env, default = PROVIDERS[provider]
    return ChatOpenAI(model=os.environ.get(model_env, default), api_key=os.environ[key_env], base_url=base_url,
                      temperature=0.3, max_retries=1, timeout=_timeout())


def build_model(offline_factory):
    forced = os.environ.get("LLM_PROVIDER", "").strip().lower()
    if forced and forced not in PROVIDERS:
        raise RuntimeError(f"unknown LLM_PROVIDER {forced!r} (use {' or '.join(PROVIDERS)})")
    order = [forced] if forced else [p for p in ("openrouter", "groq") if os.environ.get(PROVIDERS[p][1])]
    for p in order:
        if not os.environ.get(PROVIDERS[p][1]):
            raise RuntimeError(f"LLM_PROVIDER={p} but {PROVIDERS[p][1]} is not set")
    if not order:
        return offline_factory()
    models = [_chat(p) for p in order]
    return models[0].with_fallbacks(models[1:]) if len(models) > 1 else models[0]
