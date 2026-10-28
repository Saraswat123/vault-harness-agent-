"""Deterministic checks on what the model wrote. Code, not an LLM. Edit these for your agent.
A draft that returns any violation is sent back to the writer (max 3 tries). Rules that need
judgement (is it accurate? does it answer the question?) stay with the human reviewer."""
import re

MAX_WORDS = 120
BANNED = [r"\bTODO\b", r"\bas an ai\b", r"\bi hope this finds you\b"]


def validate(text: str) -> list[str]:
    v = []
    t = (text or "").strip()
    if not t:
        return ["draft is empty"]
    if len(t.split()) > MAX_WORDS:
        v.append(f"draft is longer than {MAX_WORDS} words")
    for pat in BANNED:
        if re.search(pat, t, re.I):
            v.append(f"banned phrase matched: /{pat}/")
    return v
