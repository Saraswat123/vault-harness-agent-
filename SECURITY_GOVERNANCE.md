# Security Governance and AI System Design

**Review date:** 2026-11-16  
**Scope:** Vault Harness repository and the AI agent/payment flow documented here.  
**Status:** Evidence-based engineering record; not a compliance certification or production security approval.

## How to read this document

- **Implemented / evidenced** means the source contains the control and the referenced tests or evaluation cases exist. This document does not claim those tests were rerun for this review.
- **Partial** means a control exists but has a material boundary, limitation, or untested production assumption.
- **Not implemented** means the capability was not found in the reviewed repository. It must not be described as a shipped feature.
- **Not applicable today** means the architecture does not currently use that component; the row gives the control expectations if it is introduced.

Evidence links point to repository files and tests. See [`docs/GUARDRAILS.md`](docs/GUARDRAILS.md), [`docs/CREDENTIAL_ISOLATION.md`](docs/CREDENTIAL_ISOLATION.md), and [`docs/PRT.md`](docs/PRT.md) for the longer control inventory, boundaries, and known risks.

## Current architecture and evidence

The LangGraph flow asks a model to propose a small JSON purchase intent. Deterministic code parses the response and applies policy, spending, velocity, and risk checks. The action node is the only payment side-effect path. Depending on policy, the flow auto-approves, pauses for a human, or denies. See [`vault_harness/graph.py`](vault_harness/graph.py), [`vault_harness/policy.py`](vault_harness/policy.py), and [`vault_harness/guard.py`](vault_harness/guard.py).

| Area | Status | Evidence and boundary |
|---|---|---|
| Model provider selection | Implemented, limited | [`vault_harness/models.py`](vault_harness/models.py) supports OpenRouter and Groq, environment-selected model names, a forced provider, and provider fallback when both keys are configured. It is provider/error fallback, not semantic task routing or quality-based routing. No keys means the caller-provided scripted offline model. |
| Model call controls | Partial | Timeout defaults to 90 seconds and the client allows one retry. No repository-enforced maximum input/output token count, context-window policy, per-request inference cost cap, or tenant quota was found. |
| Structured output boundary | Implemented, evidenced | [`vault_harness/policy.py`](vault_harness/policy.py) rejects invalid JSON, unknown fields, empty merchants, and non-integer amounts. It bounds the description length and normalizes merchant/currency. Existing cases are listed in [`docs/GUARDRAILS.md`](docs/GUARDRAILS.md). |
| Deterministic payment policy | Implemented, evidenced | Merchant/currency allowlists, caps, budgets, expiry, velocity, and risk controls are applied in code. The enclave program repeats selected critical checks. See [`vault_harness/guard.py`](vault_harness/guard.py), [`vault_harness/enclave.py`](vault_harness/enclave.py), and the G1–G24 inventory in [`docs/GUARDRAILS.md`](docs/GUARDRAILS.md). |
| Approval | Partial | Policy can pause for human review and the passkey assertion is bound to payment details in the enclave program. Testing documented to date uses a software authenticator; real-device Touch ID/Face ID and production hardware isolation are not established. Small transactions can be automatic under policy. |
| Card data handling | Partial | The model receives a redacted task and does not receive the card number through the intended flow; PAN-like 13–19 digit sequences are redacted/detected. This is not general PII/DLP coverage. The enclave is a separate program, **not a deployed AWS Nitro hardware enclave**. See [`docs/CREDENTIAL_ISOLATION.md`](docs/CREDENTIAL_ISOLATION.md). |
| Secrets | Partial | Provider and payment credentials are read from environment variables; `.env` is intended for local use and ignored by Git. This is not a managed secret store or proof that every deployment/CI log is protected. Rotate credentials if exposure is suspected. Never put secret values in this document. |
| Audit and observability | Partial | The repository includes event/ledger and tracing/alert code. Persistence and operational guarantees are local/deployment-dependent; webhook authenticity and centralized, tamper-resistant retention are not established. See [`vault_harness/tracing.py`](vault_harness/tracing.py), [`vault_harness/alerts.py`](vault_harness/alerts.py), and [`docs/GUARDRAILS.md`](docs/GUARDRAILS.md). |
| API authorization | Known gap | Existing documentation says the local agent endpoint is not authenticated beyond its local-machine boundary. Do not expose it to an untrusted network. Production deployment requires authenticated identity, authorization, and network/service isolation. |
| Model tool access | Narrow / partial | The model proposes intent; deterministic application code performs the defined action. No general-purpose model tool registry or arbitrary shell access is established. The application/API boundary still needs deployment hardening. |
| Prompt injection and jailbreak resistance | Partial | The flow constrains output and deterministic policy prevents the model from setting policy. Existing scripted attack/evaluation cases include prompt injection and malformed/smuggled fields. These do not establish robustness against a live model, novel jailbreaks, indirect injection in arbitrary retrieved content, or all user inputs. |

## AI system design capability register

These entries cover the requested model routing, caching, serving, RAG, fine-tuning, latency, and cost topics. Status is based on the reviewed repository, not on a target architecture proposal.

| Capability | Current status | What is present / what is needed to call it implemented |
|---|---|---|
| Provider routing and fallback | **Implemented, basic** | OpenRouter/Groq selection and fallback on provider errors exist in `models.py`. Add task/quality/latency/cost-aware routing, health policy, and routing telemetry before claiming intelligent model routing. |
| Semantic cache | **Not implemented** | No semantic response cache was found. If added, define tenant/user isolation, cache key and similarity policy, TTL/invalidation, sensitive-data exclusions, and stale-response tests. |
| Prefix/KV cache | **Not implemented here** | No serving-layer prefix cache is configured. This is normally a model-serving concern, not evidence of an application cache. |
| Token/context budget | **Not implemented** | There is a timeout and a three-attempt graph limit, but no explicit prompt token ceiling, output token ceiling, context truncation policy, or token accounting identified. Add hard limits and test oversized inputs before claiming budget enforcement. |
| Async pipeline and streaming responses | **Not implemented / not evidenced** | The graph invokes the model synchronously via `invoke`; no user-facing token stream or asynchronous inference pipeline was identified. |
| vLLM, continuous batching, PagedAttention | **Not implemented** | The configured providers are hosted APIs. No vLLM deployment, continuous batching, or PagedAttention configuration was found. |
| RAG pipeline | **Not implemented** | No retrieval/indexing pipeline was found in this agent. If introduced, add document provenance, access filtering, untrusted-content delimiting, poisoning tests, retrieval evaluation, deletion/retention policy, and controls preventing retrieved instructions from authorizing actions. |
| Fine-tuning pipeline | **Not implemented** | No dataset curation, training, evaluation, model registry, or deployment pipeline was found. Fine-tuning must include privacy/licensing review, held-out safety evaluation, versioning, and rollback evidence. |
| Inference cost optimization | **Not implemented / unmeasured** | Payment-spend caps are not model-inference budgets. No per-request token/cost ledger or inference budget enforcement was identified. Add provider usage capture, limits, alerting, and fallback accounting. |
| Model evaluation | **Partial** | The repository documents offline scripted cases and evaluation coverage for guardrails/plumbing. This does not measure live-model answer quality or adversarial robustness. Keep model/version and evaluation results with each release. |
| MCP servers and external tool trust | **Not applicable today** | No MCP server integration was identified in this agent. Before adding one, require explicit tool allowlists, scoped credentials, caller authorization, argument validation, approval for consequential actions, untrusted tool-result handling, and auditable request/result records. |

## Detailed model and agent design record

This section records the requested design checklist against the code as it exists today. Values below describe repository defaults; environment configuration can change the provider/model. Provider model limits are service specifications and can change, so verify them against the active account and model before deployment.

### 1. Model and provider

- **Groq provider:** supported through the OpenAI-compatible endpoint in [`vault_harness/models.py`](vault_harness/models.py).
- **Default Groq model:** `openai/gpt-oss-120b`; `GROQ_MODEL` can override it. OpenRouter is the other configured provider and uses `nvidia/nemotron-3-super-120b-a12b:free` by default.
- **Context window:** Groq currently lists GPT-OSS 120B with a 131,072-token context window and 65,536 maximum output tokens. These are provider/model limits, not application-enforced limits. The configured model can be overridden, so the applicable limit must be checked for that model. See [Groq's GPT-OSS 120B model page](https://console.groq.com/docs/model/openai/gpt-oss-120b).
- **Application input/output limits:** no explicit `max_tokens`/output cap or request token ceiling was found in the model client. Provider hard limits and rate limits still apply; they do not replace application budgets.
- **Routing/fallback:** default order is OpenRouter, then Groq when both credentials are configured; `LLM_PROVIDER` can force either. Fallback handles provider errors, not semantic task type, quality, price, or latency. No fallback model is defined within Groq itself; Groq is the fallback provider in the default chain.
- **No keys:** `build_model` uses the caller's offline scripted model. That path is for deterministic local tests and is not a live-model substitute.

### 2. Transformer and inference architecture

The repository calls hosted inference APIs; it does not implement transformer layers, attention, KV memory, GPU scheduling, or model weights. At a high level, a transformer tokenizes input into token IDs, computes token representations through attention and feed-forward layers, and generates output tokens autoregressively. In decoder inference, a KV cache retains prior attention keys/values during generation so the model need not recompute the entire prefix for every next token.

| Concern | Who manages it in this repository |
|---|---|
| Tokenization, model architecture, attention kernels, KV cache memory, accelerators, batching, serving capacity | Groq or OpenRouter provider |
| Prompt text, selected model ID, provider order, HTTP timeout, graph attempts, parsing, business policy | Application |
| Provider queue time, throughput, rate limits, cached-prefix usage and request token counts | Provider reports some usage/latency fields; application does not currently persist a complete inference metrics ledger |
| User-level concurrency/backpressure, end-to-end latency SLO, cost budget, circuit breaker | Not evidenced as implemented; must be added at the service layer |

Do not describe provider KV caching as an application-managed cache. Groq documents automatic prefix prompt caching for supported models, but this code does not request cache management or record cache hit/miss metrics. See [Groq prompt caching](https://console.groq.com/docs/prompt-caching).

### 3. Prompt architecture

- **System prompt:** `SYSTEM` in [`vault_harness/graph.py`](vault_harness/graph.py) asks for exactly one JSON purchase object and says not to include card details.
- **User prompt:** the current task plus correction feedback from a rejected draft. Card-like digit sequences are redacted before entering the graph state.
- **Tool descriptions:** none are passed as model tools in this flow. The payment action is application code after validation and policy checks.
- **Conversation history:** no general multi-turn chat history is assembled for the model; the workflow carries task, draft, and retry feedback. A graph checkpointer may persist workflow state, but that is not a designed summarization/compression system.
- **Context compression:** not implemented. Keep large LMS records out of prompts; fetch only authorized fields and summarize with provenance if a future product needs it.
- **Prompt versioning:** no dedicated prompt registry/version ID was identified. The prompt is source code; use a recorded prompt revision/hash and evaluation set when changing it.

### 4. Sampling and generation parameters

The OpenAI-compatible client sets `temperature=0.3`, `max_retries=1`, and a timeout from `LLM_TIMEOUT_S` (default 90 seconds). No `top_p`, maximum output token value, stop sequences, or tool-choice setting is configured in the application. The structured purchase intent is intended to be stable and constrained; creative generation is not the task. Provider-side reasoning capability does not grant authority to make a payment: deterministic code controls the action.

### 5. Reasoning and agent execution

- **Reasoning-model behavior:** model internals/hidden reasoning are provider-managed. The application should consume only the required structured result and must not expose hidden chain-of-thought. If user-facing explanations are added, return a brief decision summary grounded in policy/tool results.
- **Planning and tool loop:** current flow is a LangGraph state machine (`work → check → review/act/deny`); it is not an open-ended plan-and-call-tools loop. There are no model tool schemas or model-selected external tools.
- **Maximum steps/retries:** `MAX_ATTEMPTS = 3` limits rejected intent-generation attempts in [`vault_harness/graph.py`](vault_harness/graph.py). Provider client retry is separately configured to one retry. These limits are not a universal request/deadline budget.
- **Action authority:** only validated intent reaches deterministic policy; only the action path performs the payment side effect. Preserve this separation if the flow grows.

### 6. Structured output

There are no model function-call schemas configured. The model is prompted to return JSON; [`vault_harness/policy.py`](vault_harness/policy.py) parses it into the typed `Intent` contract, rejects unknown/mistyped fields and card-like data, and bounds description length. Invalid output returns corrective feedback for another attempt, up to three attempts, then fails closed. The downstream graph tracks typed state/outcomes, while action results are ordinary application data, not a generated tool-call contract. See existing cases in [`docs/GUARDRAILS.md`](docs/GUARDRAILS.md).

### 7–8. Context/KV efficiency, token cost, and prompt caching

Application-side context trimming, conversation summaries, tool-result compaction, and database-field selection are not implemented as a general subsystem. This payment flow sends a small task and a short schema instruction; keep it that way. If LMS support is added, fetch only fields authorized for the caller and needed for the answer, and keep results compact.

No application metrics currently establish input tokens, output tokens, tool-result tokens, cost per request/task, or cache hit rate. Groq's service may automatically cache matching prompt prefixes for supported models; its documentation describes exact-prefix matching and usage fields such as cached token counts. Treat this as provider-managed behavior and explicitly capture usage metadata before claiming cost or cache optimization. Use stable system instructions and tool schemas before per-request data to improve the chance of prefix matches, while keeping tenant-specific/private data isolated and never relying on cache behavior for authorization.

### 9. Hallucination and grounding controls for an LMS agent

The current repository is a payment-agent project, not an LMS integration. It has no LMS connector, campus/role model, or live LMS source of truth. Therefore the following are **requirements for a future LMS agent**, not implemented controls:

- Never guess live LMS data such as grades, enrollment, attendance, deadlines, or course counts; query an authorized source for current values.
- Apply role, user, campus, course, and record-level authorization before retrieval, not only in the prompt. Do not let model-generated filters expand access.
- Return “I don’t know” or ask for clarification when data is absent, stale, conflicting, or unauthorized.
- Preserve source identity, record timestamp/version, and retrieval provenance; cite the data used when appropriate.
- Validate the final response against tool results and permissions; a successful tool call is not by itself proof the response is complete or correctly scoped.
- Add negative tests for unauthorized cross-role/campus/tenant access and prompt injection embedded in LMS content.

### 10. Evaluation and reliability

Existing offline evaluation cases cover payment guardrails and scripted attacks, not LMS task quality or live model behavior. Before launch of an LMS assistant, build an approved, de-identified golden dataset and track at minimum: task completion, tool-selection accuracy, argument accuracy, unsupported-claim/hallucination rate, unauthorized-data access attempts, latency p50/p95, retry rate, and failure rate. Define pass thresholds and owners before deployment. Report results by model, prompt, tool, and dataset version; include regression cases for each incident. Do not use aggregate success rate to hide security-critical failures.

### 11–12. Fine-tuning, QLoRA, and distillation

No training or fine-tuning pipeline exists in this repository. Consider fine-tuning only after representative evaluation data shows a repeatable gap and prompt, retrieval, or tool changes have been assessed. Use approved instruction examples, remove or protect personal/sensitive data, separate training and validation sets, document licenses and provenance, and evaluate safety/regressions before release. QLoRA requires a separately hosted fine-tuned model and serving path; it does not modify the Groq-hosted `openai/gpt-oss-120b` model.

For distillation, a stronger teacher may draft examples, but filter them and require human review before training. Compare student quality, security, cost, and latency against the baseline. Keep security-sensitive decisions deterministic in application policy rather than relying on fine-tuned model behavior.

### 13. Auto-agent learning and change control

The agent does not autonomously train on user feedback or modify its own prompts/tools. A safe future improvement loop should store feedback and failed tasks under a retention/access policy, convert them into reviewed examples, version prompts and tool definitions, run regression and security evaluations, and promote changes only after an authorized reviewer approves them. Production agents must not self-modify prompts, policies, tools, or model routing without controlled review and rollback.

## Security threat areas and operating requirements

| Threat area | Current control/evidence | Remaining requirement |
|---|---|---|
| Prompt injection / jailbreak | Strict intent schema, policy checks independent of model text, and scripted attack cases. | Run adversarial tests against each actual production model and prompt version; test direct and indirect injection; ensure tool/action authorization never depends on model compliance alone. |
| Input and output validation | JSON schema-like deterministic parser; PAN scan/redaction. | Define handling for other PII/secrets, Unicode/encoding edge cases, oversized payloads, and logging/export paths. |
| Data leakage | Intended architecture keeps payment-card material outside model context; credential isolation is documented. | Verify actual deployment traces, error reporting, crash dumps, backups, and provider retention terms; the current PAN pattern is not comprehensive DLP. |
| Tool sandboxing | Narrow action path; model has no established arbitrary tool/shell interface. | Isolate the service process, restrict filesystem/network permissions, and enforce authorization at the action boundary before public or multi-user deployment. |
| Secrets management | Environment variables and local ignored `.env` workflow. | Use an approved secret manager in deployment, least privilege, rotation, access audit, and CI secret scanning. Verify logs and artifacts do not expose values. |
| Authorization and human approval | Policy-based step-up, passkey flow, and payment-bound enclave verification are documented. | Authenticate API callers, bind identity to policy/card/agent, and validate approval on real devices and deployed hardware. Clearly disclose transactions eligible for automatic approval. |
| RAG/context poisoning | No RAG pipeline currently. | If added, preserve source identity and trust level, enforce document ACLs at retrieval, quarantine untrusted instructions, detect poisoning, and audit index updates. |
| MCP/tool trust | No MCP server currently. | Treat tool descriptions and results as untrusted input; allowlist tools/hosts, scope credentials, validate schemas, set timeouts/quotas, and require human approval for consequential actions. |
| Audit/logging | Local event/ledger/tracing components exist. | Add authenticated, tamper-resistant central logs, retention/access rules, verified alert delivery, and redaction tests. Never log secrets or full card data. |

These categories align with threat themes in the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and risk-management concepts in the [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework). This mapping is a planning aid; it does **not** claim compliance or certification.

## Release gates

Before exposing the service beyond a trusted local development environment:

1. Add authentication and authorization to every API route; enforce network/service isolation and least privilege.
2. Decide and enforce input/output token ceilings, context policy, inference quotas, and cost alerts.
3. Run the existing offline tests/evaluations and add live-model adversarial evaluation for each configured model/prompt version. Record versions and results.
4. Verify secret storage, redacted logging, backup/crash-dump behavior, and credential rotation in the target deployment.
5. Validate passkey flows on real target devices and do not claim AWS Nitro isolation until deployed and independently evidenced.
6. Establish operational audit retention, alert authenticity, incident response, and rollback ownership.

Before adding RAG, MCP, vLLM, caching, or fine-tuning, document the data flows and threat boundary first, then add component-specific access controls and evaluations. Do not mark an item implemented based only on a design document or dependency being installed.

## Verification record

This record was assembled by inspecting the current source and existing repository documentation on **2026-11-16**. Test names and evaluation cases are cited as existing evidence; no claim is made that they were executed as part of this documentation change. The repository itself records important non-production boundaries, including the mock/non-hardware enclave, software-authenticator-only passkey tests, and unauthenticated local endpoint. See [`docs/PRT.md`](docs/PRT.md) and [`docs/CREDENTIAL_ISOLATION.md`](docs/CREDENTIAL_ISOLATION.md).

Re-review this file whenever model providers, tools, retrieval sources, payment actions, secrets, deployment boundaries, or data retention behavior change.
