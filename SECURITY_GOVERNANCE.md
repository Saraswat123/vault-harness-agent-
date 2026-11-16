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
