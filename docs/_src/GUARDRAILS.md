# Guardrails

Every control that limits what the agent can do, **where it is enforced (host or enclave), which test proves it, and how it could be bypassed.**
Code references (`path:line`) are generated from the source by `docs/_refs.py`.

## 1. The shape of a decision

The model only proposes `{merchant, amount_cents, currency, description}`. Code decides. Order of evaluation ([[vault_harness/guard.py::decide]]):

```
input redaction → strict JSON parse → FREEZE → policy (allowlist, currency, cap, budget, expiry) → VELOCITY → RISK SCORE
      → auto | human approval | deny  →  [human approval: Touch ID passkey]  →  re-check FREEZE  →  payment
      → enclave re-checks (revocation, signature/passkey, cap, host+path, amount-in-request, placeholder)  →  post-check  →  ledger + alert + event
```

| Outcome | Meaning |
|---|---|
| `done` | paid and the post-check matched the approved intent |
| `denied` | a guardrail stopped it before any browser started |
| `rejected` | the human said no |
| `failed_validation` | the proposal was not valid JSON / had unknown fields / carried card-like digits (3 retries) |
| `refused` | the enclave or page refused after approval (nothing charged); `aborted` if **no card was sent** (doesn't count as a failed payment) |
| `awaiting_approval` | paused for a human |
| *halt* | the safety kernel stopped the agent (unexpected outcome, e.g. `unconfirmed`: a card was sent but no success page was seen) |

## 2. The controls

Config lives in `config/policy.interview.json` (loaded by [[vault_harness/policy.py::load_policy]]; dataclass [[vault_harness/policy.py::Policy]]). Current values: auto-approve under **$2.00**, per-purchase cap **$20.00**, total budget **$20.00**, merchants `buy.stripe.com` / `shop.agentcard.sh` / `stripe-test-mode`, USD only, velocity 12/min · 30/hour · 60/day and $20/hour/day, risk step-up ≥40, deny ≥70, burst detector 20 (default 3).

| # | Guardrail | Enforced in | Code | Tests (and eval cases) |
|---|---|---|---|---|
| G1 | **Input redaction**: card-like digits removed from the task and model output before entering state | host | [[vault_harness/graph.py::start]], [[vault_harness/policy.py::redact]] | `test_flow::test_card_number_in_the_task_is_redacted_before_it_reaches_state`; eval `leak_card_in_task`, `leak_card_spaced_in_task` |
| G2 | **Strict intent schema**: unknown fields, non-int amounts, card-like strings rejected | host | [[vault_harness/policy.py::parse_intent]] | `test_flow::test_smuggling_a_card_number_into_the_intent_is_rejected`; eval `atk_unknown_field_smuggle`, `atk_amount_as_string`, `atk_not_json`, `leak_card_field_smuggle` |
| G3 | **Merchant + currency allowlist** | host | [[vault_harness/policy.py::evaluate]] | `test_flow::test_policy_denies_without_review_or_charge` (parametrized); eval `atk_merchant_not_allowed`, `atk_wrong_currency` |
| G4 | **Per-purchase cap** | host **and enclave** | `evaluate`; [[vault_harness/enclave.py::_gate]] (`max_single_cents`) | `test_enclave::test_enclave_cap_holds_even_if_the_host_lied_about_policy`; eval `atk_over_per_purchase_cap` |
| G5 | **Total budget** (running total survives runs; written only after a payment succeeds) | host | [[vault_harness/policy.py::Budget]] | `test_flow::test_budget_exhausted_denies`, `::test_budget_accumulates_across_runs`; eval `atk_budget_exhausted`, `atk_split_payments_hit_budget` |
| G6 | **Expiry** of spending authority | host | `evaluate` | `test_flow::test_expired_authority_denies`; eval `atk_authority_expired` |
| G7 | **Velocity caps**: payments per minute/hour/day, spend per hour/day (SQLite event store; only attempts that reached the processor count) | host | [[vault_harness/guard.py::check_velocity]], [[vault_harness/guard.py::EventStore]] | `test_guard::test_per_minute_velocity_cap_denies`, `::test_cap_counts_only_the_window_and_only_real_attempts`, `::test_spend_velocity_cap_denies`; eval `atk_velocity_per_minute`, `atk_velocity_per_hour`, `atk_velocity_spend_per_day` |
| G8 | **Real-time risk score 0–100** (table below): ≥40 forces a human even under the auto limit; ≥70 denies | host | [[vault_harness/guard.py::risk_score]] | `test_guard::test_card_testing_burst_forces_a_human`, `::test_many_failures_plus_burst_is_denied`, `::test_amount_far_above_history_adds_risk`, `::test_new_merchant_alone_does_not_block_a_small_payment`; eval `atk_card_testing_burst_forces_a_human`, `atk_repeated_failures_force_a_human` |
| G9 | **Human approval** at/above the auto limit (or on a risk step-up). With a registered passkey it is a **Touch ID assertion bound to this payment** and verified **inside the enclave** | host + enclave | graph node `review`; [[vault_harness/enclave.py::_check_passkey]]; [[vault_harness/enclave.py::approval_challenge]]; [[vault_harness/webauthn.py::verify_assertion]] | `test_passkey_enclave::test_a_touch_id_approval_for_this_payment_is_accepted`, `::test_once_a_passkey_is_registered_the_software_user_key_no_longer_approves`, `::test_an_approval_for_a_different_amount_is_refused`, `::test_an_approval_cannot_be_replayed`; `test_enclave::test_amount_at_or_above_auto_limit_needs_the_USER_signature`; eval `ctl_five_dollars_needs_approval_then_approved`, `ctl_human_rejects` |
| G10 | **Instant freeze** by scope `all` / `agent:` / `card:` / `merchant:`. Checked when deciding, **again just before paying**, and mirrored into the enclave as signed revocations. **Lifting needs Touch ID**; freezing never does | host + enclave | [[vault_harness/guard.py::Freezes]]; graph node `act`; [[vault_harness/enclave_vault.py::sync_revocations]]; [[vault_harness/enclave.py::lift]] | `test_guard::test_every_freeze_scope_denies`, `::test_freeze_placed_after_approval_still_stops_the_payment`, `::test_host_freeze_reaches_the_enclave_and_lifting_it_restores_payments`; `test_passkey_enclave::test_the_host_cannot_lift_a_freeze_but_the_owners_touch_id_can`; `test_webapp::test_lifting_a_freeze_needs_touch_id_once_a_passkey_exists`; eval `atk_frozen_*` |
| G11 | **Mandate ("autopilot")**: owner authorizes once (≤10 payments, ≤$2 each, ≤60 min); the agent then pays with no inputs; revocable at once; Touch ID over the exact terms | host (limits) | [[webapp.py::agent_pay]], [[webapp.py::authorize]] | `test_webapp::test_agent_pays_with_no_inputs_until_the_mandate_is_used_up`, `::test_revoking_the_mandate_stops_the_agent_at_once`, `::test_an_expired_mandate_cannot_be_used`, `::test_a_freeze_still_stops_an_agent_that_holds_a_mandate`, `::test_authorizing_the_agent_needs_touch_id_over_those_exact_terms` |
| G12 | **Page total must equal the approved amount** (and USD is selected explicitly) | host | [[vault_harness/hosted_checkout.py::drive]], [[vault_harness/enclave_vault.py::pay]] | `test_wiring::test_page_total_different_from_the_approved_amount_is_refused_before_the_card_is_touched`; seen live on the real page (GBP/SGD pricing stopped a run) |
| G13 | **Request amount must equal the approved amount** (page lies: shows $1, submits $99.99) | **enclave** | `_gate` | `test_enclave::test_request_amount_must_equal_the_approved_amount`; `test_wiring::test_page_that_shows_one_amount_and_submits_another_is_stopped_by_the_enclave` |
| G14 | **Processor host + path allowlist**, https only (the card can only go to `api.stripe.com/v1/payment_methods`) | **enclave** | `_gate` | `test_enclave::test_card_cannot_be_sent_to_an_attacker_host`, `::test_http_downgrade_refused`; `test_hosted_checkout::test_forward_refuses_any_path_other_than_payment_methods` |
| G15 | **Single-use, bound placeholder** (merchant+amount+currency, 10-min TTL), burned *before* the card is touched | **enclave** | [[vault_harness/enclave.py::issue_placeholder]] | `test_enclave::test_placeholder_is_single_use`, `::test_placeholder_bound_to_the_exact_payment`, `test_vault.py` |
| G16 | **Idempotency**: per-placeholder key on the processor call; the client never retries a create | enclave / client | [[vault_harness/stripe_processor.py::StripeTestProcessor]], [[vault_harness/agentcard.py::AgentcardClient]] | `test_wiring::test_processor_strips_amount_from_tokens_uses_the_approved_amount_and_idempotency_key`; `test_agentcard::test_authorization_body_and_no_retry_on_failure` |
| G17 | **Test-mode key enforcement**: the sandbox processor refuses live keys in code and stops if Stripe reports `livemode` | host | `StripeTestProcessor` | `test_wiring::test_processor_refuses_a_live_key`, `::test_a_live_publishable_key_is_refused`, `::test_processor_stops_if_stripe_reports_livemode` |
| G18 | **Post-check**: the result must match the approved intent (amount, merchant, currency, charge id; no card-like digits); a mismatch **halts the agent** and a resume cannot pay twice | host | [[vault_harness/checks.py::post_act]], [[vendor/agent_kernel.py::Kernel]] | `test_kernel::test_an_action_that_claims_done_but_did_not_is_caught_and_cannot_be_retried` |
| G19 | **Halt switch** (a file outside the agent) stops the next step, even between approval and action | host | `Kernel` | `test_kernel::test_halt_stops_the_run_before_the_model_is_called`, `::test_halt_between_approval_and_action_prevents_the_action` |
| G20 | **Tamper-evident ledger** of every step (hash-chained, secrets redacted) | host | `vendor/blackbox/ledger.py` | `test_kernel::test_every_step_is_recorded_and_the_ledger_verifies` |
| G21 | **Alerts** on every payment, denial, step-up, freeze, mandate (JSON lines; optional webhook, **webhook not verified**) | host | [[vault_harness/alerts.py::emit]] | `test_guard::test_alerts_are_written_and_redact_card_numbers`, `::test_denial_alerts_critical_when_frozen` |
| G22 | **Dry-run by default**; live needs an explicit flag; real-money state is separate from sandbox state | host | `actions.perform`, `pay_perflo.py` | `test_flow::test_dry_run_default_never_touches_the_vault`, `test_guard::test_dry_run_records_nothing` |
| G23 | **Stateless browser** (one fresh session, no profile/vault/pool, deleted afterwards) | host | [[vault_harness/browser.py::KernelSession]] | `test_browser.py` (unit + live) |
| G24 | **Link/captcha stops**: a Stripe Link login prompt makes the run stop; captchas are left to a human | host | [[vault_harness/hosted_checkout.py::drive]] | `test_hosted_checkout::test_link_login_prompt_is_recognised` |

### Risk score ([[vault_harness/guard.py::risk_score]])
| Signal | Points |
|---|---|
| first completed payment to this merchant | +20 |
| amount > 3× the median of past payments (needs ≥3 samples) | +25 |
| ≥ `burst_count` small (≤ $2) payments in 5 min (card-testing pattern) | +40 |
| 2–3 refused/denied attempts in 10 min | +25 |
| ≥ 4 refused/denied attempts in 10 min | +45 |

`≥ step_up_at (40)` → a human must approve even under the auto limit. `≥ deny_at (70)` → denied. Pre-card refusals are recorded as `aborted` and **do not** count as failures (this was a real bug found on the live page).

## 3. Host-enforced vs enclave-enforced (what a compromised host can do)

| Control | Host | Enclave |
|---|---|---|
| Per-purchase cap | ✔ | ✔ |
| Merchant allowlist, budget, velocity, risk score, expiry, mandate limits | ✔ | ✘ |
| Human approval ≥ auto limit | ✔ | ✔ (passkey assertion verified inside) |
| Risk-driven step-up under the auto limit | ✔ | ✘ |
| Freeze | ✔ | ✔ (signed revocation); lifting needs Touch ID in the enclave |
| Processor host/path, amount-in-request, placeholder single use, CVC nonce single use | ✘ | ✔ |

**A compromised host cannot:** read the card; send it anywhere but `api.stripe.com/v1/payment_methods`; pay ≥ $2 without the owner's Touch ID (once a passkey is registered); lift a freeze; replay an approval, a placeholder or a CVC box; charge a different amount than approved.
**A compromised host can:** make payments **under the auto limit** without a human, because it holds the policy signing key and the enclave does not enforce budget or velocity. Within the enclave's per-purchase cap it could therefore keep making sub-$2 payments until something outside the enclave stops it. Moving budget and velocity into the enclave is the obvious next hardening step and is **not built**.

## 4. Known gaps in the guardrails (honest list)

- **Merchant allowlist is on a label.** The agent's `merchant` string is checked against the allowlist, but the real destination is a URL fixed in code (`LINK` in `webapp.py` / `pay_perflo.py`); the agent cannot choose it. So the allowlist is belt-and-braces today, and would matter once the destination is derived from the proposal.
- **Budget check-then-record is not atomic.** Two runs in separate processes could both pass the budget check. The web app serialises runs (one at a time); CLI runs are not coordinated.
- **Risk weights are heuristics**, not tuned on data; thresholds are configuration.
- **Velocity/events live in a local SQLite file**: not shared across machines.
- **The agent endpoint is not authenticated** beyond "this machine" (see `docs/CREDENTIAL_ISOLATION.md` §7).
- **Alert delivery is untested** beyond the local file; no SMS/email.
- **The mandate holds pre-sealed CVC boxes** in memory (see isolation doc).
- **Passkey registration is trust-on-first-use**, per session, and platform authenticators may report a counter of 0 (replay protection then rests on the one-time challenge).
- **Only a scripted writer has been run as the "model".** The eval scores the guardrails and plumbing, not an LLM's behaviour.

## 5. The golden eval (`evals/run_eval.py`)
36 cases, scripted model, isolated state per case: **10 control** (legitimate payments must succeed; no false alarms), **20 attack** (must be stopped), **6 leak** (card number must never appear in state/result/ledger). Baseline gate: any metric that drops fails the run. The eval was verified by breaking the code on purpose: with redaction off the leak cases fall to 67%; with allowlist/cap/budget off, attack detection falls to 42%. It also caught a real miss during the build (the card-testing burst scored too low to force a human); the engine was fixed, the case was not edited. Cases: `evals/golden/payment_cases.json`.

## 6. Add or change a guardrail
1. Implement it in `vault_harness/guard.py` (host) and, if it must survive a compromised host, in `vault_harness/enclave.py::_gate`.
2. Add a unit test in `tests/` and a golden case in `evals/golden/payment_cases.json` (one control, one attack).
3. `python evals/run_eval.py` (must stay 100% or the gate fails), then `pytest -q tests`.
4. Add a row to the table above.

## 7. Reproduce
```bash
.venv/bin/python -m pytest -q tests          # 203 offline tests
.venv/bin/python evals/run_eval.py           # golden eval + regression gate
.venv/bin/python demo.py                     # guardrail scenarios, offline
.venv/bin/python freeze.py freeze all --reason "review"   # instant revocation; `freeze.py lift all` to undo
```
