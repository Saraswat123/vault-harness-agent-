# Vault Harness: guarded payments for AI agents

An agent pays online **without ever seeing, storing or remembering a card number**, inside limits set by code, with instant freeze, and with human approval by Touch ID. The card is encrypted in the owner's browser, kept only as ciphertext, and swapped into a payment **inside an enclave**; the checkout is driven by a **stateless cloud browser** (Kernel) that only ever types a worthless placeholder.

> **Status, plainly.** Seven real $1.00 payments were made on a company test card through a live Stripe Checkout link; the cardholder confirmed seven transactions on the card statement. The enclave is a **separate program, not yet a hardware-isolated Nitro enclave** (Nitro is prepared and tested only against synthetic attestation; never run on AWS). Passkey approvals are tested against a software authenticator, not yet on a real device. Everything unverified is listed in [`docs/PRT.md`](docs/PRT.md) §8.

## Reviewing this? Start here

| You want | Read |
|---|---|
| How card data and secrets are isolated, what holds what, known weaknesses, an attack list | [`docs/CREDENTIAL_ISOLATION.md`](docs/CREDENTIAL_ISOLATION.md) |
| Every guardrail: where enforced (host vs enclave), tests, bypass analysis, gaps | [`docs/GUARDRAILS.md`](docs/GUARDRAILS.md) |
| The full product requirements and test report (real payments, API study, results) | [`docs/PRT.md`](docs/PRT.md) · [`docs/PRT.pdf`](docs/PRT.pdf) |
| Moving the enclave onto AWS Nitro | [`nitro/README.md`](nitro/README.md), [`nitro/CONSOLE_STEPS.md`](nitro/CONSOLE_STEPS.md) |

A 10-minute review path:
```bash
python3.11 -m venv .venv && .venv/bin/pip install -r requirements.lock
.venv/bin/python -m pytest -q tests            # 203 offline tests, no keys needed
.venv/bin/python evals/run_eval.py             # 36 cases: legit payments pass, attacks stop, card never leaks
.venv/bin/python demo.py                       # guardrail scenarios, offline
.venv/bin/python -m vault_harness.leakscan output   # card-number scan of everything a run wrote
```
Read `vault_harness/enclave.py` (`_gate`, `pay`, `_open`, `_swap`) and `vault_harness/guard.py` (`decide`) first: they are the core of both topics.

## How one payment works

```
 owner's browser ──encrypts card (X25519 + AES-GCM)──► card store (ciphertext only)
                                                         │
 request ─► agent (proposes JSON only) ─► guard: freeze → policy → velocity → risk ─► approval (Touch ID)
                                                         ▼
   Kernel cloud browser (fresh, no profile): types a PLACEHOLDER ─► Stripe's page sends the tokenization request ─► intercepted
                                                         ▼
                                  ┌──────────── enclave ─────────────┐
                                  │ re-checks, opens the card, swaps │ ─► Stripe (host + path allowlisted)
                                  │ it in, returns a masked result   │
                                  └──────────────────────────────────┘
   ─► post-check (charge == approved) ─► tamper-evident ledger + alert + event store
```

## What isolates the credentials

- **The agent has no card and no tool that can reach one.** It emits JSON; unknown fields and card-like digits are rejected. Input and output are redacted before they reach state, the ledger or alerts.
- **The browser holds only a placeholder**: Visa-shaped, Luhn-valid, one-time, bound to merchant+amount+currency, expires in 10 minutes.
- **The host stores ciphertext only**, bound to a card id, openable only by the enclave's private key. The CVC is never stored (sealed per payment with a one-time nonce).
- **The enclave is the only place the card exists in clear**, for one payment, and may only send it to `api.stripe.com/v1/payment_methods` over https.
- **Nothing sensitive is in git**: `.env`, `output/`, keys are ignored, and the tracked tree was scanned for key-like strings.

## What limits the agent

Input redaction · strict schema · merchant/currency allowlist · per-purchase cap (host **and** enclave) · total budget · expiry · **velocity caps** · **real-time risk score** · human approval (**Touch ID, verified in the enclave**) · **instant freeze** (lifting needs Touch ID) · mandate ("autopilot") with its own limits · page-total and request-amount checks · single-use placeholders · post-check with halt · alerts · hash-chained ledger · dry-run by default. Full table with code and tests: [`docs/GUARDRAILS.md`](docs/GUARDRAILS.md).

## Layout

| Path | What |
|---|---|
| `vault_harness/` | `graph.py` (the agent flow), `policy.py`, `guard.py` (velocity, risk, freeze), `enclave.py` (sealing, swap, checks, passkey), `enclave_rpc.py` (enclave as a separate server), `hosted_checkout.py` (Stripe Checkout driver), `browser.py` (Kernel session), `cardstore.py`, `webauthn.py`, `attestation.py`, `alerts.py`, `leakscan.py`, `agentcard.py` / `kernel_vault.py` (vendor API study) |
| `vendor/` | the safety kernel (halt switch, ledger, post-checks): small, standard library only. See `vendor/README.md` |
| `webapp.py`, `static/` | local web app: add a card (encrypted in the page), let the agent pay, watch the live browser, Touch ID, freeze |
| `nitro/` | enclave image, build/run/launch scripts, KMS template, step-by-step guide (**not yet run on AWS**) |
| `evals/` | golden eval (36 cases) and baseline gate |
| `tests/` | 203 offline tests (+ live tests with `RUN_LIVE=1`) |
| `config/` | policy limits |
| `pay_perflo.py`, `pay_one_dollar.py`, `demo.py`, `freeze.py`, `kernel_enroll.py` | runners and CLIs (the card-entry runners are the weaker, terminal-based path) |

## Running things that touch money or keys

Offline tests and the eval need **no keys**. Live runs need a `.env` (see `.env.example`): `KERNEL_API_KEY`, and for the Stripe sandbox `STRIPE_TEST_KEY` + `STRIPE_PUBLISHABLE_KEY` (test mode only: the sandbox processor refuses live keys in code). Real-card runs (`pay_perflo.py --live`, the web app) charge **real money** and are capped at $2.00 per payment, 10 payments, with separate real-money state. Never commit `.env` or anything under `output/`.

```bash
.venv/bin/python webapp.py          # then open http://localhost:8765 (not 127.0.0.1: passkeys need a hostname)
.venv/bin/python freeze.py freeze all --reason "stop"     # instant revocation, from another terminal
RUN_LIVE=1 .venv/bin/python -m pytest -q tests            # also drives real Kernel browsers and Stripe TEST mode
```

## Documentation is checked against the code
`docs/_refs.py` renders the review documents from `docs/_src/` and fails if any referenced symbol, test or eval case does not exist.
