# Credential isolation

How card data and secrets are kept away from the agent, the harness, the logs and git, **how each claim is enforced, how it is tested, and where it is weak.**
Code references look like `path:line` and are generated from the source (`docs/_refs.py`), so they point at real symbols.

Honesty rules for this document: *Enforced* means code refuses to do otherwise. *Tested* names the test. *Weak* means a reviewer should push on it. Nothing below was tested on real AWS Nitro hardware; the enclave is a separate program but **not** a hardware-isolated one yet (see §7).

## 1. What is being protected

| Credential | Examples | Who must never see it |
|---|---|---|
| **Card data** | PAN, expiry, CVC | the agent/model, the Kernel cloud browser, logs, the ledger, traces, git, the host disk in clear |
| **API keys** | Kernel key, Stripe keys | the agent/model, git, logs |
| **Signing keys** | approval signers, the passkey private key | the agent; the passkey private key never leaves the owner's device |
| **Capability links** | Kernel live-view URL, checkout session URL, enrolment URLs | the agent, logs, git |

## 2. Trust zones

```
 owner's browser/device ──(ciphertext)──► host (harness process: agent, guard, browser driver, web app)
        ▲  Touch ID                           │ placeholder only                │ ciphertext + masked results only
        │                                     ▼                                 ▼
        │                          Kernel cloud browser (stateless)     ENCLAVE (separate program; Nitro VM in the real build)
        │                                     │ request carrying the placeholder        │ real card exists here, for one payment
        │                                     └──────────────► intercepted ─────────────┘
        │                                                                               │ TLS, host+path allowlisted
        └─────────────────────────────────────────────────────────────────────────────► Stripe
```

| Zone | May hold | Must not hold |
|---|---|---|
| **Owner's browser** | the typed card for a moment, then ciphertext | – (this is the "user device" role) |
| **Agent / model** (`graph.py` nodes `work`, `check`) | the task text (redacted), a JSON proposal | any card field, any key (it has no tool that reaches them) |
| **Harness host** | ciphertext boxes, placeholders, masked results, API keys in `.env` | card in clear, CVC at rest |
| **Kernel cloud browser** | the placeholder, billing details, PaymentMethod ids | the real card |
| **Enclave** | the real card, in memory, for one payment | anything after the payment (forgets) |
| **Stripe** | the real card (it is the processor) | – |

## 3. Where card data can exist in clear (the complete list)

1. **In the owner's browser page**, from typing until it is encrypted (`static/seal.js` `seal`, called in `static/index.html`). The input is cleared the moment the box exists.
2. **In the enclave's memory**, inside `vault_harness/enclave.py:117` `.pay` / `_open` / `_swap`, for one payment.
3. **At Stripe.**

Everywhere else it is ciphertext, a placeholder, or a masked result (`last4`, brand). Evidence:

| Claim | Enforced by | Tested by |
|---|---|---|
| The agent never receives card data | the agent only emits JSON, strictly parsed: `vault_harness/policy.py:54` rejects unknown fields (e.g. `card_number`) | `tests/test_flow.py::test_smuggling_a_card_number_into_the_intent_is_rejected`, eval `leak_card_field_smuggle` |
| A card number typed into the task or echoed by the model never enters state/ledger/alerts | `vault_harness/graph.py:130` redacts input; node `work` redacts model output; `vault_harness/alerts.py:17` redacts alert fields (`policy.contains_pan` / `policy.redact`) | `tests/test_flow.py::test_card_number_in_the_task_is_redacted_before_it_reaches_state`, eval `leak_*` (6 cases) |
| The browser/Kernel only ever types a worthless placeholder | `vault_harness/enclave.py:135`: Visa-shaped, Luhn-valid, one-time, bound to merchant+amount+currency, 10-minute expiry | `tests/test_enclave.py` (single use, bound, expired), `tests/test_browser.py` live: *browser only holds the placeholder* |
| The host stores only ciphertext | `vault_harness/cardstore.py:13` stores `{epk, nonce, ct, aad}` + display fields; CVC is dropped at enrolment | `tests/test_guard.py::test_enroll_stores_ciphertext_only_and_never_the_cvc` |
| A stolen card file is useless; a box can't be moved to another card id | AES-256-GCM, card id as associated data: `vault_harness/enclave.py:261` | `tests/test_enclave.py::test_tampered_ciphertext_cannot_be_opened`, `::test_card_sealed_to_a_different_enclave_cannot_be_opened`, `tests/test_guard.py::test_stored_blob_cannot_be_used_for_another_card_id` |
| The channel to the enclave carries no card number | enclave runs as a separate server: `vault_harness/enclave_rpc.py:56` | `tests/test_enclave_rpc.py::test_full_payment_across_the_socket_and_no_card_number_on_the_wire` (asserts on every byte exchanged) |
| The processor's reply can't smuggle a card back | the enclave scans the reply before returning it | `tests/test_hosted_checkout.py::test_forward_withholds_a_reply_that_carries_card_digits` |
| The card never reaches an attacker host or another API path | the enclave only sends to an allowlisted host **and path** (`api.stripe.com`, `/v1/payment_methods`), https only: `vault_harness/enclave.py:226` | `tests/test_enclave.py::test_card_cannot_be_sent_to_an_attacker_host`, `::test_http_downgrade_refused`, `tests/test_hosted_checkout.py::test_forward_refuses_any_path_other_than_payment_methods` |
| A page can't make us pay more than approved | page total must equal the approved amount; the request amount is re-checked inside the enclave | `tests/test_browser.py` live: *a lying page is stopped*, `tests/test_wiring.py::test_page_total_different_from_the_approved_amount_is_refused_before_the_card_is_touched` |
| No file a run writes contains a card number | `vault_harness/leakscan.py:20` (Luhn-valid 13–19 digit runs; ignores hashes/ids) | `tests/test_guard.py::test_whole_run_leaves_no_card_number_in_any_file`, `::test_scanner_actually_finds_a_planted_card_number`, `::test_scanner_never_flags_random_ids_and_nonces` |
| The browser keeps no state between payments | `vault_harness/browser.py:31`: no profile/vault/pool/proxy, one session per payment, deleted in `finally` | `tests/test_browser.py` (unit: deletion on every path; live: a fresh session sees none of another's cookies/storage) |

## 4. How a card gets in (the "user device" step)

- **Web app (preferred):** the page fetches the enclave's public key, then `static/seal.js:6` does X25519 → HKDF-SHA256 → AES-256-GCM (aad = card id) **in the browser**. The server receives `{epk, nonce, ct, aad}` only. The same JS, run in Node, produces a box the Python enclave opens: `tests/test_webapp.py::test_a_box_sealed_by_the_actual_browser_code_is_accepted`.
- **CVC:** never stored. Sealed per payment with a one-time nonce (`cvc-nonce:`), consumed once by the enclave (`_boxes_used`). *Exception:* a mandate pre-seals N such boxes (§7).
- **Legacy terminal scripts** (`pay_perflo.py`, `pay_one_dollar.py --prompt-card`): the card is typed at a hidden prompt, so it exists briefly in **the harness process** before sealing. This weakens isolation and is listed in §7.

## 5. Secrets inventory

| Secret | Where it lives | Read by | Blast radius if leaked | Notes |
|---|---|---|---|---|
| `KERNEL_API_KEY` | `.env` (git-ignored, mode 600) | `vault_harness/browser.py:20` (harness) | create/read/delete browser sessions in the project; **cannot** read the card | rotate in the Kernel dashboard |
| `STRIPE_TEST_KEY` (`rk_test_`/`sk_test_`) / `STRIPE_PUBLISHABLE_KEY` | `.env` | `vault_harness/stripe_processor.py:36` | test-mode only: the class **refuses** any non-`_test_` key in code | sandbox path only; the real-card path uses no Stripe secret |
| Approval signing keys (user, policy) | `output/signers/*.key` (mode 600, ignored) | harness process | can forge **software** approvals; neutralised for human approvals once a passkey is registered | the weakest link before passkey; see §7 |
| Enclave private key | RAM; or `output/enclave_key.json` sealed with a passphrase (scrypt → AES-GCM) | the enclave | opens stored cards | stand-in for KMS (`vault_harness/enclave.py:93`) |
| Passkey private key | owner's device (Touch ID / Secure Enclave) | never exported | – | only assertions leave the device |
| Kernel live-view URL | `output/live_view_url.txt` (mode 600) | the owner | watch/control that one browser session | capability link; short-lived session |
| Agentcard enrolment/approval URLs | `output/enroll_url.txt` (mode 600), never printed | the owner | save a card into that wallet | never given to an agent (Kernel's own rule) |

**Git:** `.env`, `output/`, `.venv/`, keys are ignored. An audit of everything tracked found no key-like strings, emails or addresses (`git ls-files | xargs grep -E 'sk_|rk_|pk_|AKIA|BEGIN .*PRIVATE KEY'`). Real PaymentMethod ids appear in the PRT; they cannot be used to charge.

## 6. What the agent can and cannot touch

The "agent" is the graph's `work` node (a scripted writer offline; an LLM when keyed) plus the code that interprets its output. It has **no tool** that reads the card store, the enclave, `.env`, or the filesystem. Its only output is a JSON proposal, parsed by `vault_harness/policy.py:54` (unknown fields rejected, `amount_cents` must be an int, strings scanned for card-like digits). The decision to pay is made by code (`vault_harness/guard.py:114`), and the payment is made by one function (`vault_harness/actions.py:26`) that the model cannot call directly. Prompt-injection cases are in the golden eval (`atk_prompt_injection_in_task`) and the page-text case in `tests/test_browser.py` (*injected page text is ignored*: the amount is read from the DOM by code).

## 7. Known weaknesses (please push on these)

1. **The enclave is not isolated yet.** It runs as a separate program (and a Docker image), but nothing prevents the host from reading its memory. Real Nitro isolation, attestation and KMS are written and verified only against synthetic documents; **never run on AWS**. (`nitro/README.md`)
2. **User signing key in the harness process.** Before a passkey is registered, a "human approval" is an Ed25519 signature the host itself can make. With a passkey, human approvals and freeze-lifts are verified **inside the enclave** (`vault_harness/enclave.py:162`); registration is trust-on-first-use.
3. **Legacy scripts put the card in the harness process** (hidden terminal prompt) before sealing. The web app does not.
4. **Mandate pre-seals CVC boxes** held (encrypted, in RAM, one-time, ≤60 min) in the web server: more than "never stored", and PCI DSS forbids keeping a CVC after authorization even encrypted. Test-scope design.
5. **Unauthenticated local API.** The web app trusts the local machine: host check + `X-Harness` header stop browsers/CSRF, not another local process. The agent endpoint (`/api/agent/pay`) and the owner's UI share an origin. Production needs an authenticated, separate agent identity.
6. **The enclave RPC has no transport authentication** (tcp locally, vsock on Nitro). Safe only because everything crossing it is ciphertext/public and approvals are signed; availability is not protected.
7. **Python cannot guarantee zeroization** of memory; `_open`/`_swap` clear what they can.
8. **The sandbox Stripe processor runs in the harness process with a test key.** The real-card path (`hosted_checkout.py`) uses no secret key.
9. **Kernel (a third party) sees** the placeholder, billing details, PaymentMethod ids and the page. It never sees the card, but it is a trust dependency.
10. **Scanning limits:** `leakscan` reads files only (no process memory, swap, core dumps).
11. **Compliance is out of scope** (PCI DSS scoping, disputes, KYC).

## 8. A reviewer's attack list

Try to break each of these; each should fail, and most have a test you can run.
- Put a card number in the task, in the model output, in a merchant name. (eval `leak_*`)
- Smuggle `card_number`, `destination` or any extra key into the JSON proposal. (`atk_unknown_field_smuggle`)
- Replay a placeholder, a CVC box, or a Touch ID assertion. (`tests/test_enclave.py`, `tests/test_passkey_enclave.py`)
- Capture a request to another host/path and ask the enclave to send it. (`test_card_cannot_be_sent_to_an_attacker_host`)
- Make the page show $1.00 and submit $99.99, or show GBP. (live browser test; real-page rehearsal)
- Move a stored box to another card id; open it with another enclave. (`tests/test_guard.py`, `tests/test_enclave.py`)
- Lift a freeze without Touch ID; approve with the software key after a passkey exists. (`tests/test_passkey_enclave.py`)
- Grep the tree and the git history for secrets; run the scanner over `output/`: `python -m vault_harness.leakscan output`.
- Read the agent's ledger (`~/.blackbox/ledger`) for anything card-shaped (`tests/test_guard.py::test_whole_run_leaves_no_card_number_in_any_file`).

## 9. Reproduce
```bash
.venv/bin/python -m pytest -q tests                  # offline: 203 tests
.venv/bin/python evals/run_eval.py                   # 36-case golden eval + baseline gate (6 leak cases)
.venv/bin/python -m vault_harness.leakscan output    # card-number scan of everything a run wrote
RUN_LIVE=1 .venv/bin/python -m pytest -q tests       # + real Kernel browsers, Docker, Stripe TEST mode (needs .env keys)
```
