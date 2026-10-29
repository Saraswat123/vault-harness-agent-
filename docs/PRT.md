# PRT — Guarded Agent Payments: a card vault for AI agents (Kernel + Stripe + AWS Nitro design)

Status 2026-10-29. Every claim is marked **verified** (a test or a live run produced it) or **not verified / not built**. Test card only: Stripe's public `4242 4242 4242 4242`.

---

## 1. Goal
An AI agent pays online **without ever seeing, storing, or remembering a card number**, inside limits set by code and revocable instantly.

1. Same method as the reference product (Agentcard Vault): placeholder in the checkout form, the real card swapped in at the last step, a human approval for larger amounts.
2. Cards can be **stored**, but only as ciphertext that only a trusted component (the enclave) can open.
3. A **stateless** browser (Kernel) does the checkout: one fresh session per payment, deleted afterwards.
4. Guardrails the model cannot override: per-purchase cap, total budget, merchant and currency allowlist, expiry, human approval, **velocity caps, a real-time risk score, transaction alerts, and instant freeze/revoke**.
5. Verifiable: a golden eval and a leak scanner prove the card number never appears where it must not.

**Study scope.** Agentcard's public docs were studied in depth as the reference method. What was built is an independent implementation of the same method. No claim is made about any other company's product.

---

## 2. Reference method: Agentcard Vault API (from docs.agentcard.com)
Base `https://api.agentcard.sh`; sandbox vs production is decided by the credential. Client built: `vault_harness/agentcard.py` (tested against doc-shaped fixtures; **not run against a live account**, no builder credentials were issued).

| Call | Purpose |
|---|---|
| `POST /api/v2/oauth/token` | OAuth2 client-credentials, 1 h bearer |
| `POST /api/v2/vault_sessions` | Link the user opens to save a card with a passkey (`approval_mode: customer`) |
| `GET /api/v2/vault_cards?user_id=` | brand, last4, expiry; never a card number |
| `POST /api/v2/checkout/authorizations` | A paused payment carrying the **captured processor request** |
| `GET …/authorizations/{id}` | `awaiting_approval` / `approved` / `submitted_on_device` / `declined`, plus `settlement` |
| `POST …/authorizations/{id}/cancel` | abort before the device starts sending |

**How their swap works (key finding):** the browser types a placeholder; the SDK captures the paused processor request; after a passkey approval the **user's device** decrypts the card and submits it. The server never holds the card. Their auto-approval has no spend limit and test mode always waits for a human, so limits must live in the builder's own code.

**Live study through Kernel's managed integration (verified, 2026-10-29):** with only the Kernel key, a Kernel vault and an Agentcard wallet were created (`pending_authorization` → the user enrolled a company test card → `connected`); the wallet lists one payment method (Mastercard •••• 4034, display fields only); a $5.83 purchase item reached `ready` and returned **alias** stand-ins (card number and CVC stay with Agentcard); the demo store's checkout form was inspected. The final "PAY" click was **not performed**; the unused item and browser were deleted. So the vendor's own payment was studied up to, not through, the swap.

---

## 3. Architecture
```
 user device ─ seals card (X25519 + AES-GCM) ─► card store (CIPHERTEXT ONLY)
                                                       │
 request ─► agent (LangGraph; proposes JSON only)      │
              ─► guard: freeze → policy → velocity → risk score ─► approval (human/passkey)
                                                       ▼
   Kernel browser (fresh, no profile) ─ placeholder only ─► captured processor request
                                                       ▼
                                   ┌─────────── enclave ────────────┐
                                   │ re-checks, opens card, swaps,  │ ─► Stripe (PaymentMethod + PaymentIntent)
                                   │ replays, returns masked result │
                                   └────────────────────────────────┘
              ─► post-check (charge == approved) ─► ledger + alert + event store ─► read-back from Stripe
```
**One payment, step by step**

| # | Step | Component | Sees the card? |
|---|---|---|---|
| 1 | Request arrives; any card-like digits are redacted before entering state | `start()` | no |
| 2 | Agent proposes `{merchant, amount_cents, currency}`; unknown fields rejected | model | no |
| 3 | Freeze check → policy → velocity caps → risk score → **auto / human / deny** | `guard.py` | no |
| 4 | Human approval when required (software stand-in for a passkey today) | graph pause | no |
| 5 | Enclave issues a one-time placeholder bound to merchant+amount+currency | `enclave.py` | no |
| 6 | Fresh Kernel browser opens checkout; code reads the page total; types the placeholder; the request is captured; session deleted | `browser.py` | no |
| 7 | Page total must equal the approved amount | `enclave_vault.py` | no |
| 8 | Stored card id selects a ciphertext box; a per-payment CVC is sealed to the enclave, bound to this placeholder | `enclave_vault.py` | ciphertext |
| 9 | Enclave re-checks revocations, signature, cap, host allowlist, amount-in-request | `enclave.py` | inside |
| 10 | Enclave swaps the card in and sends to Stripe; returns `{id, amount, last4}`; forgets | `stripe_processor.py` | inside |
| 11 | Post-check, event + alert recorded, Stripe read-back reconciles | `checks.py`, `pay_one_dollar.py` | no |

---

## 3b. The real checkout: Perflo Pay $1 link (Stripe Checkout)
Findings from inspecting and rehearsing against the real link (2026-10-29), **nothing was paid**:
- The page is "Perflo Pay — Test Product — $1.00". Its checkout session ids start with `cs_live_`: **it is live mode, so a payment is a real $1.00 charge.** The card fields have stable ids (`cardNumber`, `cardExpiry`, `cardCvc`, `billingName`, …); an hCaptcha frame is present; a headless browser never rendered it, a headful one does.
- Stripe Checkout sends the card to `POST api.stripe.com/v1/payment_methods` when Pay is pressed. That is the "tokenization request" in Agentcard's description, and it is where the swap happens.
- **Adaptive pricing** can show the price in the visitor's local currency (£0.78, SGD 1.33 seen from the cloud browser). The driver selects USD and, as a backstop, refuses to continue unless the page total equals the approved amount. In rehearsal this check stopped a run that would otherwise have approved $1.00 against a £0.78 page.

**Method** (`hosted_checkout.py`): headful Kernel browser (no profile) → code reads the total → types a Visa-shaped, Luhn-valid **placeholder** → Stripe's own JS issues the `payment_methods` request → we intercept it over CDP → the enclave opens the ciphertext card, swaps it in, sends it to Stripe (path and host allowlisted) → Stripe's reply (a PaymentMethod id and last4) goes back to the page → the page confirms with the id. The browser, the harness and the model never hold the card; money moves only when the page confirms.

| Check | Result |
|---|---|
| Rehearsal on the real link, `--capture-only`: placeholder typed, request intercepted, **aborted, nothing sent to Stripe** | **6 of 8 runs captured the request** with the placeholder present and no real card; the other 2 stopped safely (page total mismatch before the currency fix; one page-load timeout) |
| Same code, local stand-in checkout, **Stripe test mode**, real Kernel browser: interception → swap → real PaymentMethod → success | **passed** (live test) |
| Real card on the real link (company's Mastercard •••• 4034, $1.00 each) | **5 payments completed**, run by the card owner in their own terminal; see the table below |


**Real payments on the company's card (live mode, $1.00 each, 2026-10-29).** The card owner typed the card at hidden prompts; the assistant never saw it. Per the runner's output (the browser reached the success page and Stripe created the PaymentMethod):

| # | PaymentMethod id | last4 |
|---|---|---|
| 1 | `pm_1UVweR2St7FgIvNdB7vc7zcu` | 4034 |
| 2 | `pm_1UVwvT2St7FgIvNdxpMH98Lm` | 4034 |
| 3 | `pm_1UVwwD2St7FgIvNdjHRhnJqR` | 4034 |
| 4 | `pm_1UVwx12St7FgIvNdZJkyVUXb` | 4034 |
| 5 | `pm_1UVwyq2St7FgIvNdEsFvTV56` | 4034 |

**Evidence level:** runner output only. Perflo's Stripe account is not ours, so there is no API read-back. Independent confirmation is the emailed receipt and the merchant's Payments dashboard (status: *to be confirmed by the card owner and the merchant*). Counter: 500 cents.

**Problems met and fixed on the real page:** Stripe Link login codes (the email was a Link account, so the runner now stops at that screen and a fresh plus-address was used); adaptive pricing showing GBP/SGD; a dropdown for the UAE state; flaky cloud page loads; the guard escalating to a human after pre-card stops had been counted as failed payments (now recorded as `aborted`).

**Weak point, stated plainly:** in this terminal flow the card owner typed the card into a terminal. The agent never held it, but a person did the entry. The web app below removes the terminal.

**To run the real payments** (owner's terminal, not this chat): `python pay_perflo.py --live --times N --email … --name … --country … --zip …`. Real-money state (budget, events, alerts) is kept separate from the sandbox state. The agent kernel halts on an unexpected outcome; a payment where the card was sent but no success page was seen is reported **`unconfirmed`**, never `refused`, and stops the run.
Open risks on the real page: an hCaptcha or 3-D Secure challenge needs a human in the live view; Stripe fraud rules may decline an automated session; success detection assumes a thank-you page or a redirect.

---

## 3c. Web app: add a card and watch the agent pay, without a terminal
`python webapp.py` serves `http://127.0.0.1:8765` (localhost only; refuses other hosts and cross-site posts).
- **Add card:** the number is encrypted **in the page** (WebCrypto: X25519 → HKDF-SHA256 → AES-256-GCM, bound to a server-issued card id) and the input is cleared; the server receives ciphertext only, shown on the page. The same sealing code, run in Node, produces a box the Python enclave opens (tested); a box for one card id is refused under another.
- **Pay:** billing details, CVC (also encrypted in the page, one box per payment, tied to a one-time nonce the enclave consumes) and a typed `PAY` confirmation. Limits: 1–10 payments of at most $2.00.
- **Mandate ("Autopilot"):** the owner authorizes once (1–10 payments, at most $2.00 each, valid at most 60 minutes, typed `AUTHORIZE`). The CVC is encrypted in the page into one box per authorised payment and held in **server memory only**. After that, `POST /api/agent/pay` (or the "Let the agent pay" button) takes **no card, no CVC and no billing details**; each call consumes one box, runs the same graph (freeze, policy, velocity, risk, enclave checks), and the owner can revoke at once. State never exposes the boxes. Tested: confirmation and limit checks, pay-with-no-inputs until used up, instant revoke, expiry, and a freeze still stopping an agent that holds a mandate.
- **Trade-off, stated plainly:** pre-sealed CVC boxes are card-verification data held (encrypted, in RAM, short-lived, one-time) beyond a single authorization. PCI DSS forbids keeping a CVC after authorization even encrypted, so this is a **test-scope design**; a production system would need a processor that allows card-on-file without a CVC or a device-side step per payment.
- **Watch:** the Kernel live view of the stateless browser, the agent's log, the results table, alerts, and a **Freeze everything / Lift** button. When the guard wants a human, an **Approve / Reject** box appears; nothing is paid while it waits.
- **Persistence:** with a passphrase the enclave key is kept in `output/enclave_key.json` (scrypt → AES-256-GCM) and cards in `output/cards_web.json`, so cards survive restarts (tested; a wrong passphrase is refused). This is a stand-in for KMS, not production key custody. Billing details are remembered in the browser only.
- **Limits:** the enclave is a mock; the live-view iframe depends on Kernel allowing embedding; **not yet run with a real card from the page**.

---

## 4. Guardrails (what stops what)
| Threat | Control | Enforced in | Verified by |
|---|---|---|---|
| Agent or model learns the card | Agent proposes JSON only; digits shaped like a card are redacted at the door and in model output; `card_number` field rejected | graph, policy | eval `leak_*` (6), flow tests |
| Card leaks into state, ledger, alerts, store, logs | Redaction, ciphertext-only store, alert redaction | graph, `alerts.py`, `cardstore.py` | leak scanner over every run; eval no-leak 100% |
| Spending too much | per-purchase cap, total budget, expiry | `policy.py` + enclave cap | eval `atk_*`, flow tests |
| Paying the wrong party | merchant + currency allowlist; enclave only sends to `api.stripe.com`; request amount must equal approved amount | policy, enclave | enclave tests, injection test on a real browser |
| Runaway or scripted spending | **Velocity caps**: payments per minute/hour/day, spend per hour/day | `guard.py` | `atk_velocity_*`, unit tests |
| Card-testing and anomalies | **Risk score 0–100**: first payment to a merchant +20; amount over 3× usual +25; 3+ small payments in 5 min +40 (card-testing); 2 failures in 10 min +25, 4+ +45. ≥40 forces a human even under the auto limit; ≥70 denies | `guard.py` | `atk_card_testing_*`, `atk_repeated_failures_*`, unit tests |
| A rogue agent keeps going | **Instant freeze** by scope: `all`, `agent:`, `card:`, `merchant:`. Checked at decision time, **again just before the payment**, and mirrored into the enclave as **user-signed revocations** the host cannot forge, replay or lift | `guard.py`, graph, enclave | freeze tests (incl. freeze *after* approval), enclave revoke/lift tests, `freeze.py` live demo |
| Not knowing what happened | **Alerts** on every payment, denial, step-up and freeze (JSON lines, optional webhook); hash-chained ledger; independent Stripe read-back | `alerts.py`, agent kernel | alert tests; webhook **not verified** |
| Double charge / replay | single-use placeholder burned before the charge; idempotency key per placeholder | enclave, processor | enclave + processor tests |
| Page lies (shows $1, submits $99.99) | enclave compares the request amount with the approved amount | enclave | live browser test |
| Prompt injection from a page | amount is read from the DOM by code; no page text is parsed by the model | `browser.py` | live browser test |

Thresholds are configuration (`config/policy.interview.json`): auto-approve under $2, per-purchase cap $20, total budget $20, burst detector set to 20 for the demo (default 3; the eval keeps the strict value).

---

## 5. Stored cards: the ciphertext in detail
**Enrolment (`EnclaveVault.enroll`).**
1. The device that holds the card builds `{number, exp_month, exp_year}` (the CVC is dropped, never stored).
2. It generates a fresh **X25519** key pair, does ECDH with the enclave's public key, and derives a 256-bit key with **HKDF-SHA256** (info = label ‖ ephemeral public key ‖ enclave public key).
3. It encrypts with **AES-256-GCM**, a random 96-bit nonce, and the **card id as associated data**.
4. Output: `{epk, nonce, ct, aad}`. The enclave opens it once to validate (Luhn, brand) and returns only display fields; the host stores the box plus `brand/last4/exp`.

**What is on disk (`output/cards.json`, mode 600):** the box and display fields. **Not on disk:** the number in clear, the CVC, any key.

**Why a stolen file is useless:** opening it needs the enclave's X25519 **private** key. The AEAD tag detects any change; the associated data binds a box to its card id, so a box for card A cannot be passed off as card B (tested); a box sealed to another enclave cannot be opened (tested).

**CVC (finding).** Stripe refused a stored card without a security code ("You must collect the security code…"), and PCI DSS forbids keeping a CVC after authorization, even encrypted. So the CVC is supplied **per payment**, sealed to the enclave with the placeholder token as associated data (usable for that one payment, then discarded). Consequence: a fully unattended payment from a stored card needs either a processor that allows card-on-file without a CVC, or a device-side step that supplies it. This is a real product constraint, not solved here.

**Key custody (mock vs real).** In the mock the enclave key lives in the process, so a stored box does not survive a restart. In the real build the private key is generated inside a Nitro enclave and sealed by **KMS**, released only to an enclave whose attestation (PCR values) matches; that is what makes the ciphertext durable and the host unable to read it. **Not built.**

**Per-payment mode** (card sealed at approval time, nothing stored) remains available and is tested.

---

## 6. Nitro design and preparation status
The enclave logic now runs as a **separate program** (`vault_harness/enclave_rpc.py`: a length-prefixed JSON protocol, `EnclaveServer`, and an `EnclaveClient` with the same interface, so the harness, hosted checkout and web app are unchanged). The channel is untrusted by design: it carries only ciphertext, placeholders, public data and masked results.

| Concern | Built and tested locally | Needs real Nitro (UNVERIFIED) |
|---|---|---|
| Separate enclave process, socket protocol | **yes** (tcp; no card number on the wire) | vsock transport |
| Packaged image (`nitro/Dockerfile`, 259 MB, six source files, no keys, no `.env`) | **yes**: builds and runs; used by the harness in Stripe test mode | the EIF build with `nitro-cli` |
| Config baked into the image (signer **public** keys, limits, host and path allowlists), so it is covered by PCR0 | **yes** (`nitro/gen_signers.py`) | PCR0 value |
| Attestation **verification** (COSE_Sign1, certificate chain to a supplied root, PCR0, key binding, nonce, freshness, rejects debug mode) | **yes**, against a synthetic CA with 9 tamper cases | a real AWS document and the AWS root certificate |
| Harness refuses an enclave that does not verify; the page shows "NITRO, attestation verified · PCR0 …" only then | **yes** (fail-closed test) | with real attestation |
| Attestation fetch inside the enclave (`libnsm`) | written from the documented C API | needs `/dev/nsm`; `libnsm` build needs a **reviewed commit** (`NSM_REF`), not test-built |
| Egress to `api.stripe.com` | forwarder tested with TCP stand-ins | vsock proxy + TLS end to end; enclave clock for certificate validation |
| Approval | Ed25519 signatures checked inside; **the user key is still a software stand-in held by the harness** | passkey (WebAuthn) verified in the enclave |
| Key persistence | passphrase-sealed key file (mock); fresh key per enclave boot | KMS key policy released only to the attested image (template written, **phase 2, not built**) |
| Launch, setup, build, run, teardown scripts, step-by-step guide (`nitro/README.md`) | syntax-checked only | **never run**: no AWS access was available |

Cost: Nitro Enclaves has no extra charge; the free-tier micro instance is not supported; an `.xlarge` is roughly USD 0.15–0.20/hour (from memory, check the live price).

---|---|---|
| Isolation | none (same process) | enclave VM, no network, no persistent storage |
| Key | in-process X25519 | generated in enclave, KMS-sealed, attestation-gated release |
| Host link | function call | vsock only; egress via a vsock TLS proxy that cannot read the bytes |
| Approval | Ed25519 signatures; **user key is a software stand-in held in the harness process (the weakest link)** | passkey (WebAuthn) assertion verified in the enclave; key never leaves the device |
| Revocation | user-signed commands, replay-protected | same |
| Zeroization | best effort (Python cannot guarantee it) | Rust/C with explicit wipe |
| Attestation | `attest()` returns key + config hash | signed attestation document, checked by the sealing page and KMS |

---

## 7. Test results
**Suite:** `RUN_LIVE=1 pytest -q tests` → **175 passed**, 0 failed. Offline (`pytest -q tests`): **168 passed, 7 skipped** (the skipped ones need a real Kernel browser, Docker or live keys).

| Area | Tests | Proves |
|---|---|---|
| Flow + policy (`test_flow`) | 16 | auto / human / deny paths; budget accumulates; card in task or model output redacted |
| Placeholders (`test_vault`) | 4 | single use, bound, expiring |
| Agentcard client (`test_agentcard`) | 31 | token, errors, validation, no retry on create, reconcile (**fixtures only**) |
| Kernel vault client (`test_kernel_vault`) | 10 | one wallet per vault, mode fails closed (fixtures; the live calls ran separately) |
| Enclave (`test_enclave`) | 16 | swap only inside; signature, cap, host, amount checks; tamper and wrong-enclave failures |
| Stateless browser (`test_browser`) | 9 (4 live) | no profile/vault/pool; deleted on every path; **live:** a fresh session sees none of another's cookies/storage; only the placeholder is typed; injected page text ignored; lying page stopped by the enclave |
| Wiring + Stripe processor (`test_wiring`) | 11 | graph → enclave → processor; test-key-only; approved amount used; errors redacted |
| Guard, store, leak (`test_guard`) | 29 | velocity, risk, every freeze scope, freeze after approval, enclave revocation, alerts, ciphertext store, CVC binding, scanner finds a planted card and ignores 6,000 random ids |
| Agent kernel (`test_kernel`) | 5 | ledger verifies, halt switch, post-check |
| Web app (`test_webapp`) | 9 | host and header checks; card sealed by the browser code accepted by the enclave and refused under another id; ciphertext-only storage; pay validation; full run loop through the real graph; freeze from the page; human approval gates a payment; rejection pays nothing |
| Hosted checkout (`test_hosted_checkout`) | 8 (1 live) | forward-mode swap with formatted card and 2-digit year; path allowlist; reply withheld if it carries card digits; header whitelist; CORS echo; Visa-shaped placeholder. **Live:** local stand-in checkout in a real Kernel browser → interception → enclave swap → **real Stripe test-mode PaymentMethod** → page success |
| Enclave as a separate program (`test_enclave_rpc`) | 5 | full payment across a real socket with **no card number on the wire**; refusals and user-signed revocation cross the channel; errors never leak request contents; the attestation nonce reaches the enclave and a failing verifier makes `attest` fail closed |
| Attestation verifier (`test_attestation`) | 9 | a genuine **synthetic** document verifies; rejected: wrong image (PCR0), tampered bytes, untrusted CA, expired certificate, wrong public key, replayed nonce, stale timestamp, debug-mode zero PCRs, garbage. **Not yet tried on a real AWS document** |
| Packaged enclave image (`test_nitro_local`, live) | 2 | the 259 MB image runs as a container; the harness attests, enrolls and revokes over the socket; a real Kernel browser pays through it into a **real Stripe test-mode PaymentMethod**; the container log holds no card number |
| Eval gate (`test_eval`) | 2 | no metric below baseline |

**Golden eval** (`evals/run_eval.py`, **36 cases**: 10 control, 20 attack, 6 leak): control no-false-alarm **100%**, attack no-miss **100%**, leak outcomes **100%**, card number found in state/result/ledger: **0**. The eval was checked by breaking things: with redaction off, leak cases fell to 67%; with allowlist/cap/budget off, attacks fell to 42%. During the build it also caught a real miss (card-testing burst scored too low to force a human); the engine was fixed, the case was not edited.

**Live Stripe sandbox payments (test mode, test card, every one read back from Stripe):** **18 of 18 reconciled** (amount, currency, `succeeded`, `livemode:false`).
- Payments 1–10, per-payment card entry: `pi_3UVqcjKCp4CjFk8l0thalE2G`, `pi_3UVqd7KCp4CjFk8l0LToagT8`, `pi_3UVqdDKCp4CjFk8l0iNX3kIZ`, `pi_3UVqdJKCp4CjFk8l08jaUYnb`, `pi_3UVqdOKCp4CjFk8l0C1weEnk`, `pi_3UVqdUKCp4CjFk8l1DidkIXm`, `pi_3UVqdZKCp4CjFk8l0nDsCMSg`, `pi_3UVqdfKCp4CjFk8l1V5Ka3qV`, `pi_3UVqdlKCp4CjFk8l0k2tfzk8`, `pi_3UVqdrKCp4CjFk8l0VFxOd9J`.
- Payments 11–13, **card enrolled once as ciphertext**, per-payment sealed CVC: `pi_3UVsc8KCp4CjFk8l1LDVmkMH`, `pi_3UVscEKCp4CjFk8l1xZZqLdG`, `pi_3UVscJKCp4CjFk8l0z0mL7l3`.
- Payments 14–18, a second run with a freshly enrolled ciphertext card, after all final changes: `pi_3UVuw2KCp4CjFk8l16UPDzU3`, `pi_3UVuw7KCp4CjFk8l04u4mIB4`, `pi_3UVuwDKCp4CjFk8l08kyVwSt`, `pi_3UVuwIKCp4CjFk8l0JzBKaCx`, `pi_3UVuwOKCp4CjFk8l0imTTMTN`.
- Total recorded in the budget file: 1800 of 2000 cents. All payments are Stripe **test mode** with Stripe's public test card: no real money moved.

**Live freeze demo:** after `freeze.py freeze merchant:stripe-test-mode`, the next payment was denied before any browser started, with a `critical` alert; `lift` restored it.

**Leak scan** over `output/` and the ledger after the live runs: 0 findings. Scope: files only (see §8).

**Journey notes (honest log).** Stripe refused raw card numbers on a secret key, then on a publishable key until a sandbox setting was enabled, then refused the end-of-life Charges API (now PaymentMethods + PaymentIntents), then refused a stored card without a CVC. Each refusal came back as `refused`, with no charge and no card number in any output. Several tests were flaky because they searched random hex for short substrings (`123`, `4242`) and the leak scanner mistook random ids for card numbers; each was traced to its cause and fixed (stability: the offline suite passed 600 consecutive runs after the fixes, 0 failures).

---

## 8. Not verified / not built
- **Real AWS Nitro Enclave**: vsock, a real attestation document, KMS key release and the Stripe vsock proxy were prepared (§6, `nitro/`) but **never run on AWS**. Locally the enclave is a separate containerised program with no hardware isolation.
- **Passkey (Face ID / Touch ID) approval.** Approval is a software stand-in; the user signing key lives in the harness process.
- **Attestation in the sealing page.** The page encrypts to the enclave's public key, but with a mock enclave there is no attestation document for it to verify.
- **Agentcard live API** (no builder credentials) and the vendor's payment through the swap (stopped before the click).
- **A real-card payment on the Perflo link.** Built and rehearsed (§3b) but **not executed by the assistant**; it needs the card owner at a terminal. The sandbox Stripe processor still refuses live keys by design. The company's test card was enrolled in Agentcard's wallet only.
- **Webhook alert delivery** (the sink exists; no receiver was tested). No SMS/email alerting.
- **Process-memory, swap and core-dump leakage.** The scanner reads files only; memory safety is a property of the real enclave, not tested here.
- **LLM quality.** The model is a scripted writer, so the eval scores the guardrails and plumbing, not model behaviour.
- **Unattended stored-card payments** without a per-payment CVC (see §5).
- **Compliance.** PCI DSS scoping, dispute handling, insurance, KYC: out of scope.

## 9. Reproduce
```bash
cd ~/vault-harness
.venv/bin/python -m pytest -q tests                 # offline
RUN_LIVE=1 .venv/bin/python -m pytest -q tests      # + real Kernel browsers
.venv/bin/python evals/run_eval.py                  # 36-case golden eval + baseline gate
.venv/bin/python demo.py --browser                  # guardrail scenarios + real browser → enclave swap
.venv/bin/python pay_one_dollar.py --live --stored --times 3   # Stripe sandbox, ciphertext card (needs STRIPE_TEST_KEY, STRIPE_PUBLISHABLE_KEY in .env)
.venv/bin/python freeze.py freeze all --reason "incident"      # instant revocation
.venv/bin/python -m vault_harness.leakscan output   # card-number scan
```

## 10. Appendix: AWS Nitro steps
See `nitro/CONSOLE_STEPS.md` (browser-console checklist, 14 steps) and `nitro/README.md` (what is and is not tested) for the steps (billing alarm, SSO login, launch with no inbound ports, SSM access, build with a reviewed libnsm commit, run, verify attestation, view through an SSM port forward, terminate). None of them has been executed.
