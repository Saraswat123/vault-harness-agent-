"""The $1 payment: harness agent -> policy -> stateless Kernel browser -> enclave swap -> Stripe TEST mode -> independent read-back.

  python pay_one_dollar.py            dry run: shows the plan, charges nothing, needs no Stripe key
  python pay_one_dollar.py --live     real Stripe TEST-mode charge of $1.00 (needs STRIPE_TEST_KEY=sk_test_... in .env)
  python pay_one_dollar.py --live --times 10   ten $1 payments, stops at the first problem; budget cap ($20) still applies
  python pay_one_dollar.py --live --prompt-card
                                      type the card at a hidden prompt instead of using Stripe's public 4242 test card.
                                      Use only a card you were told is for testing. In TEST mode Stripe accepts test numbers only.
Test mode is enforced in code: the Stripe processor refuses any key that is not sk_test_/rk_test_.
"""
import argparse
import getpass
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from langgraph.checkpoint.memory import MemorySaver  # noqa: E402

from vault_harness import actions, policy  # noqa: E402
from vault_harness import enclave as E  # noqa: E402
from vault_harness.browser import KernelSession, checkout_page  # noqa: E402
from vault_harness.enclave_vault import EnclaveVault  # noqa: E402
from vault_harness.fake_model import ScriptedWriter  # noqa: E402
from vault_harness.graph import build, start  # noqa: E402
from vault_harness.stripe_processor import StripeTestProcessor  # noqa: E402

TEST_CARD = {"number": "4242424242424242", "exp_month": 12, "exp_year": 2030, "cvc": "123"}      # Stripe's public test card


def card_from_prompt() -> dict:
    n = getpass.getpass("card number (hidden): ").replace(" ", "")
    m = getpass.getpass("exp month MM (hidden): ")
    y = getpass.getpass("exp year YYYY (hidden): ")
    c = getpass.getpass("cvc (hidden): ")
    return {"number": n, "exp_month": int(m), "exp_year": int(y), "cvc": c}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="actually create the TEST-mode charge")
    ap.add_argument("--prompt-card", action="store_true")
    ap.add_argument("--cents", type=int, default=100)
    ap.add_argument("--times", type=int, default=1)
    ap.add_argument("--stored", action="store_true", help="enroll the card ONCE as ciphertext in a card store and pay with its card id")
    a = ap.parse_args()
    pol = policy.Policy(**{k: (tuple(v) if isinstance(v, list) else v) for k, v in json.loads((ROOT / "config" / "policy.interview.json").read_text()).items()})
    os.environ["VAULT_POLICY"] = (ROOT / "config" / "policy.interview.json").read_text()

    processor = None
    if a.live:
        processor = StripeTestProcessor()                                     # raises on a missing or non-test key
    user, polkey = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    raw = lambda k: k.public_key().public_bytes(*E._RAW)
    enc = E.MockEnclave(user_pub=raw(user), policy_pub=raw(polkey), processor=processor or (lambda r: {"status": 500, "json": {}}),
                        auto_limit_cents=pol.auto_approve_under_cents, max_single_cents=pol.max_single_cents)
    from vault_harness.cardstore import CardStore
    store = CardStore(ROOT / "output" / "cards.json") if a.stored else None
    vault = EnclaveVault(enc, user_key=user, policy_key=polkey, card_source=card_from_prompt if a.prompt_card else (lambda: dict(TEST_CARD)),
                         make_browser=lambda: KernelSession(name="vault-harness-pay"), make_page=lambda i: checkout_page(i.amount_cents),
                         auto_limit_cents=pol.auto_approve_under_cents, card_store=store,
                         cvc_source=(lambda: getpass.getpass("cvc (hidden): ")) if (a.stored and a.prompt_card) else (lambda: TEST_CARD["cvc"]))
    card_id = ""
    if a.stored:
        info = vault.enroll(card_from_prompt() if a.prompt_card else dict(TEST_CARD))          # sealed to the enclave key; ciphertext stored
        card_id = info["card_id"]
        print(f"card on file: {info['brand']} ****{info['last4']} id={card_id}  (ciphertext only in {store.path.name}; CVC not stored)")
    actions.use(vault)

    draft = json.dumps({"merchant": "stripe-test-mode", "amount_cents": a.cents, "currency": "usd", "description": "harness test payment"})
    print(f"mode: {'LIVE (Stripe TEST mode)' if a.live else 'DRY RUN'}   payments: {a.times} x ${a.cents/100:.2f}   budget so far: {policy.Budget().spent()} of {pol.budget_total_cents} cents")
    rows = []
    for n in range(1, a.times + 1):
        g = build(MemorySaver(), ScriptedWriter(drafts=[draft]))
        cfg = {"configurable": {"thread_id": f"pay-{n}-{os.urandom(3).hex()}"}}
        start(g, f"Pay the ${a.cents/100:.2f} test (#{n})", a.live, cfg, card_id=card_id)
        st = g.get_state(cfg).values
        if any(t.interrupts for t in g.get_state(cfg).tasks):
            print(f"#{n} PAUSED for human approval ({st['verdict']['reasons']}); stopping."); return 2
        res = st.get("result") or {}
        row = {"n": n, "outcome": st.get("outcome"), "charge": res.get("charge_id", "-"), "last4": res.get("card_last4", "-"), "stripe": "-"}
        if a.live and st.get("outcome") == "done":
            ch = processor.get_payment(res["charge_id"])                        # independent read-back from Stripe
            ok = (ch["amount"] == a.cents and ch["amount_received"] == a.cents and ch["currency"] == "usd" and ch["status"] == "succeeded" and ch["livemode"] is False)
            row["stripe"] = "RECONCILED" if ok else "MISMATCH"
        rows.append(row)
        print(f"#{n:<2} outcome={row['outcome']:18s} charge={row['charge']:28s} last4={row['last4']}  stripe={row['stripe']}")
        bad = row["outcome"] not in ("done", "dry_run_previewed") or row["stripe"] == "MISMATCH"
        if bad:                                                                  # fail fast: never keep spending after a problem
            print(f"STOP at #{n}: {st.get('result') or st.get('verdict')}"); return 1
    done = sum(r["outcome"] == "done" for r in rows)
    print(f"\nsummary: {len(rows)} run, {done} charged, {sum(r['stripe'] == 'RECONCILED' for r in rows)} reconciled with Stripe, spent {policy.Budget().spent()} of {pol.budget_total_cents} cents")
    return 0


if __name__ == "__main__":
    sys.exit(main())
