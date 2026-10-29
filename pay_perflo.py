"""Pay the $1 Perflo Pay link through the harness: guard -> stateless Kernel browser (placeholder only) -> enclave swap -> Stripe.

  python pay_perflo.py --capture-only                     SAFE rehearsal: types the placeholder, intercepts the request, sends NOTHING to Stripe
  python pay_perflo.py --live --times 5 --email you@x.com --name "Your Name" --country IN --zip 560001 [--address ... --city ...]
        REAL PAYMENTS of $1.00 each with the card you type at the hidden prompts. Run it in a real Terminal window, not through `!`.

The card is typed at hidden prompts in YOUR terminal, sealed to the enclave key, and kept only as ciphertext for this run.
CVC: asked once, held in this process for the run only, sealed fresh for every payment, never written to disk.
Real-money state is separate from the sandbox state: output/budget_real.json, events_real.db, alerts_real.jsonl.
Stop everything at any moment from another terminal:  python freeze.py freeze all --reason stop
"""
import argparse
import getpass
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
_scratch = Path(tempfile.mkdtemp(prefix="vh-rehearsal-")) if "--capture-only" in sys.argv else None     # rehearsals never touch real-money state
os.environ["VAULT_EVENTS_DB"] = str((_scratch or ROOT / "output") / "events_real.db")
os.environ["VAULT_ALERTS_FILE"] = str((_scratch or ROOT / "output") / "alerts_real.jsonl")
os.environ["VAULT_POLICY"] = (ROOT / "config" / "policy.interview.json").read_text()

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from langgraph.checkpoint.memory import MemorySaver  # noqa: E402
from langgraph.types import Command  # noqa: E402

from vault_harness import actions, policy  # noqa: E402
from vault_harness import enclave as E  # noqa: E402
from vault_harness.cardstore import CardStore  # noqa: E402
from vault_harness.fake_model import ScriptedWriter  # noqa: E402
from vault_harness.graph import build, start  # noqa: E402
from vault_harness.hosted_checkout import ForwardProcessor, HostedCheckoutVault  # noqa: E402

LINK = "https://buy.stripe.com/4gM8wI7ET9eGdCL5292B204"
policy.BUDGET_FILE = (_scratch or ROOT / "output") / "budget_real.json"


def ask_card() -> dict:
    n = getpass.getpass("card number (hidden): ").replace(" ", "").replace("-", "")
    m = getpass.getpass("expiry month MM (hidden): ")
    y = getpass.getpass("expiry year YYYY (hidden): ")
    return {"number": n, "exp_month": int(m), "exp_year": int(y if len(y) == 4 else "20" + y)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--capture-only", action="store_true")
    ap.add_argument("--times", type=int, default=1)
    ap.add_argument("--cents", type=int, default=100)
    ap.add_argument("--url", default=LINK)
    ap.add_argument("--email", default="test@example.com")
    ap.add_argument("--name", default="Test User")
    ap.add_argument("--country", default="US")
    ap.add_argument("--zip", default="94107")
    ap.add_argument("--address", default="")
    ap.add_argument("--city", default="")
    ap.add_argument("--state", default="", help="state/province if the checkout asks for it")
    a = ap.parse_args()
    if a.live == a.capture_only:
        sys.exit("choose exactly one of --live or --capture-only")
    names = {"united arab emirates": "AE", "uae": "AE", "india": "IN", "united states": "US", "usa": "US", "united kingdom": "GB", "uk": "GB",
             "singapore": "SG", "canada": "CA", "australia": "AU", "germany": "DE", "france": "FR"}
    a.country = names.get(a.country.strip().lower(), a.country.strip().upper())
    if len(a.country) != 2:
        sys.exit(f"--country must be a 2-letter code like AE, IN, US (got {a.country!r})")
    a.name, a.email, a.address, a.city, a.state = (x.strip() for x in (a.name, a.email, a.address, a.city, a.state))
    if a.capture_only:                                           # dummy billing details for the rehearsal only
        a.address, a.city = a.address or "1 Market St", a.city or "San Francisco"
    else:
        missing = [f for f, v in (("--email", a.email if a.email != "test@example.com" else ""), ("--name", a.name if a.name != "Test User" else ""),
                                  ("--address", a.address), ("--city", a.city), ("--zip (use - if your country has no postal code)", a.zip if a.zip != "94107" else ""), ("--country", a.country)) if not v]
        if missing:
            sys.exit("--live needs your real billing details, matching the card: " + ", ".join(missing))
    if a.cents > 200 or a.times > 10:
        sys.exit("refusing: this runner is capped at $2.00 per payment and 10 payments")

    cfg = json.loads((ROOT / "config" / "policy.interview.json").read_text())
    pol = policy.Policy(**{k: (tuple(v) if isinstance(v, list) else v) for k, v in cfg.items()})
    if a.live:
        print(f"\nREAL MONEY: {a.times} x ${a.cents/100:.2f} to 'Perflo Pay' ({a.url.split('/')[2]}). Budget cap ${pol.budget_total_cents/100:.2f} (this runner's own counter: {policy.Budget().spent()} cents spent).")
        if input("Type PAY to authorise, anything else to stop: ").strip() != "PAY":
            sys.exit("stopped, nothing sent")
        card = ask_card()
        cvc = getpass.getpass("cvc (hidden): ")
    else:
        card, cvc = {"number": "4242424242424242", "exp_month": 12, "exp_year": 2030}, "123"       # Stripe's public test card; never sent in capture-only

    user, polkey = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    raw = lambda k: k.public_key().public_bytes(*E._RAW)
    enc = E.MockEnclave(user_pub=raw(user), policy_pub=raw(polkey), processor=ForwardProcessor(), auto_limit_cents=pol.auto_approve_under_cents,
                        max_single_cents=pol.max_single_cents, allowed_paths=("/v1/payment_methods",))
    store = CardStore(Path(tempfile.mkdtemp(prefix="vh-cards-")) / "cards.json")
    vault = HostedCheckoutVault(enc, checkout_url=a.url, capture_only=a.capture_only, user_key=user, policy_key=polkey, card_store=store,
                                cvc_source=lambda: cvc, auto_limit_cents=pol.auto_approve_under_cents, make_browser=None, make_page=None,
                                billing={"email": a.email, "name": a.name, "country": a.country, "zip": "" if a.zip == "-" else a.zip, "address": a.address, "city": a.city, "state": a.state})
    info = vault.enroll(card)
    card = None                                                              # the harness keeps ciphertext only from here on
    print(f"card on file as ciphertext: {info['brand']} ****{info['last4']}  id={info['card_id']}")
    actions.use(vault)
    draft = json.dumps({"merchant": "buy.stripe.com", "amount_cents": a.cents, "currency": "usd", "description": "Perflo Pay test product"})
    ok = 0
    for n in range(1, a.times + 1):
        g, cfgd = build(MemorySaver(), ScriptedWriter(drafts=[draft])), {"configurable": {"thread_id": f"perflo-{n}-{os.urandom(3).hex()}"}}
        try:
            start(g, f"Pay the ${a.cents/100:.2f} Perflo test (#{n})", True, cfgd, card_id=info["card_id"])
        except Exception as e:                                                # the kernel halts the agent on an unexpected outcome
            print(f"#{n} HALTED: {type(e).__name__}: {str(e)[:300]}\nCheck your email receipt / the merchant before doing anything else."); return 1
        st = g.get_state(cfgd).values
        if any(t.interrupts for t in g.get_state(cfgd).tasks):
            print(f"#{n} the guard wants a human: {st['verdict']['reasons']}")
            ans = input("Type APPROVE to go ahead with this payment, anything else to stop: ").strip()
            if ans != "APPROVE":
                print("stopped by you, nothing sent"); return 2
            g.invoke(Command(resume={"decision": "approve"}), cfgd)
            st = g.get_state(cfgd).values
        res = st.get("result") or {}
        if a.capture_only:
            print("CAPTURE-ONLY result:", json.dumps(res.get("observed") or res))
            print("driver state:", json.dumps({k: v for k, v in getattr(vault, "last", {}).items() if k in ("calls", "aborted", "success", "final", "snippet", "error", "exception", "form_errors")})); return 0
        print(f"#{n} outcome={st.get('outcome')} payment_method={res.get('charge_id','-')} last4={res.get('card_last4','-')}" + ("" if st.get("outcome") == "done" else f"  reason={res.get('reason') or st.get('verdict')}"))
        if st.get("outcome") != "done":
            return 1
        ok += 1
    print(f"\n{ok}/{a.times} payments completed. Counter: {policy.Budget().spent()} cents. Receipts go to {a.email}; confirm them in the merchant dashboard.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
