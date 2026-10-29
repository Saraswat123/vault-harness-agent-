"""Demo: guarded agent payments. Offline by default; --browser adds a real Kernel browser + the mock enclave swap.
Uses Stripe's public TEST card number only inside the enclave step. Nothing real is charged: the processor is a local stub."""
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
tmp = Path(tempfile.mkdtemp(prefix="vault-demo-"))
os.environ.update(BLACKBOX_DIR=str(tmp / "ledger"), AGENT_CONTROL_DIR=str(tmp / "control"), VAULT="mock",
                  VAULT_POLICY=(ROOT / "config" / "policy.interview.json").read_text())

from langgraph.checkpoint.memory import MemorySaver  # noqa: E402
from langgraph.types import Command  # noqa: E402

from vault_harness import actions, policy  # noqa: E402
from vault_harness.fake_model import ScriptedWriter  # noqa: E402
from vault_harness.graph import build, start  # noqa: E402

policy.BUDGET_FILE = tmp / "budget.json"


def d(cents, merchant="buy.stripe.com"):
    return json.dumps({"merchant": merchant, "amount_cents": cents, "currency": "usd", "description": "demo"})


def scenario(title, task, draft, approve=None):
    actions.reset()
    g, cfg = build(MemorySaver(), ScriptedWriter(drafts=[draft])), {"configurable": {"thread_id": title}}
    start(g, task, True, cfg)
    waiting = any(t.interrupts for t in g.get_state(cfg).tasks)
    note = ""
    if waiting:
        note = " -> paused for human approval"
        if approve:
            g.invoke(Command(resume={"decision": approve}), cfg); note += f" -> human said {approve}"
    st = g.get_state(cfg).values
    why = st.get("verdict", {}).get("reasons") if st.get("outcome") == "denied" else ""
    print(f"  {title:34s} outcome={st.get('outcome') or 'awaiting_approval':18s}{note} {why or ''}")
    return st


print("Policy: auto-approve < $2, per-purchase cap $20, total budget $20, merchants buy.stripe.com / shop.agentcard.sh\n")
scenario("$1 test payment", "Pay the $1 test", d(100))
scenario("$5 payment, human approves", "Pay $5", d(500), approve="approve")
scenario("$5 payment, human rejects", "Pay $5", d(500), approve="reject")
scenario("$25 (over the $20 cap)", "Pay $25", d(2500))
scenario("unknown merchant", "Pay evil", d(100, "evil.example"))
st = scenario("card typed into the task", "Pay $1 with card 4242 4242 4242 4242", d(100))
print(f"\n  state holds the card number?  {'4242 4242' in repr(st)}   (input_redacted={st.get('input_redacted')})")
print(f"  spent so far: {policy.Budget().spent()} cents of {json.loads(os.environ['VAULT_POLICY'])['budget_total_cents']}")

if "--browser" in sys.argv:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from vault_harness import enclave as E
    from vault_harness.browser import KernelSession, checkout_page
    PAN = "4242424242424242"                              # Stripe public test card
    seen = []
    def stripe(req):
        seen.append(req); return {"status": 200, "json": {"id": "ch_demo_stub", "status": "succeeded", "amount": 100, "last4": PAN[-4:]}}
    user, pol = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    raw = lambda k: k.public_key().public_bytes(*E._RAW)
    enc = E.MockEnclave(user_pub=raw(user), policy_pub=raw(pol), processor=stripe, auto_limit_cents=200)
    print("\nReal Kernel browser (stateless, no profile) -> placeholder only -> mock enclave swap")
    with KernelSession(name="vault-harness-demo") as br:
        probe = enc.issue_placeholder(policy.Intent("buy.stripe.com", 100, "usd"))
        cap = br.capture_checkout(checkout_page(100), probe)
    print(f"  browser session deleted afterwards:  {br.deleted}")
    print(f"  total read from the page DOM by code: {cap['total_cents']} cents")
    print(f"  browser typed placeholder, not the card: placeholder in request={probe.number in cap['request']['body']}, real card in request={PAN in json.dumps(cap)}")
    intent = policy.Intent("buy.stripe.com", cap["total_cents"], "usd")
    ph = enc.issue_placeholder(intent)
    body = cap["request"]["body"].replace(probe.number, ph.number).replace(f"card[cvc]={probe.cvc}", f"card[cvc]={ph.cvc}")
    out = enc.pay(sealed=E.seal(bytes.fromhex(enc.attest()["pubkey"]), {"number": PAN, "exp_month": 12, "exp_year": 2030, "cvc": "123"}),
                  placeholder=ph, intent=intent, request={**cap["request"], "body": body},
                  approval={"signer": "policy", "sig": pol.sign(E.approval_message(intent, ph.token)).hex()})
    print(f"  enclave result (masked): {out}")
    print(f"  processor stub received the REAL card: {PAN in seen[0]['body']};  harness/agent ever held it: False")
