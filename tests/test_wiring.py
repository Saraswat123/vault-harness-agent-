"""graph -> act -> EnclaveVault -> (stateless browser) -> mock enclave -> processor. Browser is faked here; the live version is test_browser + demo."""
import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from vault_harness import actions, kernel_setup, policy
from vault_harness import enclave as E
from vault_harness.browser import checkout_page
from vault_harness.enclave_vault import EnclaveVault
from vault_harness.fake_model import ScriptedWriter
from vault_harness.graph import build, start
from vault_harness.stripe_processor import StripeTestProcessor

PAN = "4242424242424242"
CARD = {"number": PAN, "exp_month": 12, "exp_year": 2030, "cvc": "123"}
CFG = {"configurable": {"thread_id": "w"}}
RAW = E._RAW


class FakeBrowser:
    """Stands in for KernelSession: types the placeholder into the form body, reports the DOM total."""
    def __init__(self, total_cents, form_amount=None, log=None): self.total, self.form, self.log = total_cents, form_amount, log
    def __enter__(self): return self
    def __exit__(self, *a):
        if self.log is not None: self.log.append("deleted")
    def capture_checkout(self, html, ph):
        amt = self.total if self.form is None else self.form
        body = f"card[number]={ph.number}&card[cvc]={ph.cvc}&card[exp_month]={ph.exp_month}&card[exp_year]={ph.exp_year}&amount={amt}"
        return {"total_cents": self.total, "request": {"url": "https://api.stripe.com/v1/tokens", "method": "POST", "headers": {}, "body": body}}


class Stripe:
    def __init__(self): self.seen = []
    def __call__(self, req):
        self.seen.append(req)
        return {"status": 200, "json": {"id": "ch_wired", "status": "succeeded", "amount": req["meta"]["amount_cents"], "last4": PAN[-4:]}}


@pytest.fixture
def rig(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, "BUDGET_FILE", tmp_path / "b.json")
    monkeypatch.setenv("VAULT_POLICY", (policy.Path(__file__).resolve().parent.parent / "config" / "policy.interview.json").read_text())
    user, pol, stripe, log = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Stripe(), []
    enc = E.MockEnclave(user_pub=user.public_key().public_bytes(*RAW), policy_pub=pol.public_key().public_bytes(*RAW), processor=stripe, auto_limit_cents=200, max_single_cents=2000)

    def wire(total, form_amount=None):
        actions.use(EnclaveVault(enc, user_key=user, policy_key=pol, card_source=lambda: dict(CARD), auto_limit_cents=200,
                                 make_browser=lambda: FakeBrowser(total, form_amount, log), make_page=lambda i: checkout_page(i.amount_cents)))
    yield wire, stripe, log
    actions.reset()


def run(cents, resume=None):
    d = json.dumps({"merchant": "stripe-test-mode", "amount_cents": cents, "currency": "usd", "description": "wired"})
    g = build(MemorySaver(), ScriptedWriter(drafts=[d]))
    start(g, "pay it", True, CFG)
    if resume and any(t.interrupts for t in g.get_state(CFG).tasks):
        g.invoke(Command(resume={"decision": resume}), CFG)
    return g.get_state(CFG).values


def test_one_dollar_flows_graph_to_processor_with_the_real_card_only_at_the_end(rig):
    wire, stripe, log = rig; wire(100)
    st = run(100)
    assert st["outcome"] == "done" and st["result"]["charge_id"] == "ch_wired" and st["result"]["card_last4"] == "4242"
    assert f"card[number]={PAN}" in stripe.seen[0]["body"] and stripe.seen[0]["meta"]["amount_cents"] == 100
    assert PAN not in repr(st) and PAN not in repr(list(kernel_setup.get_kernel().ledger.records()))
    assert log == ["deleted"] and policy.Budget().spent() == 100


def test_five_dollars_needs_the_human_then_the_user_key_signs(rig):
    wire, stripe, log = rig; wire(500)
    d = json.dumps({"merchant": "stripe-test-mode", "amount_cents": 500, "currency": "usd"})
    g = build(MemorySaver(), ScriptedWriter(drafts=[d])); start(g, "pay", True, CFG)
    assert stripe.seen == [] and any(t.interrupts for t in g.get_state(CFG).tasks)      # nothing reaches Stripe before approval
    g.invoke(Command(resume={"decision": "approve"}), CFG)
    assert g.get_state(CFG).values["outcome"] == "done" and len(stripe.seen) == 1


def test_page_total_different_from_the_approved_amount_is_refused_before_the_card_is_touched(rig):
    wire, stripe, log = rig; wire(total=999)
    st = run(100)
    assert st["outcome"] == "refused" and "page total 999" in st["result"]["reason"] and stripe.seen == [] and policy.Budget().spent() == 0


def test_page_that_shows_one_amount_and_submits_another_is_stopped_by_the_enclave(rig):
    wire, stripe, log = rig; wire(total=100, form_amount=9999)
    st = run(100)
    assert st["outcome"] == "refused" and "request amount 9999" in st["result"]["reason"] and stripe.seen == []


def test_browser_session_is_deleted_even_when_the_enclave_refuses(rig):
    wire, stripe, log = rig; wire(total=100, form_amount=9999)
    run(100)
    assert log == ["deleted"]


# ---- Stripe processor, with a fake transport ----
def stripe_transport(calls, charge_status=200):
    def h(r):
        calls.append(r)
        if r.url.path == "/v1/payment_methods":
            return httpx.Response(200, json={"id": "pm_1", "card": {"last4": "4242"}})
        if r.url.path == "/v1/payment_intents":
            return httpx.Response(charge_status, json={"id": "pi_1", "status": "succeeded", "amount": 100, "amount_received": 100, "livemode": False} if charge_status == 200 else {"error": {"message": "Your card was declined. 4242424242424242"}})
        return httpx.Response(404, json={})
    return httpx.MockTransport(h)


REQ = {"url": "https://api.stripe.com/v1/tokens", "method": "POST", "headers": {"cookie": "x"}, "body": f"card[number]={PAN}&card[cvc]=123&card[exp_month]=12&card[exp_year]=2030&amount=100",
       "meta": {"amount_cents": 100, "currency": "usd", "idempotency_key": "ph_abc"}}


def test_processor_refuses_a_live_key():
    with pytest.raises(ValueError, match="non-test"):
        StripeTestProcessor("sk_live_abc123", transport=stripe_transport([]))
    with pytest.raises(ValueError):
        StripeTestProcessor("pk_test_abc", transport=stripe_transport([]))


def test_processor_strips_amount_from_tokens_uses_the_approved_amount_and_idempotency_key():
    calls = []
    out = StripeTestProcessor("sk_test_abc", transport=stripe_transport(calls))(REQ)
    pm, pi = calls
    assert b"amount" not in pm.content and b"cookie" not in pm.content and b"type=card" in pm.content and pm.headers["authorization"] == "Bearer sk_test_abc"
    assert b"amount=100" in pi.content and b"confirm=true" in pi.content and b"payment_method=pm_1" in pi.content and pi.headers["idempotency-key"] == "ph_abc"
    assert out == {"status": 200, "json": {"id": "pi_1", "status": "succeeded", "amount": 100, "last4": "4242"}}


def test_processor_error_text_never_carries_a_card_number():
    out = StripeTestProcessor("sk_test_abc", transport=stripe_transport([], charge_status=402))(REQ)
    assert out["status"] == 402 and PAN not in repr(out) and "REDACTED" in repr(out)


def test_processor_stops_if_stripe_reports_livemode():
    def h(r):
        return httpx.Response(200, json={"id": "pm_1", "card": {"last4": "4242"}} if r.url.path == "/v1/payment_methods" else {"id": "pi", "status": "succeeded", "amount": 100, "livemode": True})
    assert StripeTestProcessor("sk_test_abc", transport=httpx.MockTransport(h))(REQ)["status"] == 500


def test_creates_the_payment_method_with_the_publishable_key_and_the_intent_with_the_server_key():
    calls = []
    StripeTestProcessor("rk_test_server", transport=stripe_transport(calls), publishable="pk_test_pub")(REQ)
    pm, pi = calls
    assert pm.headers["authorization"] == "Bearer pk_test_pub" and pi.headers["authorization"] == "Bearer rk_test_server"


def test_a_live_publishable_key_is_refused():
    with pytest.raises(ValueError, match="non-test publishable"):
        StripeTestProcessor("rk_test_server", transport=stripe_transport([]), publishable="pk_live_abc")
