"""Velocity caps, risk engine, freezes (host and enclave), alerts, stored cards, leak scan. Deterministic, offline."""
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from vault_harness import actions, alerts, guard, kernel_setup, leakscan, policy
from vault_harness import enclave as E
from vault_harness.browser import checkout_page
from vault_harness.cardstore import CardStore
from vault_harness.enclave_vault import EnclaveVault
from vault_harness.fake_model import ScriptedWriter
from vault_harness.graph import build, start
from vault_harness.policy import Intent

PAN = "4242424242424242"
CARD = {"number": PAN, "exp_month": 12, "exp_year": 2030, "cvc": "123"}
RAW = E._RAW
I = Intent("stripe-test-mode", 100, "usd")


def pol(**kw):
    return policy.Policy(allowed_merchants=("stripe-test-mode", "other.example"), **kw)


# ---------------- velocity ----------------
def test_per_minute_velocity_cap_denies():
    s = guard.EventStore()
    for _ in range(3):
        s.add(merchant="stripe-test-mode", amount=100, outcome="done")
    v = guard.decide(I, pol(velocity={"per_minute": 3}), 0, store=s)
    assert v.action == "deny" and "velocity" in v.reasons[0]


def test_cap_counts_only_the_window_and_only_real_attempts():
    s = guard.EventStore()
    for _ in range(5):
        s.add(merchant="stripe-test-mode", amount=100, outcome="done", ts=time.time() - 3000)       # outside the minute
        s.add(merchant="stripe-test-mode", amount=100, outcome="denied")                              # denials are not payments
    assert guard.decide(I, pol(velocity={"per_minute": 3}), 0, store=s).action != "deny"


def test_spend_velocity_cap_denies():
    s = guard.EventStore(); s.add(merchant="stripe-test-mode", amount=950, outcome="done")
    assert guard.decide(I, pol(velocity={"spend_per_day_cents": 1000}), 0, store=s).action == "deny"


# ---------------- risk ----------------
def test_new_merchant_alone_does_not_block_a_small_payment():
    assert guard.decide(I, pol(), 0).action == "auto"


def test_card_testing_burst_forces_a_human():
    s = guard.EventStore()
    for _ in range(3):
        s.add(merchant="stripe-test-mode", amount=100, outcome="done")
    v = guard.decide(I, pol(), 0, store=s)
    assert v.action == "approve" and v.reasons[0].startswith("step-up") and v.risk >= 40


def test_many_failures_plus_burst_is_denied():
    s = guard.EventStore()
    for _ in range(3):
        s.add(merchant="stripe-test-mode", amount=100, outcome="done")
    for _ in range(4):
        s.add(merchant="stripe-test-mode", amount=100, outcome="refused")
    v = guard.decide(I, pol(), 0, store=s)
    assert v.action == "deny" and v.risk >= 70


def test_amount_far_above_history_adds_risk():
    s = guard.EventStore()
    for _ in range(4):
        s.add(merchant="stripe-test-mode", amount=100, outcome="done", ts=time.time() - 4000)
    score, why = guard.risk_score(Intent("stripe-test-mode", 900, "usd"), pol(), s, time.time())
    assert score >= 25 and any("usual" in w for w in why)


# ---------------- freezes ----------------
@pytest.mark.parametrize("scope", ["all", "merchant:stripe-test-mode", "agent:vault-harness", "card:vc_1"])
def test_every_freeze_scope_denies(scope):
    guard.Freezes().freeze(scope, "test")
    assert guard.decide(I, pol(), 0, card_id="vc_1").action == "deny"


def test_lift_restores_payments_and_unrelated_scope_does_not_block():
    f = guard.Freezes(); f.freeze("merchant:evil.example"); f.freeze("all")
    assert guard.decide(I, pol(), 0).action == "deny"
    f.lift("all")
    assert guard.decide(I, pol(), 0).action == "auto"


# ---------------- alerts ----------------
def test_alerts_are_written_and_redact_card_numbers():
    alerts.emit("payment_done", "info", charge="pi_1", note=f"card {PAN} used")
    row = alerts.read("payment_done")[0]
    assert PAN not in json.dumps(row) and "REDACTED" in row["note"]


# ---------------- graph: alerts, events, freeze after approval ----------------
def run(drafts, live=True, **kw):
    g = build(MemorySaver(), ScriptedWriter(drafts=drafts)); cfg = {"configurable": {"thread_id": "g"}}
    start(g, "pay", live, cfg, **kw)
    return g, cfg


def d(cents, merchant="stripe-test-mode"):
    return json.dumps({"merchant": merchant, "amount_cents": cents, "currency": "usd"})


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setattr(policy, "BUDGET_FILE", tmp_path / "b.json")
    monkeypatch.setenv("VAULT", "mock")
    monkeypatch.setenv("VAULT_POLICY", json.dumps({"allowed_merchants": ["stripe-test-mode"], "budget_total_cents": 2000, "auto_approve_under_cents": 200, "max_single_cents": 2000}))
    actions.reset()


def test_payment_records_an_event_and_an_alert(env):
    g, cfg = run([d(100)])
    assert g.get_state(cfg).values["outcome"] == "done"
    assert alerts.read("payment_done") and guard.EventStore().count(60, time.time(), ("done",)) == 1


def test_denial_alerts_critical_when_frozen(env):
    guard.Freezes().freeze("merchant:stripe-test-mode", "incident")
    g, cfg = run([d(100)])
    assert g.get_state(cfg).values["outcome"] == "denied"
    assert alerts.read("payment_denied")[0]["severity"] == "critical"


def test_freeze_placed_after_approval_still_stops_the_payment(env):
    g, cfg = run([d(500)])                                   # $5: pauses for approval
    assert any(t.interrupts for t in g.get_state(cfg).tasks)
    guard.Freezes().freeze("all", "operator hit the brakes")  # freeze lands between approval and payment
    g.invoke(Command(resume={"decision": "approve"}), cfg)
    st = g.get_state(cfg).values
    assert st["outcome"] == "refused" and "frozen at execution time" in st["result"]["reason"] and policy.Budget().spent() == 0


def test_dry_run_records_nothing(env):
    run([d(100)], live=False)
    assert guard.EventStore().count(60, time.time(), ("done", "refused", "denied")) == 0


# ---------------- enclave: revocation, card store, ciphertext ----------------
class Stripe:
    def __init__(self): self.seen = []
    def __call__(self, req):
        self.seen.append(req)
        return {"status": 200, "json": {"id": "pi_x", "status": "succeeded", "amount": req["meta"]["amount_cents"], "last4": PAN[-4:]}}


class FakeBrowser:
    def __init__(self, total): self.total = total
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def capture_checkout(self, html, ph):
        body = f"card[number]={ph.number}&card[cvc]={ph.cvc}&card[exp_month]={ph.exp_month}&card[exp_year]={ph.exp_year}&type=card&amount={self.total}"
        return {"total_cents": self.total, "request": {"url": "https://api.stripe.com/v1/payment_methods", "method": "POST", "headers": {}, "body": body}}


@pytest.fixture
def vault(tmp_path):
    user, pk, stripe = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Stripe()
    enc = E.MockEnclave(user_pub=user.public_key().public_bytes(*RAW), policy_pub=pk.public_key().public_bytes(*RAW), processor=stripe, auto_limit_cents=200, max_single_cents=2000)
    store = CardStore(tmp_path / "cards.json")
    v = EnclaveVault(enc, user_key=user, policy_key=pk, make_browser=lambda: FakeBrowser(100), make_page=lambda i: checkout_page(i.amount_cents),
                     auto_limit_cents=200, card_store=store)
    return v, enc, store, stripe, user


def pay_once(v, enc, cents=100, merchant="stripe-test-mode"):
    i = Intent(merchant, cents, "usd")
    return v.pay(enc.issue_placeholder(i), i)


def test_enroll_stores_ciphertext_only_and_never_the_cvc(vault, tmp_path):
    v, enc, store, stripe, user = vault
    out = v.enroll(CARD)
    raw = (tmp_path / "cards.json").read_text()
    assert out["last4"] == "4242" and out["brand"] == "visa" and out["card_id"].startswith("vc_")
    assert PAN not in raw and '"cvc"' not in raw
    assert store.list_display()[0]["last4"] == "4242" and "sealed" not in store.list_display()[0]
    assert leakscan.scan([tmp_path]) == []


def test_pay_with_stored_card_swaps_it_in_and_sends_no_cvc(vault):
    v, enc, store, stripe, user = vault
    v.enroll(CARD)
    out = pay_once(v, enc)
    body = stripe.seen[0]["body"]
    assert out["status"] == "done" and f"card[number]={PAN}" in body and "card[cvc]" not in body


def test_stored_blob_cannot_be_used_for_another_card_id(vault):
    v, enc, store, stripe, user = vault
    a = v.enroll(CARD)["card_id"]
    store.add("vc_other", {"brand": "visa", "last4": "4242", "exp_month": 12, "exp_year": 2030}, store.sealed(a))     # same blob, wrong id
    v._card_id = "vc_other"
    out = pay_once(v, enc)
    assert out["status"] == "refused" and "not bound" in out["reason"] and stripe.seen == []


def test_stored_card_is_useless_to_a_different_enclave(vault):
    v, enc, store, stripe, user = vault
    cid = v.enroll(CARD)["card_id"]
    other = E.MockEnclave(user_pub=user.public_key().public_bytes(*RAW), policy_pub=Ed25519PrivateKey.generate().public_key().public_bytes(*RAW), processor=Stripe())
    with pytest.raises(E.EnclaveRefused, match="could not be opened"):
        other.enroll(store.sealed(cid), cid)


def test_enroll_rejects_an_invalid_card_number(vault):
    v, enc, store, stripe, user = vault
    with pytest.raises(E.EnclaveRefused, match="validation"):
        v.enroll({**CARD, "number": "4242424242424241"})
    assert store.list_display() == []


def test_host_freeze_reaches_the_enclave_and_lifting_it_restores_payments(vault):
    v, enc, store, stripe, user = vault
    v.enroll(CARD)
    f = guard.Freezes(); f.freeze("merchant:stripe-test-mode", "incident")
    out = pay_once(v, enc)
    assert out["status"] == "refused" and "revoked: merchant:stripe-test-mode" in out["reason"] and stripe.seen == []
    f.lift("merchant:stripe-test-mode")
    assert pay_once(v, enc)["status"] == "done"


def test_enclave_revocation_needs_the_user_signature_and_cannot_be_replayed(vault):
    v, enc, store, stripe, user = vault
    v.enroll(CARD)
    with pytest.raises(E.EnclaveRefused, match="signature invalid"):
        enc.revoke("all", "n1", Ed25519PrivateKey.generate().sign(b"revoke:all:n1").hex())      # a compromised host cannot forge a lift or a revoke
    enc.revoke("all", "n2", user.sign(b"revoke:all:n2").hex())
    with pytest.raises(E.EnclaveRefused, match="replayed"):
        enc.revoke("all", "n2", user.sign(b"revoke:all:n2").hex())
    with pytest.raises(E.EnclaveRefused, match="signature invalid"):
        enc.lift("all", "n3", Ed25519PrivateKey.generate().sign(b"lift:all:n3").hex())          # host cannot lift a freeze either
    assert pay_once(v, enc)["status"] == "refused"


def test_whole_run_leaves_no_card_number_in_any_file(vault, tmp_path, monkeypatch):
    v, enc, store, stripe, user = vault
    v.enroll(CARD)
    monkeypatch.setattr(policy, "BUDGET_FILE", tmp_path / "b.json")
    monkeypatch.setenv("VAULT_POLICY", json.dumps({"allowed_merchants": ["stripe-test-mode"]}))
    actions.use(v)
    g = build(MemorySaver(), ScriptedWriter(drafts=[d(100)]))
    start(g, f"pay $1 with card {PAN}", True, {"configurable": {"thread_id": "leak"}}, card_id=v._card_id)
    assert g.get_state({"configurable": {"thread_id": "leak"}}).values["outcome"] == "done"
    assert leakscan.scan([tmp_path], literals=[PAN]) == []
    actions.reset()


def test_scanner_actually_finds_a_planted_card_number(tmp_path):
    (tmp_path / "oops.log").write_text("charged card 4242 4242 4242 4242 ok")
    (tmp_path / "hash.txt").write_text("sha256 373787695892179a663b556e78d1fd00112233445566778899aabbccddeeff00")
    hits = leakscan.scan([tmp_path])
    assert len(hits) == 1 and hits[0][1] == "card-number" and PAN not in repr(hits)


def test_cvc_is_supplied_per_payment_bound_to_the_placeholder_and_never_stored(vault, tmp_path):
    v, enc, store, stripe, user = vault
    v._cvc = lambda: "123"
    v.enroll(CARD)
    assert pay_once(v, enc)["status"] == "done" and "card[cvc]=123" in stripe.seen[0]["body"]
    assert '"cvc"' not in (tmp_path / "cards.json").read_text() and leakscan.scan([tmp_path]) == []


def test_a_cvc_box_made_for_one_placeholder_cannot_be_used_for_another(vault):
    v, enc, store, stripe, user = vault
    cid = v.enroll(CARD)["card_id"]
    i = Intent("stripe-test-mode", 100, "usd")
    a, b = enc.issue_placeholder(i), enc.issue_placeholder(i)
    boxed_for_a = E.seal(bytes.fromhex(enc.attest()["pubkey"]), {"cvc": "123"}, aad=f"cvc:{a.token}".encode())
    approval = {"signer": "policy", "sig": v._pol.sign(E.approval_message(i, b.token)).hex()}
    cap = FakeBrowser(100).capture_checkout("", b)
    with pytest.raises(E.EnclaveRefused, match="not bound"):
        enc.pay(sealed=store.sealed(cid), placeholder=b, intent=i, request=cap["request"], approval=approval, card_id=cid, cvc_sealed=boxed_for_a)


def test_scanner_never_flags_random_ids_and_nonces(tmp_path):
    """Regression for a flake: ~1 in 700 random 'vc_'+20 hex ids contain a Luhn-valid 13-digit run. Thousands of them must scan clean."""
    import random
    rnd = random.Random(7)
    rows = [{"id": "vc_" + "".join(rnd.choice("0123456789abcdef") for _ in range(20)),
             "nonce": "".join(rnd.choice("0123456789abcdef") for _ in range(24)),
             "ph": "ph_" + "".join(rnd.choice("0123456789abcdef") for _ in range(20))} for _ in range(6000)]
    (tmp_path / "ids.json").write_text(json.dumps(rows))
    assert leakscan.scan([tmp_path]) == []


def test_a_refusal_before_any_card_was_sent_is_aborted_not_a_failed_payment(env, monkeypatch):
    monkeypatch.setattr(actions, "perform", lambda i, dry_run=True: {"status": "refused", "card_sent": False, "reason": "link prompt"})
    for _ in range(3):
        run([d(100)])
    s = guard.EventStore()
    assert s.count(600, time.time(), ("refused", "denied")) == 0 and s.count(600, time.time(), ("aborted",)) == 3
    assert guard.decide(Intent("stripe-test-mode", 100, "usd"), pol(), 0, store=s).action == "auto"          # no false step-up


def test_a_refusal_after_the_card_was_sent_still_counts(env, monkeypatch):
    monkeypatch.setattr(actions, "perform", lambda i, dry_run=True: {"status": "refused", "card_sent": True, "reason": "declined"})
    run([d(100)])
    assert guard.EventStore().count(600, time.time(), ("refused",)) == 1
