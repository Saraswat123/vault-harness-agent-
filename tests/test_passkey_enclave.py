"""Passkey (Touch ID) approvals verified INSIDE the enclave. Software authenticator; the host cannot forge, replay, redirect or lift."""
import json
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.webauthn_soft import SoftAuthenticator
from vault_harness import enclave as E
from vault_harness import guard
from vault_harness.cardstore import CardStore
from vault_harness.enclave_rpc import EnclaveClient, EnclaveServer, listen_tcp
from vault_harness.enclave_vault import EnclaveVault
from vault_harness.policy import Intent

PAN = "4242424242424242"
RAW = E._RAW
I = Intent("buy.stripe.com", 100, "usd")
BIG = Intent("buy.stripe.com", 500, "usd")


class Proc:
    def __init__(self): self.seen = []
    def __call__(self, req):
        self.seen.append(req)
        return {"status": 200, "json": {"id": "pi_pk", "status": "succeeded", "amount": req["meta"]["amount_cents"], "last4": "4242"}}


def hexed(a):
    return {"authenticator_data": a["authenticator_data"].hex(), "client_data_json": a["client_data_json"].hex(), "signature": a["signature"].hex()}


@pytest.fixture
def rig():
    user, pol, proc, auth = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Proc(), SoftAuthenticator()
    enc = E.MockEnclave(user_pub=user.public_key().public_bytes(*RAW), policy_pub=pol.public_key().public_bytes(*RAW), processor=proc, auto_limit_cents=200,
                        max_single_cents=2000, allowed_paths=("/v1/payment_methods",))
    enc.register_passkey(*auth.xy)
    return enc, user, pol, proc, auth


def req(ph):
    return {"url": "https://api.stripe.com/v1/payment_methods", "method": "POST", "headers": {}, "body": f"card[number]={ph.number}&card[cvc]={ph.cvc}&card[exp_month]=12&card[exp_year]=30&type=card"}


def pay(enc, intent, approval):
    ph = enc.issue_placeholder(intent)
    sealed = E.seal(bytes.fromhex(enc.attest()["pubkey"]), {"number": PAN, "exp_month": 12, "exp_year": 2030, "cvc": "123"})
    return enc.pay(sealed=sealed, placeholder=ph, intent=intent, request=req(ph), approval=approval)


def user_approval(auth, intent, nonce):
    return {"signer": "user", "nonce": nonce, "webauthn": hexed(auth.assert_(E.approval_challenge(intent, nonce)))}


def test_a_touch_id_approval_for_this_payment_is_accepted(rig):
    enc, user, pol, proc, auth = rig
    assert pay(enc, BIG, user_approval(auth, BIG, "n1"))["status"] == "done" and len(proc.seen) == 1


def test_once_a_passkey_is_registered_the_software_user_key_no_longer_approves(rig):
    enc, user, pol, proc, auth = rig
    ph = enc.issue_placeholder(BIG)
    with pytest.raises(E.EnclaveRefused, match="passkey approval"):
        enc.pay(sealed={}, placeholder=ph, intent=BIG, request=req(ph), approval={"signer": "user", "sig": user.sign(E.approval_message(BIG, ph.token)).hex()})
    assert proc.seen == []


def test_an_approval_for_a_different_amount_is_refused(rig):
    enc, user, pol, proc, auth = rig
    with pytest.raises(E.EnclaveRefused, match="challenge"):
        pay(enc, BIG, user_approval(auth, I, "n2"))                                         # Touch ID was given for $1.00, offered for $5.00
    assert proc.seen == []


def test_an_approval_cannot_be_replayed(rig):
    enc, user, pol, proc, auth = rig
    ap = user_approval(auth, BIG, "n3")
    assert pay(enc, BIG, ap)["status"] == "done"
    with pytest.raises(E.EnclaveRefused, match="already used|counter"):
        pay(enc, BIG, ap)
    assert len(proc.seen) == 1


def test_another_devices_approval_is_refused(rig):
    enc, user, pol, proc, auth = rig
    with pytest.raises(E.EnclaveRefused, match="signature"):
        pay(enc, BIG, user_approval(SoftAuthenticator(), BIG, "n4"))
    assert proc.seen == []


def test_an_approval_without_the_biometric_flag_is_refused(rig):
    enc, user, pol, proc, auth = rig
    from vault_harness.webauthn import UP
    bad = {"signer": "user", "nonce": "n5", "webauthn": hexed(auth.assert_(E.approval_challenge(BIG, "n5"), flags=UP))}
    with pytest.raises(E.EnclaveRefused, match="verification"):
        pay(enc, BIG, bad)


def test_the_policy_signer_still_covers_small_auto_payments_but_not_big_ones(rig):
    enc, user, pol, proc, auth = rig
    ph = enc.issue_placeholder(I)
    sealed = E.seal(bytes.fromhex(enc.attest()["pubkey"]), {"number": PAN, "exp_month": 12, "exp_year": 2030, "cvc": "123"})
    ok = enc.pay(sealed=sealed, placeholder=ph, intent=I, request=req(ph), approval={"signer": "policy", "sig": pol.sign(E.approval_message(I, ph.token)).hex()})
    assert ok["status"] == "done"
    ph2 = enc.issue_placeholder(BIG)
    with pytest.raises(E.EnclaveRefused, match="USER must sign"):
        enc.pay(sealed=sealed, placeholder=ph2, intent=BIG, request=req(ph2), approval={"signer": "policy", "sig": pol.sign(E.approval_message(BIG, ph2.token)).hex()})


def test_only_one_passkey_can_ever_be_registered(rig):
    enc, user, pol, proc, auth = rig
    with pytest.raises(E.EnclaveRefused, match="already registered"):
        enc.register_passkey(*SoftAuthenticator().xy)


def test_the_host_cannot_lift_a_freeze_but_the_owners_touch_id_can(rig):
    enc, user, pol, proc, auth = rig
    enc.revoke("all", "r1", user.sign(b"revoke:all:r1").hex())                          # freezing stays easy (safe direction)
    with pytest.raises(E.EnclaveRefused, match="passkey approval"):
        enc.lift("all", "l1", user.sign(b"lift:all:l1").hex())                           # the software key can no longer lift
    ap = auth.assert_(E.lift_challenge("all", "l2"))
    enc.lift("all", "l2", "", hexed(ap))
    assert pay(enc, BIG, user_approval(auth, BIG, "n6"))["status"] == "done"             # lifted: payments work again


def test_a_lift_assertion_for_another_scope_is_refused(rig):
    enc, user, pol, proc, auth = rig
    enc.revoke("all", "r2", user.sign(b"revoke:all:r2").hex())
    with pytest.raises(E.EnclaveRefused, match="challenge"):
        enc.lift("all", "l3", "", hexed(auth.assert_(E.lift_challenge("merchant:x", "l3"))))


# ---- over the socket, and through the vault adapter ----
def test_passkey_registration_and_approval_work_across_the_socket():
    user, pol, proc, auth = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Proc(), SoftAuthenticator()
    enc = E.MockEnclave(user_pub=user.public_key().public_bytes(*RAW), policy_pub=pol.public_key().public_bytes(*RAW), processor=proc, auto_limit_cents=200, max_single_cents=2000,
                        allowed_paths=("/v1/payment_methods",))
    lst = listen_tcp("127.0.0.1", 0)
    threading.Thread(target=EnclaveServer(enc).serve_forever, args=(lst,), daemon=True).start()
    c = EnclaveClient(f"tcp://127.0.0.1:{lst.getsockname()[1]}", timeout=10)
    c.register_passkey(*auth.xy)
    ph = c.issue_placeholder(BIG)
    sealed = E.seal(bytes.fromhex(c.attest()["pubkey"]), {"number": PAN, "exp_month": 12, "exp_year": 2030, "cvc": "123"})
    assert c.pay(sealed=sealed, placeholder=ph, intent=BIG, request=req(ph), approval=user_approval(auth, BIG, "s1"))["status"] == "done"
    with pytest.raises(E.EnclaveRefused, match="already registered"):
        c.register_passkey(*SoftAuthenticator().xy)
    lst.close()


class Browser:
    def __init__(self, total): self.total = total
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def capture_checkout(self, html, ph):
        return {"total_cents": self.total, "request": req(ph)}


def test_vault_uses_the_owners_assertion_once_and_stays_frozen_if_the_lift_is_refused(rig, tmp_path, monkeypatch):
    enc, user, pol, proc, auth = rig
    monkeypatch.setenv("VAULT_FREEZE_FILE", str(tmp_path / "f.json"))
    v = EnclaveVault(enc, user_key=user, policy_key=pol, make_browser=lambda: Browser(500), make_page=lambda i: "", auto_limit_cents=200,
                     card_store=CardStore(tmp_path / "c.json"), cvc_source=lambda: "123")
    v.enroll({"number": PAN, "exp_month": 12, "exp_year": 2030})
    v.user_approval = {"nonce": "v1", "webauthn": hexed(auth.assert_(E.approval_challenge(BIG, "v1")))}
    assert v.pay(enc.issue_placeholder(BIG), BIG)["status"] == "done" and v.user_approval is None          # consumed by exactly one payment
    guard.Freezes().freeze("all", "t")
    assert v.pay(enc.issue_placeholder(BIG), BIG)["status"] == "refused"                                    # frozen (the revoke reached the enclave)
    guard.Freezes().lift("all")                                                                              # the HOST removes it from its file...
    out = v.pay(enc.issue_placeholder(BIG), BIG)
    assert out["status"] == "refused" and "revoked" in out["reason"]                                        # ...but without Touch ID the enclave stays frozen
    guard.Freezes().freeze("all", "again"); guard.Freezes().lift("all")
    v.lift_assertions["all"] = {"nonce": "v2", "webauthn": hexed(auth.assert_(E.lift_challenge("all", "v2")))}
    v.user_approval = {"nonce": "v3", "webauthn": hexed(auth.assert_(E.approval_challenge(BIG, "v3")))}
    assert v.pay(enc.issue_placeholder(BIG), BIG)["status"] == "done"                                       # the owner's Touch ID lifted it
