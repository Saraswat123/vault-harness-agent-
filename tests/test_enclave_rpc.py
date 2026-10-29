"""The enclave as a separate server. Same behaviour as in-process, across a real socket; the channel never carries a card number."""
import json
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vault_harness import enclave as E
from vault_harness.cardstore import CardStore
from vault_harness.enclave_rpc import EnclaveClient, EnclaveServer, listen_tcp
from vault_harness.enclave_vault import EnclaveVault
from vault_harness.policy import Intent

PAN = "4242424242424242"
RAW = E._RAW
I = Intent("stripe-test-mode", 100, "usd")


class Stripe:
    def __init__(self): self.seen = []
    def __call__(self, req):
        self.seen.append(req)
        return {"status": 200, "json": {"id": "pi_rpc", "status": "succeeded", "amount": req["meta"]["amount_cents"], "last4": PAN[-4:]}}


class Tap:
    """Records every byte the server and client exchange: the 'untrusted channel' as a test can see it."""
    def __init__(self, client_call): self.log = []; self._c = client_call


@pytest.fixture
def rig():
    user, pk, stripe = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Stripe()
    enc = E.MockEnclave(user_pub=user.public_key().public_bytes(*RAW), policy_pub=pk.public_key().public_bytes(*RAW), processor=stripe, auto_limit_cents=200)
    srv = EnclaveServer(enc)
    lst = listen_tcp("127.0.0.1", 0)
    wire = []
    orig = srv.handle
    def spy(req):
        wire.append(json.dumps(req)); out = orig(req); wire.append(json.dumps(out)); return out
    srv.handle = spy
    threading.Thread(target=srv.serve_forever, args=(lst,), daemon=True).start()
    client = EnclaveClient(f"tcp://127.0.0.1:{lst.getsockname()[1]}", timeout=10)
    yield client, user, pk, stripe, wire
    lst.close()


class Browser:
    def __init__(self, total): self.total = total
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def capture_checkout(self, html, ph):
        body = f"card[number]={ph.number}&card[cvc]={ph.cvc}&card[exp_month]={ph.exp_month}&card[exp_year]={ph.exp_year}&type=card&amount={self.total}"
        return {"total_cents": self.total, "request": {"url": "https://api.stripe.com/v1/payment_methods", "method": "POST", "headers": {}, "body": body}}


def vault(client, user, pk, tmp_path):
    return EnclaveVault(client, user_key=user, policy_key=pk, make_browser=lambda: Browser(100), make_page=lambda i: "", auto_limit_cents=200,
                        card_store=CardStore(tmp_path / "c.json"), cvc_source=lambda: "123")


def test_full_payment_across_the_socket_and_no_card_number_on_the_wire(rig, tmp_path):
    client, user, pk, stripe, wire = rig
    v = vault(client, user, pk, tmp_path)
    info = v.enroll({"number": PAN, "exp_month": 12, "exp_year": 2030})
    out = v.pay(client.issue_placeholder(I), I)
    assert info["last4"] == "4242" and out["status"] == "done" and out["charge_id"] == "pi_rpc"
    assert f"card[number]={PAN}" in stripe.seen[0]["body"]                          # the processor (inside the enclave) got the real card
    assert PAN not in "".join(wire)                                                  # the channel never carried it, either direction


def test_refusals_cross_the_socket_as_enclave_refusals(rig):
    client, user, pk, stripe, wire = rig
    ph = client.issue_placeholder(I)
    with pytest.raises(E.EnclaveRefused, match="signature invalid"):
        client.pay(sealed=E.seal(bytes.fromhex(client.attest()["pubkey"]), {"number": PAN, "exp_month": 12, "exp_year": 2030}), placeholder=ph, intent=I,
                   request={"url": "https://api.stripe.com/v1/payment_methods", "method": "POST", "headers": {}, "body": f"card[number]={ph.number}"},
                   approval={"signer": "policy", "sig": Ed25519PrivateKey.generate().sign(b"x").hex()})
    assert stripe.seen == []


def test_revocation_over_the_socket_needs_the_user_signature(rig):
    client, user, pk, stripe, wire = rig
    with pytest.raises(E.EnclaveRefused, match="signature invalid"):
        client.revoke("all", "n1", Ed25519PrivateKey.generate().sign(b"revoke:all:n1").hex())
    client.revoke("all", "n2", user.sign(b"revoke:all:n2").hex())
    with pytest.raises(E.EnclaveRefused, match="revoked"):
        pay = client.issue_placeholder(I)
        client.pay(sealed={"epk": "00", "nonce": "00", "ct": "00", "aad": ""}, placeholder=pay, intent=I,
                   request={"url": "https://api.stripe.com/v1/payment_methods", "method": "POST", "headers": {}, "body": ""}, approval={"signer": "policy", "sig": "00"})


def test_unknown_op_and_garbage_do_not_leak_internals(rig):
    client, user, pk, stripe, wire = rig
    with pytest.raises(RuntimeError, match="unknown_op"):
        client._call("nonsense")
    with pytest.raises(RuntimeError, match="enclave error: internal"):
        client._call("enroll", sealed="not a dict", card_id=3)                       # server errors never echo request contents


def test_attestation_nonce_reaches_the_server_and_a_failing_verifier_makes_attest_fail_closed():
    import socket
    seen = {}
    user, pk = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    enc = E.MockEnclave(user_pub=user.public_key().public_bytes(*RAW), policy_pub=pk.public_key().public_bytes(*RAW), processor=Stripe())
    srv = EnclaveServer(enc, attestation=lambda pub, nonce: (seen.update(pub=pub, nonce=nonce) or "ab" * 8))
    lst = listen_tcp("127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, args=(lst,), daemon=True).start()
    url = f"tcp://127.0.0.1:{lst.getsockname()[1]}"
    calls = []
    out = EnclaveClient(url, verify_attestation=lambda o, n: calls.append((o["attestation_doc"], n))).attest()
    assert seen["nonce"] == calls[0][1] and len(seen["nonce"]) == 32 and seen["pub"].hex() == out["pubkey"]     # the verifier checks the nonce WE chose
    def reject(o, n):
        raise RuntimeError("attestation did not verify")
    with pytest.raises(RuntimeError, match="did not verify"):
        EnclaveClient(url, verify_attestation=reject).attest()                                                  # no key is handed out unless it verifies
    lst.close()
