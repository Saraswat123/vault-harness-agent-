"""Mock enclave: the card is sealed by the user, swapped in only inside, never returned, never kept."""
import gc
import re

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vault_harness import enclave as E
from vault_harness.policy import Intent

PAN = "4242424242424242"                     # Stripe public test card
CARD = {"number": PAN, "exp_month": 12, "exp_year": 2030, "cvc": "123"}
I = Intent("buy.stripe.com", 100, "usd")
RAW = E._RAW


class FakeStripe:
    """Records exactly what the processor receives, so we can prove the swap happened and the placeholder did not reach it."""
    def __init__(self, status="succeeded"):
        self.seen, self.status = [], status

    def __call__(self, req):
        self.seen.append(req)
        return {"status": 200, "json": {"id": "ch_test_1", "status": self.status, "amount": 100, "last4": PAN[-4:]}}


@pytest.fixture
def world():
    user, pol = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    stripe = FakeStripe()
    enc = E.MockEnclave(user_pub=user.public_key().public_bytes(*RAW), policy_pub=pol.public_key().public_bytes(*RAW), processor=stripe)
    return enc, user, pol, stripe


def req(ph, amount=100, url="https://api.stripe.com/v1/tokens"):
    body = f"card[number]={ph.number}&card[cvc]={ph.cvc}&card[exp_month]={ph.exp_month}&card[exp_year]={ph.exp_year}&amount={amount}"
    return {"url": url, "method": "POST", "headers": {}, "body": body}


def go(world, intent=I, signer="policy", amount=100, url="https://api.stripe.com/v1/tokens", sealed=None, key=None):
    enc, user, pol, stripe = world
    ph = enc.issue_placeholder(intent)
    sk = key or (pol if signer == "policy" else user)
    approval = {"signer": signer, "sig": sk.sign(E.approval_message(intent, ph.token)).hex()}
    sealed = sealed or E.seal(bytes.fromhex(enc.attest()["pubkey"]), CARD)
    return enc, ph, enc.pay(sealed=sealed, placeholder=ph, intent=intent, request=req(ph, amount, url), approval=approval)


def test_happy_path_swaps_the_real_card_in_and_returns_only_masked_data(world):
    enc, ph, out = go(world)
    seen = world[3].seen[0]["body"]
    assert out["status"] == "done" and out["card_last4"] == "4242" and out["charge_id"] == "ch_test_1"
    assert f"card[number]={PAN}" in seen and ph.number not in seen             # processor got the REAL card, not the placeholder
    assert PAN not in repr(out) and "cvc" not in repr(out)


def test_placeholder_is_luhn_valid_and_distinct_from_the_card():
    u, p = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    enc = E.MockEnclave(user_pub=u.public_key().public_bytes(*RAW), policy_pub=p.public_key().public_bytes(*RAW), processor=FakeStripe())
    ph = enc.issue_placeholder(I)
    assert len(ph.number) == 16 and E._luhn(ph.number[:-1]) == ph.number and ph.number != PAN


def test_host_only_ever_holds_ciphertext(world):
    enc = world[0]
    sealed = E.seal(bytes.fromhex(enc.attest()["pubkey"]), CARD)
    assert PAN not in repr(sealed) and "cvc" not in repr(sealed) and set(sealed) == {"epk", "nonce", "ct", "aad"}


def test_enclave_keeps_nothing_after_the_payment(world):
    enc, ph, out = go(world)
    gc.collect()
    blob = repr(vars(enc)) + repr(enc._ph)
    assert PAN not in blob and "cvc" not in blob.replace(f"cvc='{ph.cvc}'", "")      # no card material left on the object


def test_placeholder_is_single_use(world):
    enc, user, pol, stripe = world
    enc, ph, _ = go(world)
    approval = {"signer": "policy", "sig": pol.sign(E.approval_message(I, ph.token)).hex()}
    with pytest.raises(E.EnclaveRefused, match="already used"):
        enc.pay(sealed=E.seal(bytes.fromhex(enc.attest()["pubkey"]), CARD), placeholder=ph, intent=I, request=req(ph), approval=approval)
    assert len(stripe.seen) == 1


def test_amount_at_or_above_auto_limit_needs_the_USER_signature(world):
    big = Intent("buy.stripe.com", 500, "usd")
    with pytest.raises(E.EnclaveRefused, match="USER must sign"):
        go(world, intent=big, signer="policy", amount=500)
    assert world[3].seen == []
    assert go(world, intent=big, signer="user", amount=500)[2]["status"] == "done"


def test_forged_or_wrong_key_signature_refused(world):
    with pytest.raises(E.EnclaveRefused, match="signature invalid"):
        go(world, key=Ed25519PrivateKey.generate())
    assert world[3].seen == []


def test_enclave_cap_holds_even_if_the_host_lied_about_policy(world):
    with pytest.raises(E.EnclaveRefused, match="cap"):
        go(world, intent=Intent("buy.stripe.com", 2001, "usd"), signer="user", amount=2001)


def test_card_cannot_be_sent_to_an_attacker_host(world):
    with pytest.raises(E.EnclaveRefused, match="not allowed"):
        go(world, url="https://evil.example/v1/tokens")
    assert world[3].seen == []


def test_http_downgrade_refused(world):
    with pytest.raises(E.EnclaveRefused, match="not allowed"):
        go(world, url="http://api.stripe.com/v1/tokens")


def test_request_amount_must_equal_the_approved_amount(world):
    with pytest.raises(E.EnclaveRefused, match="request amount 9999"):
        go(world, amount=9999)                           # injected page tries to charge more than approved
    assert world[3].seen == []


def test_request_without_the_placeholder_refused(world):
    enc, user, pol, stripe = world
    ph = enc.issue_placeholder(I)
    r = {"url": "https://api.stripe.com/v1/tokens", "method": "POST", "headers": {}, "body": "card[number]=4000000000000002&amount=100"}
    with pytest.raises(E.EnclaveRefused, match="does not carry"):
        enc.pay(sealed=E.seal(bytes.fromhex(enc.attest()["pubkey"]), CARD), placeholder=ph, intent=I, request=r,
                approval={"signer": "policy", "sig": pol.sign(E.approval_message(I, ph.token)).hex()})


def test_placeholder_bound_to_the_exact_payment(world):
    enc, user, pol, stripe = world
    ph = enc.issue_placeholder(I)
    other = Intent("buy.stripe.com", 101, "usd")
    with pytest.raises(E.EnclaveRefused, match="not bound"):
        enc.pay(sealed=E.seal(bytes.fromhex(enc.attest()["pubkey"]), CARD), placeholder=ph, intent=other, request=req(ph, 101),
                approval={"signer": "policy", "sig": pol.sign(E.approval_message(other, ph.token)).hex()})


def test_tampered_ciphertext_cannot_be_opened(world):
    enc = world[0]
    s = E.seal(bytes.fromhex(enc.attest()["pubkey"]), CARD)
    s["ct"] = s["ct"][:-2] + ("00" if s["ct"][-2:] != "00" else "11")
    with pytest.raises(E.EnclaveRefused, match="could not be opened"):
        go(world, sealed=s)


def test_card_sealed_to_a_different_enclave_cannot_be_opened(world):
    other = E.MockEnclave(user_pub=world[1].public_key().public_bytes(*RAW), policy_pub=world[2].public_key().public_bytes(*RAW), processor=FakeStripe())
    with pytest.raises(E.EnclaveRefused, match="could not be opened"):
        go(world, sealed=E.seal(bytes.fromhex(other.attest()["pubkey"]), CARD))


def test_processor_decline_is_reported_without_card_data():
    u, p = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    enc = E.MockEnclave(user_pub=u.public_key().public_bytes(*RAW), policy_pub=p.public_key().public_bytes(*RAW), processor=FakeStripe(status="failed"))
    _, _, out = go((enc, u, p, None))
    assert out["status"] == "refused" and PAN not in repr(out)


def test_a_browser_sealed_cvc_box_is_single_use_by_nonce(world):
    enc, user, pol, stripe = world
    pub = bytes.fromhex(enc.attest()["pubkey"])
    card = E.seal(pub, {"number": PAN, "exp_month": 12, "exp_year": 2030}, aad=b"vc_1")
    cvc = E.seal(pub, {"cvc": "123"}, aad=b"cvc-nonce:abc")
    def go():
        ph = enc.issue_placeholder(I)
        return enc.pay(sealed=card, placeholder=ph, intent=I, request=req(ph), approval={"signer": "policy", "sig": pol.sign(E.approval_message(I, ph.token)).hex()},
                       card_id="vc_1", cvc_sealed=cvc, cvc_aad="cvc-nonce:abc")
    assert go()["status"] == "done" and "card[cvc]=123" in stripe.seen[0]["body"]
    with pytest.raises(E.EnclaveRefused, match="already used"):
        go()                                                                                              # the same CVC box cannot pay twice
