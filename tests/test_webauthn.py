import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from tests.webauthn_soft import SoftAuthenticator
from vault_harness.webauthn import AT, UP, UV, WebAuthnError, parse_registration, verify_assertion

ORIGIN, RP = "http://localhost:8765", "localhost"
CH = hashlib.sha256(b"approve:payment-1").digest()


def reg(a, ch=b"c" * 32, **kw):
    obj, cd = a.register(ch, **kw)
    return parse_registration(obj, cd, ch, ORIGIN, RP)


def check(a, assertion, challenge=CH, last=0, origin=ORIGIN, rp=RP):
    x, y = a.xy
    return verify_assertion(x, y, assertion["authenticator_data"], assertion["client_data_json"], assertion["signature"], challenge, origin, rp, last)


def test_registration_extracts_the_credential_and_public_key():
    a = SoftAuthenticator(); r = reg(a)
    assert r["credential_id"] == a.cred_id and (r["x"], r["y"]) == a.xy


@pytest.mark.parametrize("kw,msg", [({"flags": UP | AT}, "verification"), ({"flags": UV | AT}, "presence"), ({"flags": UP | UV}, "attested"),
                                    ({"origin": "http://evil.example"}, "origin"), ({"rp_id": "evil.example"}, "relying party")])
def test_registration_rejects_bad_ceremonies(kw, msg):
    with pytest.raises(WebAuthnError, match=msg):
        reg(SoftAuthenticator(), **kw)


def test_registration_challenge_must_match():
    a = SoftAuthenticator(); obj, cd = a.register(b"c" * 32)
    with pytest.raises(WebAuthnError, match="challenge"):
        parse_registration(obj, cd, b"d" * 32, ORIGIN, RP)


def test_a_genuine_assertion_verifies_and_returns_the_counter():
    a = SoftAuthenticator(); assert check(a, a.assert_(CH)) == 1


@pytest.mark.parametrize("kw,msg", [({"flags": UP}, "verification"), ({"flags": UV}, "presence"), ({"origin": "http://evil.example"}, "origin"),
                                    ({"rp_id": "evil.example"}, "relying party"), ({"ctype": "webauthn.create"}, "ceremony")])
def test_assertions_without_touch_id_or_for_another_site_are_rejected(kw, msg):
    a = SoftAuthenticator()
    with pytest.raises(WebAuthnError, match=msg):
        check(a, a.assert_(CH, **kw))


def test_an_assertion_for_a_different_action_is_rejected():
    a = SoftAuthenticator()
    with pytest.raises(WebAuthnError, match="challenge"):
        check(a, a.assert_(hashlib.sha256(b"approve:payment-2").digest()))               # signed for payment 2, offered for payment 1


def test_another_devices_signature_is_rejected():
    a, other = SoftAuthenticator(), SoftAuthenticator()
    with pytest.raises(WebAuthnError, match="signature"):
        check(a, a.assert_(CH, key=other.key))


def test_a_tampered_signature_is_rejected():
    a = SoftAuthenticator(); s = a.assert_(CH); s["signature"] = s["signature"][:-1] + bytes([s["signature"][-1] ^ 1])
    with pytest.raises(WebAuthnError):
        check(a, s)


def test_counter_rollback_is_rejected_as_a_clone_or_replay():
    a = SoftAuthenticator(); first = a.assert_(CH)
    assert check(a, first) == 1
    with pytest.raises(WebAuthnError, match="counter"):
        check(a, first, last=1)
