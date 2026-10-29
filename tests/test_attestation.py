"""Attestation verification against a SYNTHETIC document signed by a self-made CA. Proves the logic and every tamper case; a real AWS document is untested."""
import datetime as dt
import time

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from vault_harness.attestation import AttestationError, verify

PUB = bytes(range(32))
PCR0, PCR1, PCR2 = b"\x11" * 48, b"\x22" * 48, b"\x33" * 48


def cert(subject, issuer, key, issuer_key, ca, days=(-1, 30)):
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now + dt.timedelta(days=days[0])).not_valid_after(now + dt.timedelta(days=days[1])))
    return b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True).sign(issuer_key, hashes.SHA384())


def make_doc(root_key=None, leaf_days=(-1, 30), pcrs=None, pub=PUB, nonce=b"n" * 32, ts=None, tamper=False):
    root_key = root_key or ec.generate_private_key(ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    root = cert("test-root", "test-root", root_key, root_key, True)
    leaf = cert("test-enclave", "test-root", leaf_key, root_key, False, leaf_days)
    payload = cbor2.dumps({"module_id": "i-test-enc0", "digest": "SHA384", "timestamp": int((ts or time.time()) * 1000),
                           "pcrs": pcrs or {0: PCR0, 1: PCR1, 2: PCR2}, "certificate": leaf.public_bytes(serialization.Encoding.DER),
                           "cabundle": [root.public_bytes(serialization.Encoding.DER)], "public_key": pub, "user_data": None, "nonce": nonce})
    protected = cbor2.dumps({1: -35})
    der = leaf_key.sign(cbor2.dumps(["Signature1", protected, b"", payload]), ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(der)
    doc = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, r.to_bytes(48, "big") + s.to_bytes(48, "big")]))
    if tamper:
        doc = doc[:-100] + bytes([doc[-100] ^ 1]) + doc[-99:]
    return doc, root.public_bytes(serialization.Encoding.PEM)


GOOD = {0: PCR0}


def ok(doc, root, **kw):
    return verify(doc, root_pem=root, expected_pcrs=kw.pop("expected_pcrs", GOOD), expected_pubkey=kw.pop("expected_pubkey", PUB), nonce=kw.pop("nonce", b"n" * 32), **kw)


def test_a_genuine_document_verifies_and_reports_the_measurements():
    doc, root = make_doc()
    out = ok(doc, root, expected_pcrs={0: PCR0, 1: PCR1, 2: PCR2})
    assert out["pcrs"][0] == PCR0.hex() and out["public_key"] == PUB.hex() and out["module_id"] == "i-test-enc0"


def test_wrong_image_measurement_is_rejected():
    doc, root = make_doc()
    with pytest.raises(AttestationError, match="PCR0"):
        ok(doc, root, expected_pcrs={0: b"\x99" * 48})


def test_a_tampered_document_is_rejected():
    doc, root = make_doc(tamper=True)
    with pytest.raises(AttestationError):
        ok(doc, root)


def test_a_document_from_an_untrusted_ca_is_rejected():
    doc, _ = make_doc()
    _, other_root = make_doc()
    with pytest.raises(AttestationError, match="chain"):
        ok(doc, other_root)


def test_an_expired_certificate_is_rejected():
    doc, root = make_doc(leaf_days=(-60, -30))
    with pytest.raises(AttestationError, match="expired"):
        ok(doc, root)


def test_the_signed_public_key_must_be_the_one_offered():
    doc, root = make_doc(pub=b"\xff" * 32)
    with pytest.raises(AttestationError, match="public key"):
        ok(doc, root)


def test_a_replayed_document_fails_the_nonce_and_freshness_checks():
    doc, root = make_doc(nonce=b"old" * 10)
    with pytest.raises(AttestationError, match="nonce"):
        ok(doc, root)
    doc, root = make_doc(ts=time.time() - 3600)
    with pytest.raises(AttestationError, match="fresh"):
        ok(doc, root)


def test_debug_mode_zero_pcrs_are_rejected_even_if_they_match():
    zeros = {0: b"\x00" * 48, 1: b"\x00" * 48, 2: b"\x00" * 48}
    doc, root = make_doc(pcrs=zeros)
    with pytest.raises(AttestationError, match="debug"):
        ok(doc, root, expected_pcrs={0: b"\x00" * 48})


def test_garbage_is_not_an_attestation_document():
    with pytest.raises(AttestationError):
        verify(b"not cbor", root_pem=make_doc()[1], expected_pcrs=GOOD)
