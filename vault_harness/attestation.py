"""Verify an AWS Nitro attestation document (COSE_Sign1 over a CBOR payload). Runs on the HARNESS side, not in the enclave.

What a pass proves: the document was signed by a certificate chaining to the AWS Nitro root you supply; it is fresh (your nonce, recent
timestamp); the enclave's PCR0 (hash of the exact image, config included) equals the value from YOUR build; and the public key in the signed
document is the one the enclave offers. Only then should anything be sealed to that key.
Tested here against a synthetic CA. Not yet exercised against a real AWS document: use the AWS root certificate (download it from AWS and check its
fingerprint against AWS's documentation) as `root_pem`."""
import time
from typing import Optional

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


class AttestationError(Exception):
    pass


def _verify_cert_sig(child: x509.Certificate, issuer: x509.Certificate):
    try:
        issuer.public_key().verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
    except (InvalidSignature, ValueError, TypeError):
        raise AttestationError("certificate chain: signature check failed")


def verify(doc: bytes, *, root_pem: bytes, expected_pcrs: dict, expected_pubkey: bytes = None, nonce: bytes = None,
           now: Optional[float] = None, max_age_s: int = 300) -> dict:
    now = time.time() if now is None else now
    try:
        obj = cbor2.loads(doc)
        if isinstance(obj, cbor2.CBORTag):
            obj = obj.value
        protected, _unprot, payload, sig = obj
        body = cbor2.loads(payload)
    except Exception:
        raise AttestationError("not a COSE_Sign1 attestation document")
    try:
        leaf = x509.load_der_x509_certificate(body["certificate"])
        bundle = [x509.load_der_x509_certificate(c) for c in body["cabundle"]]
    except Exception:
        raise AttestationError("bad certificates in the document")
    root = x509.load_pem_x509_certificate(root_pem)
    # chain: leaf <- intermediates <- the root YOU trust (the document's own bundle root must equal it)
    inter = [c for c in bundle if c.fingerprint(hashes.SHA256()) != root.fingerprint(hashes.SHA256())]
    chain = [leaf] + list(reversed(inter)) + [root]
    for child, issuer in zip(chain, chain[1:]):
        if child.issuer != issuer.subject:
            raise AttestationError("certificate chain does not lead to the trusted root")
        _verify_cert_sig(child, issuer)
    for c in chain:
        t = time.gmtime(now)
        nb, na = c.not_valid_before_utc.timestamp(), c.not_valid_after_utc.timestamp()
        if not nb <= now <= na:
            raise AttestationError("a certificate in the chain is expired or not yet valid")
    # COSE signature (ES384): the signature is raw r||s
    if len(sig) != 96:
        raise AttestationError("unexpected signature length")
    r, s = int.from_bytes(sig[:48], "big"), int.from_bytes(sig[48:], "big")
    to_sign = cbor2.dumps(["Signature1", protected, b"", payload])
    try:
        leaf.public_key().verify(encode_dss_signature(r, s), to_sign, ec.ECDSA(hashes.SHA384()))
    except InvalidSignature:
        raise AttestationError("document signature is invalid")
    # contents
    pcrs = body.get("pcrs", {})
    for idx, want in expected_pcrs.items():
        if pcrs.get(int(idx)) != want:
            raise AttestationError(f"PCR{idx} does not match the expected image measurement")
    if any(v == b"\x00" * len(v) for k, v in pcrs.items() if k in (0, 1, 2)):
        raise AttestationError("PCRs are all zero: the enclave is running in debug mode and attests nothing")
    if expected_pubkey is not None and body.get("public_key") != expected_pubkey:
        raise AttestationError("the signed public key is not the key the enclave offered")
    if nonce is not None and body.get("nonce") != nonce:
        raise AttestationError("nonce mismatch: stale or replayed document")
    ts = body.get("timestamp", 0) / 1000.0
    if abs(now - ts) > max_age_s:
        raise AttestationError("document is not fresh")
    return {"module_id": body.get("module_id"), "pcrs": {k: v.hex() for k, v in pcrs.items() if k in (0, 1, 2)}, "public_key": body.get("public_key", b"").hex()}
