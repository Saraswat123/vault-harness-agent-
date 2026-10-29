"""WebAuthn (passkey / Touch ID / Face ID) verification: registration and assertion, ES256 only. Runs on the harness AND inside the enclave.
What a valid assertion proves: a person unlocked the authenticator (user presence AND user verification flags set) and the device signed a challenge
that the verifier chose and bound to ONE specific action, for this origin and relying party. The private key never leaves the device.
Tested against a software authenticator; the browser side (navigator.credentials) is exercised by hand."""
import base64
import hashlib
import io
import json

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

UP, UV, AT = 0x01, 0x04, 0x40


class WebAuthnError(Exception):
    pass


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _client_data(raw: bytes, typ: str, challenge: bytes, origin: str) -> dict:
    try:
        cd = json.loads(raw)
    except Exception:
        raise WebAuthnError("clientDataJSON is not JSON")
    if cd.get("type") != typ:
        raise WebAuthnError(f"wrong ceremony type (wanted {typ})")
    if cd.get("origin") != origin:
        raise WebAuthnError("origin does not match")
    if unb64u(cd.get("challenge", "")) != challenge:
        raise WebAuthnError("challenge does not match: not signed for this action")
    if cd.get("crossOrigin"):
        raise WebAuthnError("cross-origin ceremony refused")
    return cd


def _auth_data(ad: bytes, rp_id: str, need_at: bool = False):
    if len(ad) < 37:
        raise WebAuthnError("authenticator data too short")
    if ad[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise WebAuthnError("relying party id does not match")
    flags = ad[32]
    if not flags & UP:
        raise WebAuthnError("user presence flag not set")
    if not flags & UV:
        raise WebAuthnError("user verification flag not set (no Touch ID / PIN was used)")
    if need_at and not flags & AT:
        raise WebAuthnError("no attested credential data")
    return flags, int.from_bytes(ad[33:37], "big")


def parse_registration(attestation_object: bytes, client_data_json: bytes, challenge: bytes, origin: str, rp_id: str) -> dict:
    _client_data(client_data_json, "webauthn.create", challenge, origin)
    try:
        ad = cbor2.loads(attestation_object)["authData"]
        _auth_data(ad, rp_id, need_at=True)
        cred_len = int.from_bytes(ad[53:55], "big")
        cred_id = ad[55:55 + cred_len]
        cose = cbor2.CBORDecoder(io.BytesIO(ad[55 + cred_len:])).decode()
        if cose.get(1) != 2 or cose.get(3) != -7 or cose.get(-1) != 1:
            raise WebAuthnError("only ES256 / P-256 passkeys are supported")
        x, y = cose[-2], cose[-3]
    except WebAuthnError:
        raise
    except Exception:
        raise WebAuthnError("malformed attestation object")
    return {"credential_id": cred_id, "x": x, "y": y}


def verify_assertion(x: bytes, y: bytes, authenticator_data: bytes, client_data_json: bytes, signature: bytes,
                     challenge: bytes, origin: str, rp_id: str, last_counter: int = 0) -> int:
    """Returns the new signature counter. Raises WebAuthnError on any problem."""
    _client_data(client_data_json, "webauthn.get", challenge, origin)
    _, counter = _auth_data(authenticator_data, rp_id)
    try:
        key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
        key.verify(signature, authenticator_data + hashlib.sha256(client_data_json).digest(), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise WebAuthnError("signature is invalid")
    if (counter or last_counter) and counter <= last_counter:
        raise WebAuthnError("signature counter did not increase: cloned authenticator or replay")
    return counter
