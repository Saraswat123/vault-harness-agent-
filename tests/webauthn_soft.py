"""A SOFTWARE authenticator for tests: builds exactly the bytes a browser/Touch ID would return."""
import hashlib
import json
import os

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from vault_harness.webauthn import AT, UP, UV, b64u


class SoftAuthenticator:
    def __init__(self, rp_id="localhost", origin="http://localhost:8765"):
        self.key = ec.generate_private_key(ec.SECP256R1()); self.rp_id, self.origin, self.counter = rp_id, origin, 0
        self.cred_id = os.urandom(16)

    @property
    def xy(self):
        n = self.key.public_key().public_numbers()
        return n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big")

    def _cd(self, typ, challenge, origin=None):
        return json.dumps({"type": typ, "challenge": b64u(challenge), "origin": origin or self.origin, "crossOrigin": False}).encode()

    def register(self, challenge, flags=UP | UV | AT, origin=None, rp_id=None):
        x, y = self.xy
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x, -3: y})
        ad = hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([flags]) + (0).to_bytes(4, "big") + bytes(16) + len(self.cred_id).to_bytes(2, "big") + self.cred_id + cose
        return cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": ad}), self._cd("webauthn.create", challenge, origin)

    def assert_(self, challenge, flags=UP | UV, origin=None, rp_id=None, counter=None, key=None, ctype="webauthn.get"):
        self.counter = counter if counter is not None else self.counter + 1
        ad = hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([flags]) + self.counter.to_bytes(4, "big")
        cd = self._cd(ctype, challenge, origin)
        sig = (key or self.key).sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"authenticator_data": ad, "client_data_json": cd, "signature": sig}
