"""MOCK Nitro Enclave. Same interface and trust model as the real thing; NOT a real enclave (no isolation, no attestation).

What it models:
  - The card is sealed (X25519 + HKDF + AES-GCM) to the enclave's public key on the USER'S side. The host/harness only ever
    carries ciphertext. It never sees the card and never stores it.
  - The enclave issues placeholders, checks the signed approval, checks the captured processor request, swaps the real card
    in, sends it to the processor, and returns a masked result. Nothing is kept afterwards.
  - Guardrails enforced INSIDE the enclave (so a compromised host cannot lift them): per-purchase cap, user-signature
    requirement at or above the auto-approve limit, processor host allowlist, amount-in-request must equal approved amount.

What it does NOT model: memory isolation, attestation/KMS key release, zeroization guarantees (Python cannot guarantee
wiping a str; the real build is Rust/C in a Nitro enclave). Those are PRT milestone M6.
"""
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urlparse

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from vault_harness import policy as _policy
from vault_harness import webauthn as W
from vault_harness.policy import Intent

PLACEHOLDER_TTL = 600
_RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw


def bind(i: Intent) -> str:
    return hashlib.sha256(json.dumps([i.merchant, i.amount_cents, i.currency], sort_keys=True).encode()).hexdigest()


def approval_challenge(i: Intent, nonce: str) -> bytes:
    """What the passkey signs to approve ONE payment: bound to merchant+amount+currency and a one-time nonce."""
    return hashlib.sha256(f"approve:{bind(i)}:{nonce}".encode()).digest()


def lift_challenge(scope: str, nonce: str) -> bytes:
    return hashlib.sha256(f"lift:{scope}:{nonce}".encode()).digest()


def approval_message(i: Intent, token: str) -> bytes:
    return f"pay:{bind(i)}:{token}".encode()


def _key(shared: bytes, epk: bytes, pub: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt=None, info=b"vault-harness/seal/v1" + epk + pub).derive(shared)


def seal(enclave_pub: bytes, card: dict, aad: bytes = b"") -> dict:
    """Runs on the USER'S device (or any trusted client). Returns ciphertext only."""
    esk = X25519PrivateKey.generate()
    epk = esk.public_key().public_bytes(*_RAW)
    k = _key(esk.exchange(X25519PublicKey.from_public_bytes(enclave_pub)), epk, enclave_pub)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(k).encrypt(nonce, json.dumps(card).encode(), aad)
    return {"epk": epk.hex(), "nonce": nonce.hex(), "ct": ct.hex(), "aad": aad.hex()}


def _luhn(body: str) -> str:
    s = 0
    for n, ch in enumerate(reversed(body)):
        d = int(ch) * (2 if n % 2 == 0 else 1)
        s += d - 9 if d > 9 else d
    return body + str((10 - s % 10) % 10)


@dataclass(frozen=True)
class Placeholder:
    """What the agent's browser types into the form. Luhn-valid so form validation passes; worth nothing anywhere else."""
    token: str
    number: str
    exp_month: str
    exp_year: str
    cvc: str


class EnclaveRefused(Exception):
    pass



def load_or_create_key(path, passphrase: str) -> X25519PrivateKey:
    """Mock stand-in for 'KMS releases the key only to the attested enclave': the X25519 private key lives in a file sealed with a passphrase
    (scrypt -> AES-256-GCM). Wrong passphrase = refused. The real build replaces this with KMS + attestation; nothing here is production custody."""
    import os
    from pathlib import Path
    f = Path(path)
    aad = b"vault-harness/enclave-key/v1"
    if f.exists():
        d = json.loads(f.read_text())
        k = Scrypt(salt=bytes.fromhex(d["salt"]), length=32, n=d["n"], r=8, p=1).derive(passphrase.encode())
        try:
            return X25519PrivateKey.from_private_bytes(AESGCM(k).decrypt(bytes.fromhex(d["nonce"]), bytes.fromhex(d["ct"]), aad))
        except InvalidTag:
            raise EnclaveRefused("could not unlock the enclave key (wrong passphrase?)")
    sk = X25519PrivateKey.generate()
    salt, nonce, n = os.urandom(16), os.urandom(12), 2 ** 15
    k = Scrypt(salt=salt, length=32, n=n, r=8, p=1).derive(passphrase.encode())
    raw = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps({"salt": salt.hex(), "n": n, "nonce": nonce.hex(), "ct": AESGCM(k).encrypt(nonce, raw, aad).hex()}))
    f.chmod(0o600)
    return sk


class MockEnclave:
    def __init__(self, *, user_pub: bytes, policy_pub: bytes, processor: Callable[[dict], dict],
                 auto_limit_cents: int = 500, max_single_cents: int = 2000, allowed_hosts=("api.stripe.com",), allowed_paths=None, key_file=None, passphrase=None,
                 webauthn_origin="http://localhost:8765", webauthn_rp_id="localhost"):
        self.__sk = load_or_create_key(key_file, passphrase) if key_file else X25519PrivateKey.generate()
        self._pub = self.__sk.public_key().public_bytes(*_RAW)
        self._signers = {"user": Ed25519PublicKey.from_public_bytes(user_pub), "policy": Ed25519PublicKey.from_public_bytes(policy_pub)}
        self._processor, self._auto, self._cap, self._hosts = processor, auto_limit_cents, max_single_cents, tuple(allowed_hosts)
        self._paths = tuple(allowed_paths) if allowed_paths else None      # e.g. only /v1/payment_methods may ever receive the real card
        self._ph = {}                                      # token -> {number, bind, exp, used}
        self._wa_origin, self._wa_rp, self._passkey = webauthn_origin, webauthn_rp_id, None     # passkey: {x, y, counter}
        self._boxes_used = set()                              # one-time CVC nonces already consumed (browser-sealed CVC boxes)
        self._revoked, self._nonces = set(), set()         # scopes: all | card:<id> | merchant:<host>; changed only by USER-signed commands

    def attest(self) -> dict:
        """Real Nitro: signed attestation document with PCRs; KMS releases the key only to a matching enclave."""
        return {"pubkey": self._pub.hex(), "mock": True, "config_hash": hashlib.sha256(repr((self._auto, self._cap, self._hosts)).encode()).hexdigest()}

    def issue_placeholder(self, i: Intent) -> Placeholder:
        number = _luhn("4" + "".join(str(secrets.randbelow(10)) for _ in range(14)))            # Visa-shaped + Luhn-valid so real checkout forms accept it
        p = Placeholder("ph_" + secrets.token_hex(10), number, "12", str(time.gmtime().tm_year + 3), "".join(str(secrets.randbelow(10)) for _ in range(3)))
        self._ph[p.token] = {"number": number, "bind": bind(i), "exp": time.time() + PLACEHOLDER_TTL, "used": False}
        return p

    # ---- the one operation ----
    # ---- instant revocation, enforced here so a compromised host cannot lift it ----
    def _cmd(self, verb: str, scope: str, nonce: str, sig: str):
        if nonce in self._nonces:
            raise EnclaveRefused("command replayed")
        try:
            self._signers["user"].verify(bytes.fromhex(sig), f"{verb}:{scope}:{nonce}".encode())
        except (InvalidSignature, ValueError):
            raise EnclaveRefused("command signature invalid")
        self._nonces.add(nonce)

    def revoke(self, scope: str, nonce: str, sig: str):
        self._cmd("revoke", scope, nonce, sig); self._revoked.add(scope)

    def register_passkey(self, x: bytes, y: bytes) -> str:
        """Trust-on-first-use in this mock. In the real build the passkey public key must arrive over the attested channel (or be baked into the image)."""
        if self._passkey:
            raise EnclaveRefused("a passkey is already registered")
        self._passkey = {"x": x, "y": y, "counter": 0}
        return hashlib.sha256(x + y).hexdigest()[:16]

    def _check_passkey(self, challenge: bytes, approval: dict, once_key: str):
        wa, nonce = approval.get("webauthn"), approval.get("nonce")
        if not wa or not nonce:
            raise EnclaveRefused("a passkey approval (Touch ID) is required")
        if once_key in self._boxes_used:
            raise EnclaveRefused("approval already used")
        try:
            new = W.verify_assertion(self._passkey["x"], self._passkey["y"], bytes.fromhex(wa["authenticator_data"]), bytes.fromhex(wa["client_data_json"]),
                                     bytes.fromhex(wa["signature"]), challenge, self._wa_origin, self._wa_rp, self._passkey["counter"])
        except (W.WebAuthnError, KeyError, ValueError) as e:
            raise EnclaveRefused(f"passkey approval invalid: {e}")
        self._passkey["counter"] = new
        self._boxes_used.add(once_key)

    def lift(self, scope: str, nonce: str, sig: str, webauthn: dict = None):
        if self._passkey:                                   # with a passkey registered, lifting a freeze needs Touch ID: the host cannot do it alone
            self._check_passkey(lift_challenge(scope, nonce), {"webauthn": webauthn, "nonce": nonce}, f"lift:{nonce}")
        else:
            self._cmd("lift", scope, nonce, sig)
        self._revoked.discard(scope)

    def enroll(self, sealed: dict, card_id: str) -> dict:
        """Open a sealed card once, validate it, return DISPLAY fields only. The host stores the sealed box; the enclave stores nothing."""
        card = self._open(sealed, card_id)
        try:
            n = str(card.get("number", ""))
            if not n.isdigit() or not 13 <= len(n) <= 19 or _luhn(n[:-1]) != n:
                raise EnclaveRefused("card number failed validation")
            brand = "visa" if n[0] == "4" else "mastercard" if n[:2] in ("51", "52", "53", "54", "55") or 2221 <= int(n[:4]) <= 2720 else "amex" if n[:2] in ("34", "37") else "discover" if n[0] == "6" else "unknown"
            return {"brand": brand, "last4": n[-4:], "exp_month": int(card["exp_month"]), "exp_year": int(card["exp_year"])}
        finally:
            card.clear()

    def pay(self, *, sealed: dict, placeholder: Placeholder, intent: Intent, request: dict, approval: dict, card_id: str = None, cvc_sealed: dict = None, mode: str = "charge", cvc_aad: str = None) -> dict:
        rec = self._ph.get(placeholder.token)
        for sc in ("all", f"card:{card_id}" if card_id else None, f"merchant:{intent.merchant}"):
            if sc in self._revoked:
                raise EnclaveRefused(f"revoked: {sc}")
        self._gate(rec, placeholder, intent, request, approval)
        rec["used"] = True                                  # burned before any card is touched: a retry cannot double-charge
        card = self._open(sealed, card_id)
        if cvc_sealed:                                       # per-payment CVC: bound to THIS placeholder, used once, never stored
            if cvc_aad:                                      # a CVC box sealed in the user's browser, tied to a one-time nonce
                if not cvc_aad.startswith("cvc-nonce:") or cvc_aad in self._boxes_used:
                    raise EnclaveRefused("cvc box already used or malformed")
                self._boxes_used.add(cvc_aad)
            c2 = self._open(cvc_sealed, cvc_aad or f"cvc:{placeholder.token}")
            card["cvc"] = c2.get("cvc"); c2.clear()
        try:
            real = self._swap(request, placeholder, card)
            out = self._processor({**real, "meta": {"amount_cents": intent.amount_cents, "currency": intent.currency, "idempotency_key": placeholder.token}})
        finally:
            for k in list(card):                            # best effort only (see module docstring)
                card[k] = "0" * len(str(card[k]))
            card.clear()
            real = None
        if mode == "forward":                               # hosted checkout: hand the processor's reply back to the page, never the card
            body = str(out.get("raw", ""))
            if _policy.contains_pan(body):
                return {"status": "refused", "reason": "processor reply carried card-like digits; withheld"}
            return {"status": "forwarded", "http_status": out.get("status"), "content_type": out.get("ctype", "application/json"), "body": body}
        return self._result(out, intent)

    # ---- guards, all inside the trust boundary ----
    def _gate(self, rec, ph, i, req, approval):
        if rec is None:
            raise EnclaveRefused("unknown placeholder")
        if rec["used"]:
            raise EnclaveRefused("placeholder already used")
        if time.time() > rec["exp"]:
            raise EnclaveRefused("placeholder expired")
        if rec["bind"] != bind(i):
            raise EnclaveRefused("placeholder not bound to this payment")
        if i.amount_cents <= 0 or i.amount_cents > self._cap:
            raise EnclaveRefused(f"amount outside enclave cap {self._cap}")
        signer = approval.get("signer")
        if signer not in self._signers:
            raise EnclaveRefused("unknown signer")
        if signer == "policy" and i.amount_cents >= self._auto:
            raise EnclaveRefused("at or above the auto-approve limit the USER must sign")
        if signer == "user" and self._passkey:             # a human approval must be a Touch ID / passkey assertion for THIS payment
            self._check_passkey(approval_challenge(i, str(approval.get("nonce", ""))), approval, f"appr:{approval.get('nonce')}")
        else:
            try:
                self._signers[signer].verify(bytes.fromhex(approval.get("sig", "")), approval_message(i, ph.token))
            except (InvalidSignature, ValueError):
                raise EnclaveRefused("approval signature invalid")
        u = urlparse(req.get("url", ""))
        if u.scheme != "https" or u.hostname not in self._hosts:
            raise EnclaveRefused(f"processor host {u.hostname!r} not allowed")   # a captured request to evil.example would receive the real card
        if self._paths and u.path not in self._paths:
            raise EnclaveRefused(f"processor path {u.path!r} not allowed")
        pairs = parse_qsl(req.get("body", ""), keep_blank_values=True)
        m = next((v for k, v in pairs if k == "amount" and v.isdigit()), None)
        if m is not None and int(m) != i.amount_cents:
            raise EnclaveRefused(f"request amount {m} != approved {i.amount_cents}")
        if not any(k == "card[number]" and re.sub(r"\D", "", v) == ph.number for k, v in pairs):
            raise EnclaveRefused("request does not carry this placeholder")

    def _open(self, sealed: dict, card_id: str = None) -> dict:
        if bytes.fromhex(sealed.get("aad", "") or "") != (card_id or "").encode():
            raise EnclaveRefused("sealed card is not bound to this card id")      # a blob for card A cannot be passed off as card B
        try:
            epk = bytes.fromhex(sealed["epk"])
            k = _key(self.__sk.exchange(X25519PublicKey.from_public_bytes(epk)), epk, self._pub)
            return json.loads(AESGCM(k).decrypt(bytes.fromhex(sealed["nonce"]), bytes.fromhex(sealed["ct"]), bytes.fromhex(sealed.get("aad", ""))))
        except (InvalidTag, KeyError, ValueError):
            raise EnclaveRefused("sealed card could not be opened")

    @staticmethod
    def _swap(request: dict, ph: Placeholder, card: dict) -> dict:
        out = []
        for k, v in parse_qsl(request["body"], keep_blank_values=True):
            if k == "card[number]":
                v = card["number"]
            elif k == "card[cvc]":
                if card.get("cvc") in (None, ""):
                    continue                                                      # CVC is never stored; card-on-file payments go without it
                v = str(card["cvc"])
            elif k == "card[exp_month]":
                v = str(int(card["exp_month"])).zfill(len(v)) if len(v) > 1 else str(int(card["exp_month"]))
            elif k == "card[exp_year]":
                y = int(card["exp_year"]); v = str(y % 100).zfill(2) if len(v) <= 2 else str(y)      # keep the width the page used
            out.append((k, v))
        return {**request, "body": urlencode(out, safe="[]")}

    @staticmethod
    def _result(out: dict, i: Intent) -> dict:
        j = out.get("json", {})
        if out.get("status") != 200 or j.get("status") not in ("succeeded", "ok"):
            return {"status": "refused", "reason": str(j.get("error", "processor declined"))[:400]}
        return {"status": "done", "charge_id": j.get("id", ""), "merchant": i.merchant, "amount_cents": j.get("amount", i.amount_cents),
                "currency": i.currency, "card_last4": j.get("last4")}
