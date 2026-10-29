"""The enclave as a separate program: a tiny length-prefixed JSON protocol, a server that wraps the enclave logic, and a client with the SAME
interface as MockEnclave (so EnclaveVault, HostedCheckoutVault and the web app work unchanged).

Transports:  tcp://host:port   (local tests, Docker)        vsock://CID:port   (real Nitro: the parent talks to the enclave over vsock)
The channel is UNTRUSTED by design: everything crossing it is ciphertext, a placeholder, public data, or a masked result. The card number never
crosses it; the replies from the processor are scanned for card-like digits inside the enclave before they are returned.
"""
import json
import socket
import struct
import threading
from dataclasses import asdict

from vault_harness import enclave as E
from vault_harness.policy import Intent

MAX_MSG = 2_000_000


def _send(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv(sock):
    head = b""
    while len(head) < 4:
        c = sock.recv(4 - len(head))
        if not c:
            raise ConnectionError("closed")
        head += c
    n = struct.unpack(">I", head)[0]
    if n > MAX_MSG:
        raise ValueError("message too large")
    buf = b""
    while len(buf) < n:
        c = sock.recv(min(65536, n - len(buf)))
        if not c:
            raise ConnectionError("closed")
        buf += c
    return json.loads(buf)


def _dial(url: str, timeout: float):
    scheme, rest = url.split("://", 1)
    host, port = rest.rsplit(":", 1)
    if scheme == "tcp":
        return socket.create_connection((host, int(port)), timeout=timeout)
    if scheme == "vsock":
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)               # Linux only (the parent EC2 instance)
        s.settimeout(timeout); s.connect((int(host), int(port)))
        return s
    raise ValueError(f"unknown transport {scheme!r}")


class EnclaveServer:
    """Wraps a MockEnclave-compatible object. Run inside the enclave (vsock) or in a container (tcp)."""

    def __init__(self, enclave, attestation=None):
        self.enc, self._att, self._lock = enclave, attestation, threading.Lock()

    def handle(self, req: dict) -> dict:
        op, a = req.get("op"), req.get("args", {})
        try:
            with self._lock:
                if op == "attest":
                    out = dict(self.enc.attest())
                    if self._att:
                        out["attestation_doc"] = self._att(bytes.fromhex(out["pubkey"]), bytes.fromhex(a["nonce"]) if a.get("nonce") else None)     # real Nitro: signed by the hypervisor, carries PCRs
                    return {"ok": True, "result": out}
                if op == "issue_placeholder":
                    return {"ok": True, "result": asdict(self.enc.issue_placeholder(Intent(**a["intent"])))}
                if op == "enroll":
                    return {"ok": True, "result": self.enc.enroll(a["sealed"], a["card_id"])}
                if op == "pay":
                    return {"ok": True, "result": self.enc.pay(sealed=a["sealed"], placeholder=E.Placeholder(**a["placeholder"]), intent=Intent(**a["intent"]),
                                                                request=a["request"], approval=a["approval"], card_id=a.get("card_id"), cvc_sealed=a.get("cvc_sealed"),
                                                                mode=a.get("mode", "charge"), cvc_aad=a.get("cvc_aad"))}
                if op == "revoke":
                    self.enc.revoke(a["scope"], a["nonce"], a["sig"]); return {"ok": True, "result": None}
                if op == "lift":
                    self.enc.lift(a["scope"], a["nonce"], a.get("sig", ""), a.get("webauthn")); return {"ok": True, "result": None}
                if op == "register_passkey":
                    return {"ok": True, "result": self.enc.register_passkey(bytes.fromhex(a["x"]), bytes.fromhex(a["y"]))}
            return {"ok": False, "error": "unknown_op", "message": str(op)[:40]}
        except E.EnclaveRefused as e:
            return {"ok": False, "error": "EnclaveRefused", "message": str(e)}
        except Exception as e:                                                      # never leak internals or request contents across the channel
            return {"ok": False, "error": "internal", "message": type(e).__name__}

    def serve_forever(self, listener: socket.socket):
        def one(conn):
            try:
                with conn:
                    conn.settimeout(90)
                    _send(conn, self.handle(_recv(conn)))
            except Exception:
                pass
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=one, args=(conn,), daemon=True).start()


def listen_tcp(host: str, port: int) -> socket.socket:
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((host, port)); s.listen(16)
    return s


def listen_vsock(port: int) -> socket.socket:
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); s.bind((socket.VMADDR_CID_ANY, port)); s.listen(16)
    return s


class EnclaveClient:
    """Drop-in for MockEnclave on the harness side."""

    def __init__(self, url: str, timeout: float = 90, verify_attestation=None):
        self.url, self.timeout, self._verify = url, timeout, verify_attestation

    def _call(self, op: str, **args):
        s = _dial(self.url, self.timeout)
        try:
            _send(s, {"op": op, "args": args})
            r = _recv(s)
        finally:
            s.close()
        if not r.get("ok"):
            if r.get("error") == "EnclaveRefused":
                raise E.EnclaveRefused(r.get("message", ""))
            raise RuntimeError(f"enclave error: {r.get('error')}")
        return r["result"]

    def attest(self) -> dict:
        import os
        nonce = os.urandom(32)
        out = self._call("attest", nonce=nonce.hex())
        if self._verify:
            self._verify(out, nonce)                           # raises unless the signed document checks out (PCRs, chain, key binding, nonce)
        return out

    def issue_placeholder(self, intent: Intent) -> E.Placeholder:
        return E.Placeholder(**self._call("issue_placeholder", intent=asdict(intent)))

    def enroll(self, sealed: dict, card_id: str) -> dict:
        return self._call("enroll", sealed=sealed, card_id=card_id)

    def pay(self, *, sealed, placeholder, intent, request, approval, card_id=None, cvc_sealed=None, mode="charge", cvc_aad=None) -> dict:
        return self._call("pay", sealed=sealed, placeholder=asdict(placeholder), intent=asdict(intent), request=request, approval=approval,
                          card_id=card_id, cvc_sealed=cvc_sealed, mode=mode, cvc_aad=cvc_aad)

    def revoke(self, scope, nonce, sig):
        self._call("revoke", scope=scope, nonce=nonce, sig=sig)

    def lift(self, scope, nonce, sig="", webauthn=None):
        self._call("lift", scope=scope, nonce=nonce, sig=sig, webauthn=webauthn)

    def register_passkey(self, x: bytes, y: bytes) -> str:
        return self._call("register_passkey", x=x.hex(), y=y.hex())
