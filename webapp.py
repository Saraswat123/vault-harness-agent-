"""Local web app for the vault harness (127.0.0.1 only). No terminal card entry.

  python webapp.py            then open http://127.0.0.1:8765
  1. Add card:  the number is encrypted IN YOUR BROWSER to the enclave's public key; this server only ever receives ciphertext.
  2. Pay:       the agent pays the $1 Perflo Pay link through a stateless Kernel browser; you watch the live view, the guard decisions and
                the results. The CVC is encrypted in the browser per payment (one-time nonce) and never stored.
  3. Mandate:   authorize once (count, expiry, CVC sealed in the page); then 'Let the agent pay' / POST /api/agent/pay needs NO inputs.
  4. Brakes:    Freeze all / Lift, and a human Approve/Reject box when the guard wants one.
The enclave is a MOCK. With a passphrase its key is kept in output/enclave_key.json (sealed), so cards survive restarts; without one they last only while this server runs. Real-money state is separate from sandbox state.
"""
import argparse
import http.server
import json
import os
import secrets
import sys
import tempfile
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("VAULT_EVENTS_DB", str(ROOT / "output" / "events_real.db"))
os.environ.setdefault("VAULT_ALERTS_FILE", str(ROOT / "output" / "alerts_real.jsonl"))
os.environ["VAULT_POLICY"] = (ROOT / "config" / "policy.interview.json").read_text()

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from langgraph.checkpoint.memory import MemorySaver  # noqa: E402
from langgraph.types import Command  # noqa: E402

from vault_harness import actions, alerts, guard, policy  # noqa: E402
from vault_harness import enclave as E  # noqa: E402
from vault_harness.cardstore import CardStore  # noqa: E402
from vault_harness.fake_model import ScriptedWriter  # noqa: E402
from vault_harness.graph import build, start  # noqa: E402
from vault_harness.enclave_rpc import EnclaveClient as _EC  # noqa: E402
from vault_harness.hosted_checkout import ForwardProcessor, HostedCheckoutVault  # noqa: E402

LINK = "https://buy.stripe.com/4gM8wI7ET9eGdCL5292B204"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/seal.js": ("seal.js", "text/javascript; charset=utf-8")}


class App:
    def __init__(self, vault_factory=None, budget_file=None, data_dir=None, passphrase=None):
        cfg = json.loads((ROOT / "config" / "policy.interview.json").read_text())
        self.pol = policy.Policy(**{k: (tuple(v) if isinstance(v, list) else v) for k, v in cfg.items()})
        policy.BUDGET_FILE = Path(budget_file or ROOT / "output" / "budget_real.json")
        self.user, self.polkey = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        raw = lambda k: k.public_key().public_bytes(*E._RAW)
        self.mode, self.pcr0 = "mock (in-process)", None
        url = os.environ.get("VAULT_ENCLAVE")
        if url:                                                    # the enclave is a separate program: container (tcp://) or real Nitro (vsock://)
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _K
            load = lambda n: _K.from_private_bytes(bytes.fromhex((ROOT / "output" / "signers" / f"{n}.key").read_text().strip()))
            self.user, self.polkey = load("user"), load("policy")      # their PUBLIC halves are baked into the enclave image
            verify, self.mode = None, "enclave over a socket (NOT attested)"
            if os.environ.get("VAULT_EXPECT_PCR0") and os.environ.get("VAULT_ROOT_PEM"):
                from vault_harness import attestation as _A
                root, want = Path(os.environ["VAULT_ROOT_PEM"]).read_bytes(), bytes.fromhex(os.environ["VAULT_EXPECT_PCR0"])
                self.pcr0 = want.hex()
                verify = lambda out, nonce: _A.verify(bytes.fromhex(out.get("attestation_doc", "")), root_pem=root, expected_pcrs={0: want},
                                                      expected_pubkey=bytes.fromhex(out["pubkey"]), nonce=nonce)
                self.mode = "NITRO, attestation verified"
            self.enc = _EC(url, verify_attestation=verify)
        else:
          self.enc = E.MockEnclave(user_pub=raw(self.user), policy_pub=raw(self.polkey), processor=ForwardProcessor(), auto_limit_cents=self.pol.auto_approve_under_cents,
                                   max_single_cents=self.pol.max_single_cents, allowed_paths=("/v1/payment_methods",),
                                   key_file=(Path(data_dir) / "enclave_key.json") if data_dir and passphrase else None, passphrase=passphrase)
        self.persistent = bool(data_dir and passphrase)
        self.store = CardStore((Path(data_dir) / "cards_web.json") if self.persistent else Path(tempfile.mkdtemp(prefix="vh-web-")) / "cards.json")
        self.issued, self.lock = set(), threading.Lock()
        self.s = {"running": False, "log": [], "results": [], "approval": None, "started": 0.0}
        self._decision, self._decision_evt = None, threading.Event()
        self.mandate = None                              # in MEMORY only: {card_id, billing, boxes[(nonce, box)], cents, expires_at, last4}
        self.vault_factory = vault_factory or self._real_vault

    # ---------- plumbing ----------
    def say(self, msg: str):
        with self.lock:
            self.s["log"].append(f"{time.strftime('%H:%M:%S')}  {msg}")
            self.s["log"] = self.s["log"][-300:]

    def _real_vault(self, **kw):
        return HostedCheckoutVault(self.enc, checkout_url=LINK, user_key=self.user, policy_key=self.polkey, card_store=self.store,
                                   auto_limit_cents=self.pol.auto_approve_under_cents, make_browser=None, make_page=None, say=self.say, **kw)

    def live_url(self):
        f = ROOT / "output" / "live_view_url.txt"
        try:
            return f.read_text().strip() if f.exists() and f.stat().st_mtime >= self.s["started"] - 1 else None
        except OSError:
            return None

    def state(self) -> dict:
        with self.lock:
            snap = {**self.s, "log": list(self.s["log"]), "results": list(self.s["results"])}
        return {**snap, "live": self.live_url() if snap["running"] else None, "freezes": guard.Freezes().active(),
                "cards": self.store.list_display(), "counter_cents": policy.Budget().spent(), "budget_cents": self.pol.budget_total_cents,
                "alerts": alerts.read()[-12:], "mandate": self._mandate_public(), "enclave": {"mode": self.mode, "pcr0": self.pcr0}}

    def _mandate_public(self):
        m = self._live_mandate() if self.mandate else None
        return {"remaining": len(m["boxes"]), "of": m["n"], "cents": m["cents"], "expires_at": m["expires_at"], "last4": m["last4"]} if m else None

    # ---------- API ----------
    def attest(self):
        return self.enc.attest()

    def new_card_id(self):
        return CardStore.new_id()

    def enroll(self, card_id: str, sealed: dict) -> dict:
        display = self.enc.enroll(sealed, card_id)                      # ciphertext in; display fields out
        self.store.add(card_id, display, sealed)
        self.say(f"card on file: {display['brand']} ****{display['last4']} (ciphertext only; {len(json.dumps(sealed))} bytes stored)")
        return {"card_id": card_id, **display}

    def nonces(self, n: int) -> list:
        out = [secrets.token_hex(8) for _ in range(max(1, min(n, 10)))]
        self.issued.update(out)
        return out

    def freeze(self, scope: str, reason: str):
        guard.Freezes().freeze(scope, reason or "web app"); alerts.emit("freeze_set", "critical", scope=scope, reason=reason or "")
        self.say(f"FROZEN: {scope}")

    def lift(self, scope: str):
        guard.Freezes().lift(scope); alerts.emit("freeze_lifted", "warn", scope=scope); self.say(f"lifted: {scope}")

    def decide(self, decision: str):
        self._decision = "approve" if decision == "approve" else "reject"
        self._decision_evt.set()

    def pay(self, b: dict) -> dict:
        if self.s["running"]:
            raise ValueError("a run is already in progress")
        if b.get("confirm") != "PAY":
            raise ValueError("type PAY to confirm that these are REAL payments")
        times, cents = int(b.get("times", 1)), int(b.get("cents", 100))
        if not 1 <= times <= 10 or not 1 <= cents <= 200:
            raise ValueError("limits: 1-10 payments of at most $2.00")
        if b.get("card_id") not in {c["id"] for c in self.store.list_display()}:
            raise ValueError("unknown card id: add a card first")
        nonces, boxes = b.get("nonces", []), b.get("cvc_boxes", [])
        if len(nonces) != times or len(boxes) != times or any(n not in self.issued for n in nonces):
            raise ValueError("one issued nonce and one sealed CVC per payment are required")
        bill = b.get("billing", {})
        for f in ("email", "name", "country", "address", "city"):
            if not str(bill.get(f, "")).strip():
                raise ValueError(f"billing {f} is required")
        for n in nonces:
            self.issued.discard(n)
        return self._begin(b["card_id"], times, cents, bill, nonces, boxes)

    def _begin(self, card_id, times, cents, bill, nonces, boxes):
        with self.lock:
            self.s.update(running=True, results=[], approval=None, started=time.time())
        threading.Thread(target=self._run, args=(card_id, times, cents, bill, nonces, boxes), daemon=True).start()
        return {"started": True}

    # ---------- mandate: authorize once, then the agent pays with no inputs ----------
    def authorize(self, b: dict) -> dict:
        if b.get("confirm") != "AUTHORIZE":
            raise ValueError("type AUTHORIZE to allow the agent to make REAL payments within these limits")
        n, cents, mins = int(b.get("count", 1)), int(b.get("cents", 100)), int(b.get("minutes", 30))
        if not (1 <= n <= 10 and 1 <= cents <= 200 and 1 <= mins <= 60):
            raise ValueError("limits: 1-10 payments, at most $2.00 each, valid at most 60 minutes")
        card = next((c for c in self.store.list_display() if c["id"] == b.get("card_id")), None)
        if not card:
            raise ValueError("unknown card id: add a card first")
        nonces, boxes = b.get("nonces", []), b.get("cvc_boxes", [])
        if len(nonces) != n or len(boxes) != n or any(x not in self.issued for x in nonces):
            raise ValueError("one issued nonce and one sealed CVC per authorised payment are required")
        bill = b.get("billing", {})
        for f in ("email", "name", "country", "address", "city"):
            if not str(bill.get(f, "")).strip():
                raise ValueError(f"billing {f} is required")
        for x in nonces:
            self.issued.discard(x)
        self.mandate = {"card_id": card["id"], "billing": bill, "boxes": list(zip(nonces, boxes)), "cents": cents, "expires_at": time.time() + mins * 60, "last4": card["last4"], "n": n}
        alerts.emit("mandate_created", "warn", payments=n, cents=cents, minutes=mins, card_last4=card["last4"])
        self.say(f"MANDATE: the agent may make up to {n} payment(s) of ${cents/100:.2f} on ****{card['last4']} for {mins} min. It will hold no card and no CVC in the clear.")
        return {"ok": True}

    def _live_mandate(self):
        m = self.mandate
        if m and (time.time() > m["expires_at"] or not m["boxes"]):
            self.say("mandate ended (" + ("expired" if time.time() > m["expires_at"] else "used up") + ")")
            self.mandate = None
        return self.mandate

    def revoke_mandate(self):
        if self.mandate:
            self.mandate = None; alerts.emit("mandate_revoked", "warn"); self.say("MANDATE REVOKED: the stored CVC boxes were dropped")

    def agent_pay(self) -> dict:
        """What an agent calls. No card, no CVC, no billing details: only the mandate's pre-sealed ciphertext is used."""
        if self.s["running"]:
            raise ValueError("a payment is already in progress")
        m = self._live_mandate()
        if not m:
            raise ValueError("no active mandate: a human must authorize one first")
        nonce, box = m["boxes"].pop(0)
        self.say(f"the AGENT requests a payment under the mandate ({len(m['boxes'])} left after this one)")
        return self._begin(m["card_id"], 1, m["cents"], m["billing"], [nonce], [box])

    def _run(self, card_id, times, cents, bill, nonces, boxes):
        draft = json.dumps({"merchant": "buy.stripe.com", "amount_cents": cents, "currency": "usd", "description": "Perflo Pay test product"})
        try:
            for i in range(times):
                n = i + 1
                aad = f"cvc-nonce:{nonces[i]}"
                vault = self.vault_factory(card_id=card_id, billing=bill, cvc_box_provider=lambda b=boxes[i], a=aad: (b, a))
                actions.use(vault)
                g, cfg = build(MemorySaver(), ScriptedWriter(drafts=[draft])), {"configurable": {"thread_id": f"web-{n}-{secrets.token_hex(3)}"}}
                self.say(f"#{n}: the agent proposes ${cents/100:.2f} to buy.stripe.com (it has no card; it will get a placeholder)")
                try:
                    start(g, f"Pay the ${cents/100:.2f} Perflo test (#{n})", True, cfg, card_id=card_id)
                except Exception as e:
                    self.say(f"#{n} HALTED by the safety kernel: {type(e).__name__}: {str(e)[:200]}. Check the receipt before doing anything else.")
                    self._add(n, "halted", "-", "-"); return
                st = g.get_state(cfg).values
                if any(t.interrupts for t in g.get_state(cfg).tasks):
                    with self.lock:
                        self.s["approval"] = st["verdict"]["reasons"]
                    self.say(f"#{n}: the guard wants a human: {st['verdict']['reasons']}")
                    self._decision_evt.clear()
                    got = self._decision_evt.wait(300)
                    with self.lock:
                        self.s["approval"] = None
                    if not got or self._decision != "approve":
                        self.say(f"#{n}: stopped (no approval)"); self._add(n, "stopped", "-", "-"); return
                    g.invoke(Command(resume={"decision": "approve"}), cfg)
                    st = g.get_state(cfg).values
                res = st.get("result") or {}
                self._add(n, st.get("outcome"), res.get("charge_id", "-"), res.get("card_last4", "-"), res.get("reason") or "")
                self.say(f"#{n}: outcome={st.get('outcome')}  payment_method={res.get('charge_id','-')}  last4={res.get('card_last4','-')}" + (f"  reason={res.get('reason')}" if res.get("reason") else ""))
                if st.get("outcome") != "done":
                    return
        finally:
            with self.lock:
                self.s["running"] = False

    def _add(self, n, outcome, pm, last4, reason=""):
        with self.lock:
            self.s["results"].append({"n": n, "outcome": outcome, "payment_method": pm, "last4": last4, "reason": reason})


def make_handler(app: App, port: int):
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store"); self.send_header("X-Content-Type-Options", "nosniff"); self.end_headers(); self.wfile.write(data)

        def _ok_host(self):
            if self.headers.get("Host", "") not in hosts:                 # blocks DNS-rebinding style access
                self._send(403, {"error": "bad host"}); return False
            return True

        def do_GET(self):
            if not self._ok_host():
                return
            path = self.path.split("?")[0]
            if path in STATIC:
                f, ct = STATIC[path]; return self._send(200, (ROOT / "static" / f).read_bytes(), ct)
            if path == "/api/attest": return self._send(200, app.attest())
            if path == "/api/new-card-id": return self._send(200, {"card_id": app.new_card_id()})
            if path == "/api/state": return self._send(200, app.state())
            if path == "/api/nonces":
                n = int((self.path.split("n=")[1] if "n=" in self.path else "1").split("&")[0]); return self._send(200, {"nonces": app.nonces(n)})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._ok_host():
                return
            if self.headers.get("X-Harness") != "1":                      # a cross-site form post cannot set this header
                return self._send(403, {"error": "missing X-Harness header"})
            try:
                b = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0) or b"{}")
                path = self.path.split("?")[0]
                if path == "/api/enroll": return self._send(200, app.enroll(b["card_id"], b["sealed"]))
                if path == "/api/pay": return self._send(200, app.pay(b))
                if path == "/api/mandate": return self._send(200, app.authorize(b))
                if path == "/api/mandate/revoke": app.revoke_mandate(); return self._send(200, {"ok": True})
                if path == "/api/agent/pay": return self._send(200, app.agent_pay())
                if path == "/api/approve": app.decide(b.get("decision", "reject")); return self._send(200, {"ok": True})
                if path == "/api/freeze": app.freeze(b.get("scope", "all"), b.get("reason", "")); return self._send(200, {"ok": True})
                if path == "/api/lift": app.lift(b.get("scope", "all")); return self._send(200, {"ok": True})
                self._send(404, {"error": "not found"})
            except (ValueError, KeyError, E.EnclaveRefused) as e:
                self._send(400, {"error": str(e)[:300]})
            except Exception as e:
                self._send(500, {"error": f"{type(e).__name__}"})
    return H


def serve(port=8765, app=None, open_browser=True):
    app = app or App()
    print("cards persist across restarts (passphrase-sealed key)" if app.persistent else "EPHEMERAL: cards are forgotten when this server stops")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), make_handler(app, port))
    port = srv.server_address[1]
    srv.RequestHandlerClass = make_handler(app, port)
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()
    print(f"vault harness web app on http://127.0.0.1:{port}  (Ctrl+C to stop)")
    return srv, app


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--port", type=int, default=8765); ap.add_argument("--no-open", action="store_true")
    a = ap.parse_args()
    import getpass
    pw = getpass.getpass("Passphrase to unlock the enclave key (first run: choose one; empty = no persistence): ")
    try:
        app = App(data_dir=ROOT / "output", passphrase=pw or None)
    except E.EnclaveRefused as e:
        sys.exit(str(e))
    srv, _ = serve(a.port, app=app, open_browser=not a.no_open)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("stopped")
