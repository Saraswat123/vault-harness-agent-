"""The local web app: security checks, browser-side encryption (via Node), validation, run loop, freeze, human approval. Offline, fake vault."""
import http.client
import json
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

from vault_harness import enclave as E
from vault_harness import policy

ROOT = Path(__file__).resolve().parent.parent
PAN = "4242424242424242"


class FakeVault:
    def issue_placeholder(self, i):
        return "ph"

    def pay(self, ph, i):
        return {"status": "done", "charge_id": "pm_fake1", "merchant": i.merchant, "amount_cents": i.amount_cents, "currency": i.currency, "card_last4": "4242"}


@pytest.fixture
def web(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_POLICY", (ROOT / "config" / "policy.interview.json").read_text())
    monkeypatch.setattr(policy, "BUDGET_FILE", tmp_path / "b.json")
    import webapp
    app = webapp.App(vault_factory=lambda **kw: FakeVault(), budget_file=tmp_path / "b.json")
    srv, _ = webapp.serve(0, app, open_browser=False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def call(method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        h = {"X-Harness": "1", "Content-Type": "application/json", **(headers or {})}
        c.request(method, path, json.dumps(body) if body is not None else None, h)
        r = c.getresponse(); raw = r.read(); c.close()
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, raw
    yield app, call
    srv.shutdown()


def enroll_python(app, call, number=PAN):
    cid = call("GET", "/api/new-card-id")[1]["card_id"]
    box = E.seal(bytes.fromhex(call("GET", "/api/attest")[1]["pubkey"]), {"number": number, "exp_month": 12, "exp_year": 2030}, aad=cid.encode())
    return cid, call("POST", "/api/enroll", {"card_id": cid, "sealed": box})


BILL = {"email": "a+x@b.co", "name": "A B", "country": "AE", "address": "1 St", "city": "Dubai"}


def pay_body(app, call, cid, times=1, cents=100, confirm="PAY"):
    nonces = call("GET", f"/api/nonces?n={times}")[1]["nonces"]
    return {"card_id": cid, "times": times, "cents": cents, "confirm": confirm, "nonces": nonces, "cvc_boxes": [{"x": 1}] * times, "billing": BILL}


def wait_idle(call, t=15):
    end = time.time() + t
    while time.time() < end:
        s = call("GET", "/api/state")[1]
        if not s["running"]:
            return s
        time.sleep(0.1)
    raise AssertionError("run did not finish")


def test_page_and_script_are_served_and_post_needs_the_header_and_host(web):
    app, call = web
    assert call("GET", "/")[0] == 200 and b"Vault Harness" in call("GET", "/")[1] and call("GET", "/seal.js")[0] == 200
    assert call("POST", "/api/freeze", {"scope": "all"}, headers={"X-Harness": "0"})[0] == 403          # a cross-site post cannot set this header
    assert call("GET", "/api/state", headers={"Host": "evil.example"})[0] == 403                         # DNS-rebinding style access refused


def test_card_added_in_the_page_reaches_the_server_as_ciphertext_only(web, tmp_path):
    app, call = web
    cid, (code, out) = enroll_python(app, call)
    assert code == 200 and out["last4"] == "4242" and out["brand"] == "visa"
    st = call("GET", "/api/state")[1]
    assert st["cards"][0]["last4"] == "4242" and "sealed" not in st["cards"][0]
    assert PAN not in app.store.path.read_text() and PAN not in json.dumps(st)


@pytest.mark.skipif(not shutil.which("node"), reason="node needed to run the browser-side sealing code")
def test_a_box_sealed_by_the_actual_browser_code_is_accepted(web):
    app, call = web
    cid = call("GET", "/api/new-card-id")[1]["card_id"]
    pub = call("GET", "/api/attest")[1]["pubkey"]
    box = json.loads(subprocess.run(["node", str(ROOT / "tests" / "seal_interop.mjs"), pub, cid, json.dumps({"number": PAN, "exp_month": 12, "exp_year": 2030})],
                                    capture_output=True, text=True, check=True).stdout)
    assert PAN not in json.dumps(box)
    code, out = call("POST", "/api/enroll", {"card_id": cid, "sealed": box})
    assert code == 200 and out["last4"] == "4242"
    bad = call("POST", "/api/enroll", {"card_id": "vc_other", "sealed": box})                            # same box under another card id
    assert bad[0] == 400 and "not bound" in bad[1]["error"]


def test_pay_validation(web):
    app, call = web
    cid, _ = enroll_python(app, call)
    assert call("POST", "/api/pay", pay_body(app, call, cid, confirm="yes"))[0] == 400                    # must type PAY
    assert call("POST", "/api/pay", pay_body(app, call, "vc_unknown"))[0] == 400
    assert call("POST", "/api/pay", pay_body(app, call, cid, cents=500))[0] == 400                        # capped at $2.00 per payment
    assert call("POST", "/api/pay", pay_body(app, call, cid, times=11))[0] == 400
    b = pay_body(app, call, cid); b["nonces"] = ["notissued"]
    assert call("POST", "/api/pay", b)[0] == 400
    b = pay_body(app, call, cid); b["billing"] = {**BILL, "address": ""}
    assert call("POST", "/api/pay", b)[0] == 400


def test_full_run_loop_through_the_real_graph_with_a_fake_vault(web):
    app, call = web
    cid, _ = enroll_python(app, call)
    b = pay_body(app, call, cid, times=2)
    assert call("POST", "/api/pay", b)[0] == 200
    s = wait_idle(call)
    assert [r["outcome"] for r in s["results"]] == ["done", "done"] and s["counter_cents"] == 200
    assert any("the agent proposes" in l for l in s["log"])
    assert call("POST", "/api/pay", b)[0] == 400                                                         # the same nonces cannot be used twice


def test_freeze_from_the_page_denies_the_next_payment(web):
    app, call = web
    cid, _ = enroll_python(app, call)
    assert call("POST", "/api/freeze", {"scope": "all", "reason": "test"})[0] == 200
    assert call("GET", "/api/state")[1]["freezes"][0]["scope"] == "all"
    call("POST", "/api/pay", pay_body(app, call, cid))
    s = wait_idle(call)
    assert s["results"][0]["outcome"] == "denied" and s["counter_cents"] == 0
    call("POST", "/api/lift", {"scope": "all"})
    assert call("GET", "/api/state")[1]["freezes"] == []


def test_human_approval_box_gates_a_payment_at_the_auto_limit(web):
    app, call = web
    cid, _ = enroll_python(app, call)
    call("POST", "/api/pay", pay_body(app, call, cid, cents=200))                                        # $2.00 is not under the $2.00 auto limit
    for _ in range(100):
        if call("GET", "/api/state")[1]["approval"]:
            break
        time.sleep(0.1)
    assert call("GET", "/api/state")[1]["approval"] and call("GET", "/api/state")[1]["counter_cents"] == 0     # nothing paid while waiting
    call("POST", "/api/approve", {"decision": "approve"})
    s = wait_idle(call)
    assert s["results"][0]["outcome"] == "done" and s["counter_cents"] == 200


def test_rejecting_the_approval_stops_without_paying(web):
    app, call = web
    cid, _ = enroll_python(app, call)
    call("POST", "/api/pay", pay_body(app, call, cid, cents=200))
    for _ in range(100):
        if call("GET", "/api/state")[1]["approval"]:
            break
        time.sleep(0.1)
    call("POST", "/api/approve", {"decision": "reject"})
    s = wait_idle(call)
    assert s["results"][0]["outcome"] == "stopped" and s["counter_cents"] == 0


def test_cards_survive_a_restart_with_the_passphrase_and_not_without_it(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_POLICY", (ROOT / "config" / "policy.interview.json").read_text())
    monkeypatch.setattr(policy, "BUDGET_FILE", tmp_path / "b.json")
    import webapp
    a1 = webapp.App(budget_file=tmp_path / "b.json", data_dir=tmp_path, passphrase="correct horse")
    cid = a1.new_card_id()
    a1.enroll(cid, E.seal(bytes.fromhex(a1.attest()["pubkey"]), {"number": PAN, "exp_month": 12, "exp_year": 2030}, aad=cid.encode()))
    key_file = (tmp_path / "enclave_key.json").read_text()
    assert "private" not in key_file.lower() and PAN not in (tmp_path / "cards_web.json").read_text()
    a2 = webapp.App(budget_file=tmp_path / "b.json", data_dir=tmp_path, passphrase="correct horse")       # a "restart"
    assert a2.attest()["pubkey"] == a1.attest()["pubkey"] and a2.store.list_display()[0]["last4"] == "4242"
    assert a2.enc.enroll(a2.store.sealed(cid), cid)["last4"] == "4242"                                    # the restarted enclave can still open it
    with pytest.raises(E.EnclaveRefused, match="wrong passphrase"):
        webapp.App(budget_file=tmp_path / "b.json", data_dir=tmp_path, passphrase="wrong")


def mandate_body(app, call, cid, n=2, minutes=30, confirm="AUTHORIZE"):
    nonces = call("GET", f"/api/nonces?n={n}")[1]["nonces"]
    return {"card_id": cid, "count": n, "minutes": minutes, "cents": 100, "confirm": confirm, "nonces": nonces, "cvc_boxes": [{"x": i} for i in range(n)], "billing": BILL}


def test_mandate_needs_the_confirmation_and_valid_limits(web):
    app, call = web
    cid, _ = enroll_python(app, call)
    assert call("POST", "/api/mandate", mandate_body(app, call, cid, confirm="ok"))[0] == 400
    assert call("POST", "/api/mandate", mandate_body(app, call, cid, n=11))[0] == 400
    assert call("POST", "/api/mandate", mandate_body(app, call, cid, minutes=61))[0] == 400
    assert call("POST", "/api/agent/pay", {})[0] == 400                                                  # no mandate: the agent cannot pay


def test_agent_pays_with_no_inputs_until_the_mandate_is_used_up(web):
    app, call = web
    cid, _ = enroll_python(app, call)
    assert call("POST", "/api/mandate", mandate_body(app, call, cid, n=2))[0] == 200
    st = call("GET", "/api/state")[1]
    assert st["mandate"]["remaining"] == 2 and "cvc_boxes" not in json.dumps(st) and "boxes" not in st["mandate"]      # state never shows the boxes
    for k in (1, 0):
        assert call("POST", "/api/agent/pay", {})[0] == 200                                               # NO card, CVC or billing in this request
        s = wait_idle(call)
        assert s["results"][-1]["outcome"] == "done"
    assert call("POST", "/api/agent/pay", {})[0] == 400 and call("GET", "/api/state")[1]["mandate"] is None


def test_revoking_the_mandate_stops_the_agent_at_once(web):
    app, call = web
    cid, _ = enroll_python(app, call)
    call("POST", "/api/mandate", mandate_body(app, call, cid, n=3))
    call("POST", "/api/mandate/revoke", {})
    assert call("POST", "/api/agent/pay", {})[0] == 400 and app.mandate is None


def test_an_expired_mandate_cannot_be_used(web):
    app, call = web
    cid, _ = enroll_python(app, call)
    call("POST", "/api/mandate", mandate_body(app, call, cid, n=1))
    app.mandate["expires_at"] = time.time() - 1
    assert call("POST", "/api/agent/pay", {})[0] == 400


def test_a_freeze_still_stops_an_agent_that_holds_a_mandate(web):
    app, call = web
    cid, _ = enroll_python(app, call)
    call("POST", "/api/mandate", mandate_body(app, call, cid, n=2))
    call("POST", "/api/freeze", {"scope": "all", "reason": "stop"})
    assert call("POST", "/api/agent/pay", {})[0] == 200
    assert wait_idle(call)["results"][-1]["outcome"] == "denied" and call("GET", "/api/state")[1]["counter_cents"] == 0
