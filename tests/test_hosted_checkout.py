"""Hosted-checkout path. Unit tests are offline. The live test uses a LOCAL stand-in checkout page in a real Kernel browser and Stripe TEST mode
(pk_test key, 4242 card): it proves interception -> enclave swap -> real Stripe reply -> page success, with no real money."""
import json
import os
import re

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vault_harness import enclave as E
from vault_harness.cardstore import CardStore
from vault_harness.hosted_checkout import ForwardProcessor, HostedCheckoutVault, fulfill_headers
from vault_harness.policy import Intent

PAN = "4242424242424242"
RAW = E._RAW
I = Intent("buy.stripe.com", 100, "usd")


def enc(processor, paths=("/v1/payment_methods",)):
    u, p = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    return E.MockEnclave(user_pub=u.public_key().public_bytes(*RAW), policy_pub=p.public_key().public_bytes(*RAW), processor=processor,
                         auto_limit_cents=200, allowed_paths=paths), u, p


def req(ph, **over):
    pairs = {"type": "card", "card[number]": ph.number[:4] + " " + ph.number[4:8] + " " + ph.number[8:12] + " " + ph.number[12:], "card[cvc]": ph.cvc,
             "card[exp_month]": ph.exp_month, "card[exp_year]": ph.exp_year[-2:], "billing_details[name]": "A B", "key": "pk_live_x"}
    pairs.update(over)
    from urllib.parse import urlencode
    return {"url": "https://api.stripe.com/v1/payment_methods", "method": "POST", "headers": {"content-type": "application/x-www-form-urlencoded"}, "body": urlencode(pairs)}


def do(e, u, p, request_fn=req, mode="forward"):
    ph = e.issue_placeholder(I)
    sealed = E.seal(bytes.fromhex(e.attest()["pubkey"]), {"number": PAN, "exp_month": 12, "exp_year": 2030, "cvc": "123"})
    ap = {"signer": "policy", "sig": p.sign(E.approval_message(I, ph.token)).hex()}
    return ph, e.pay(sealed=sealed, placeholder=ph, intent=I, request=request_fn(ph), approval=ap, mode=mode)


def test_forward_swaps_a_formatted_two_digit_year_request_and_returns_the_reply_only():
    seen = []

    def proc(r):
        seen.append(r)
        return {"status": 200, "raw": json.dumps({"id": "pm_1", "card": {"last4": "4242", "brand": "visa"}}), "ctype": "application/json"}
    e, u, p = enc(proc)
    ph, out = do(e, u, p)
    body = seen[0]["body"]
    assert out["status"] == "forwarded" and json.loads(out["body"])["id"] == "pm_1" and PAN not in out["body"]
    assert f"card[number]={PAN}" in body and "card[exp_year]=30" in body and "card[exp_month]=12" in body and "card[cvc]=123" in body
    assert ph.number not in body and "pk_live_x" in body                       # the page's own publishable key is forwarded untouched


def test_forward_refuses_any_path_other_than_payment_methods():
    e, u, p = enc(lambda r: {"status": 200, "raw": "{}"})
    with pytest.raises(E.EnclaveRefused, match="path"):
        do(e, u, p, request_fn=lambda ph: {**req(ph), "url": "https://api.stripe.com/v1/charges"})


def test_forward_withholds_a_reply_that_carries_card_digits():
    e, u, p = enc(lambda r: {"status": 200, "raw": json.dumps({"echo": PAN}), "ctype": "application/json"})
    assert do(e, u, p)[1]["status"] == "refused"


def test_forward_still_requires_the_placeholder_in_the_request():
    e, u, p = enc(lambda r: {"status": 200, "raw": "{}"})
    with pytest.raises(E.EnclaveRefused, match="does not carry"):
        do(e, u, p, request_fn=lambda ph: req(ph, **{"card[number]": "4000000000000002"}))


def test_forward_processor_sends_only_whitelisted_headers():
    seen = []
    t = httpx.MockTransport(lambda r: (seen.append(r), httpx.Response(200, json={"id": "pm_x"}))[1])
    out = ForwardProcessor(t)({"url": "https://api.stripe.com/v1/payment_methods", "method": "POST", "body": "a=b",
                               "headers": {"content-type": "application/x-www-form-urlencoded", "cookie": "secret", "authorization": "Bearer x"}})
    assert out["status"] == 200 and "cookie" not in seen[0].headers and "authorization" not in seen[0].headers


def test_cors_reply_headers_echo_the_page_origin():
    h = fulfill_headers("https://buy.stripe.com", "application/json")
    assert h["access-control-allow-origin"] == "https://buy.stripe.com" and h["vary"] == "Origin"


def test_placeholder_is_visa_shaped_with_a_near_future_expiry():
    e, u, p = enc(lambda r: {})
    ph = e.issue_placeholder(I)
    assert ph.number.startswith("4") and len(ph.number) == 16 and ph.number != PAN and 2026 <= int(ph.exp_year) <= 2032 and len(ph.cvc) == 3


# ---------------- live: local stand-in checkout, REAL Stripe TEST mode ----------------
def _pk():
    """Read straight from .env: the autouse fixture hides keys from vault_harness.stripe_processor so unit tests stay hermetic."""
    from pathlib import Path
    f = Path(__file__).resolve().parent.parent / ".env"
    return dict(l.split("=", 1) for l in f.read_text().splitlines() if "=" in l).get("STRIPE_PUBLISHABLE_KEY", "").strip() if f.is_file() else ""


live = pytest.mark.skipif(not os.environ.get("RUN_LIVE"), reason="set RUN_LIVE=1 (real Kernel browser + Stripe TEST mode)")

PAGE = """<html><body><div>Total due $1.00</div>
<input id=email><input id=cardNumber><input id=cardExpiry><input id=cardCvc><input id=billingName>
<button class=SubmitButton onclick="pay()">Pay</button><div id=out></div>
<script>
async function pay(){
 const [mm,yy]=cardExpiry.value.split('/');
 const body=new URLSearchParams({'type':'card','card[number]':cardNumber.value.replace(/\\s/g,''),'card[cvc]':cardCvc.value,'card[exp_month]':mm.trim(),'card[exp_year]':yy.trim(),'billing_details[name]':billingName.value,'key':'__PK__'});
 const r=await fetch('https://api.stripe.com/v1/payment_methods',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body});
 const j=await r.json(); out.textContent = j.id ? 'Thank you '+j.id+' '+((j.card||{}).last4) : 'error '+((j.error||{}).message);
}
</script></body></html>"""


@live
def test_live_forward_path_end_to_end_in_stripe_test_mode(tmp_path):
    pk = _pk()
    if not pk or not pk.startswith("pk_test_"):
        pytest.skip("needs STRIPE_PUBLISHABLE_KEY=pk_test_… in .env")
    e, u, p = enc(ForwardProcessor())
    v = HostedCheckoutVault(e, checkout_url="https://checkout-rehearsal.test/", page_html=PAGE.replace("__PK__", pk), user_key=u, policy_key=p,
                            card_store=CardStore(tmp_path / "c.json"), cvc_source=lambda: "123", auto_limit_cents=200, make_browser=None, make_page=None,
                            billing={"email": "t@example.com", "name": "Test User", "country": "US", "zip": "94107"}, say=lambda m: None)
    v.enroll({"number": PAN, "exp_month": 12, "exp_year": 2030})
    out = v.pay(e.issue_placeholder(I), I)
    assert out["status"] == "done" and out["charge_id"].startswith("pm_") and out["card_last4"] == "4242"
    assert PAN not in repr(out) and PAN not in json.dumps(v.last)


def test_link_login_prompt_is_recognised():
    from vault_harness.hosted_checkout import LINK_CODE
    assert LINK_CODE.search("Confirm it\u2019s you Enter the code sent to a@b.co to use your saved information. Resend code")
    assert not LINK_CODE.search("Perflo Pay Test Product Total due $1.00 Pay")
