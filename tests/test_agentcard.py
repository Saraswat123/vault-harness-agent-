"""Agentcard client against fixtures shaped from docs.agentcard.com. These prove OUR client logic, not the live API."""
import json

import httpx
import pytest

from vault_harness import agentcard
from vault_harness.agentcard import AgentcardClient, AgentcardError, reconcile
from vault_harness.policy import Intent

REQ = {"url": "https://api.stripe.com/v1/tokens", "method": "POST", "headers": {"content-type": "application/x-www-form-urlencoded"}, "body": "card[number]=PLACEHOLDER"}
I = Intent("shop.agentcard.sh", 100, "usd")


def client(handler, clock=None):
    calls = []

    def h(req):
        calls.append(req)
        if req.url.path == "/api/v2/oauth/token":
            return httpx.Response(200, json={"access_token": "tok_" + str(len([c for c in calls if c.url.path.endswith("token")])), "token_type": "Bearer", "expires_in": 3600, "scope": "api"})
        return handler(req)

    return AgentcardClient("cid_test", "secret_test", transport=httpx.MockTransport(h), clock=clock or (lambda: 1000.0)), calls


def test_token_is_cached_and_secret_never_printed():
    c, calls = client(lambda r: httpx.Response(200, json={"data": []}))
    c.list_vault_cards("usr_1"); c.list_vault_cards("usr_1")
    assert len([x for x in calls if x.url.path.endswith("/token")]) == 1
    assert "secret_test" not in repr(c) and "tok_1" not in repr(c)


def test_token_reminted_after_expiry():
    t = [1000.0]
    c, calls = client(lambda r: httpx.Response(200, json={"data": []}), clock=lambda: t[0])
    c.list_vault_cards("u"); t[0] += 3600
    c.list_vault_cards("u")
    assert len([x for x in calls if x.url.path.endswith("/token")]) == 2


def test_401_triggers_one_remint_then_succeeds():
    n = {"i": 0}

    def h(r):
        n["i"] += 1
        return httpx.Response(401, json={"error": {"code": "invalid_token"}}) if n["i"] == 1 else httpx.Response(200, json={"data": []})
    c, calls = client(h)
    assert c.list_vault_cards("u") == []
    assert len([x for x in calls if x.url.path.endswith("/token")]) == 2


def test_vault_session_body_and_validation():
    c, calls = client(lambda r: httpx.Response(201, json={"id": "vs_1", "url": "https://vault.agentcard.sh/v?vs=vs_1.x", "poll_interval": 3}))
    c.create_vault_session(external_user_id="u-42", expires_in=3600)
    body = json.loads(calls[-1].content)
    assert body == {"external_user_id": "u-42", "expires_in": 3600, "approval_mode": "customer"}   # default is customer: never auto-pay
    with pytest.raises(ValueError):
        c.create_vault_session(expires_in=5)
    with pytest.raises(ValueError):
        c.create_vault_session(approval_mode="auto")


def test_partner_mode_403_surfaces_as_error():
    c, _ = client(lambda r: httpx.Response(403, json={"error": {"code": "partner_enrollment_disabled", "message": "sandbox"}}))
    with pytest.raises(AgentcardError) as e:
        c.create_vault_session(approval_mode="partner")
    assert e.value.status == 403 and e.value.code == "partner_enrollment_disabled"


def test_card_list_refuses_a_response_that_carries_a_pan():
    c, _ = client(lambda r: httpx.Response(200, json={"data": [{"id": "vc_1", "brand": "visa", "last4": "4242", "number": "4242424242424242"}]}))
    with pytest.raises(AgentcardError) as e:
        c.list_vault_cards("u")
    assert e.value.code == "pan_in_response"


def test_card_list_normal():
    c, _ = client(lambda r: httpx.Response(200, json={"data": [{"id": "vc_1", "brand": "visa", "last4": "4242", "expiry_month": 12, "expiry_year": 2030}]}))
    assert c.list_vault_cards("u")[0]["last4"] == "4242"


@pytest.mark.parametrize("origin", ["http://shop.example.com", "https://shop.example.com/", "https://Shop.example.com", "https://shop.example.com:443", "https://shop.example.com/pay"])
def test_bad_checkout_origin_rejected_before_any_request(origin):
    c, calls = client(lambda r: httpx.Response(201, json={}))
    with pytest.raises(ValueError):
        c.create_authorization(user="u", merchant="m", psp="stripe", request=REQ, amount=100, currency="USD", checkout_origin=origin)
    assert not [x for x in calls if "authorizations" in x.url.path]


def test_authorization_body_and_no_retry_on_failure():
    c, calls = client(lambda r: httpx.Response(502, json={"error": {"code": "amount_unverifiable"}}))
    with pytest.raises(AgentcardError) as e:
        c.create_authorization(user="usr_1", merchant="shop.agentcard.sh", psp="Stripe", request=REQ, amount=100, currency="USD", checkout_origin="https://shop.agentcard.sh")
    posts = [x for x in calls if "authorizations" in x.url.path]
    assert len(posts) == 1 and e.value.code == "amount_unverifiable"       # exactly one attempt: create is never retried
    b = json.loads(posts[0].content)
    assert b["psp"] == "stripe" and b["currency"] == "usd" and b["amount"] == 100 and b["request"] == REQ


@pytest.mark.parametrize("amt", [0, -1, 1.5, True, "100"])
def test_bad_amount_rejected(amt):
    c, _ = client(lambda r: httpx.Response(201, json={}))
    with pytest.raises(ValueError):
        c.create_authorization(user="u", merchant="m", psp="stripe", request=REQ, amount=amt, currency="usd", checkout_origin="https://a.com")


def test_amount_mismatch_409_is_visible():
    c, _ = client(lambda r: httpx.Response(409, json={"error": {"code": "amount_mismatch"}, "expected_cents": 100, "actual_cents": 9999}))
    with pytest.raises(AgentcardError) as e:
        c.create_authorization(user="u", merchant="m", psp="stripe", request=REQ, amount=100, currency="usd", checkout_origin="https://a.com")
    assert e.value.code == "amount_mismatch" and e.value.body["actual_cents"] == 9999


def test_preset_refusal_403_is_visible():
    c, _ = client(lambda r: httpx.Response(403, json={"error": {"code": "merchant_denied"}, "stage": "create"}))
    with pytest.raises(AgentcardError) as e:
        c.create_authorization(user="u", merchant="m", psp="stripe", request=REQ, amount=100, currency="usd", checkout_origin="https://a.com")
    assert e.value.code == "merchant_denied"


def test_wait_polls_at_the_server_interval_then_returns_final():
    seq = iter([{"status": "awaiting_approval", "poll_interval_ms": 2000}, {"status": "awaiting_approval", "poll_interval_ms": 2000}, {"status": "approved"}])
    c, _ = client(lambda r: httpx.Response(200, json=next(seq)))
    slept = []
    assert c.wait_for_authorization("cauth_1", sleep=slept.append)["status"] == "approved"
    assert slept == [2.0, 2.0]


def test_wait_gives_up_at_the_deadline_without_cancelling():
    t = [0.0]
    c, calls = client(lambda r: httpx.Response(200, json={"status": "awaiting_approval", "poll_interval_ms": 1000}), clock=lambda: t[0])
    a = c.wait_for_authorization("cauth_1", timeout=3, sleep=lambda s: t.__setitem__(0, t[0] + s))
    assert a["status"] == "awaiting_approval" and not [x for x in calls if x.url.path.endswith("/cancel")]


def test_cancel_conflict_when_device_already_sending():
    c, _ = client(lambda r: httpx.Response(409, json={"error": {"code": "outcome_unknown"}}))
    with pytest.raises(AgentcardError) as e:
        c.cancel_authorization("cauth_1")
    assert e.value.code == "outcome_unknown"


SETTLED = {"status": "approved", "currency": "usd", "amount_verified": True,
           "settlement": {"status": "settled", "final": True, "settled_amount": 100, "processor_reference": "ch_3Qxample"}}


def test_reconcile_accepts_a_matching_settlement():
    assert reconcile(SETTLED, I) is None


@pytest.mark.parametrize("patch,needle", [
    ({"settlement": {"status": "settled", "final": True, "settled_amount": 9999}}, "settled 9999"),
    ({"settlement": {"status": "unknown", "final": False, "reason": "check_pending"}}, "not settled"),
    ({"settlement": {"status": "settled", "final": False, "settled_amount": 100}}, "not settled"),
    ({"currency": "eur"}, "currency"),
    ({"amount_verified": False}, "not verified"),
    ({"settlement": None}, "not settled"),
])
def test_reconcile_catches_what_the_step_would_not(patch, needle):
    assert needle in reconcile({**SETTLED, **patch}, I)


def test_declined_with_no_charge_is_clean():
    assert reconcile({"status": "declined", "settlement": None}, I) is None
