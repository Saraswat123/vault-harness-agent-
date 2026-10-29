"""Stripe processor for the enclave. TEST MODE ONLY: a live key is refused in code, not by convention.

Runs inside the trust boundary (the enclave, in the real build). Receives the captured request after the card swap and:
  1. replays the card fields to POST /v1/tokens with the PUBLISHABLE key when set (Stripe refuses raw card numbers with a secret key) (the browser's own headers are NOT forwarded)
  2. creates a charge for the APPROVED amount (from meta, never from the page) with an idempotency key
Returns only {id, status, amount, last4}. Stripe error text is length-capped and card-number-redacted.
NOTE: Stripe test accounts may refuse raw card numbers until 'handle card information directly' is enabled; the error says so.
"""
import os
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode

import httpx

from vault_harness.policy import redact

API = "https://api.stripe.com"


def _env(name: str):
    k = os.environ.get(name)
    f = Path(__file__).resolve().parent.parent / ".env"
    if not k and f.is_file():
        k = dict(l.split("=", 1) for l in f.read_text().splitlines() if "=" in l and not l.startswith("#")).get(name)
    return k.strip() if k else None


def load_test_key() -> str:
    k = _env("STRIPE_TEST_KEY")
    if not k:
        raise RuntimeError("STRIPE_TEST_KEY not set (a Stripe TEST-mode secret or restricted key, sk_test_/rk_test_..., in .env)")
    return k


class StripeTestProcessor:
    def __init__(self, key: str = None, transport: httpx.BaseTransport = None, publishable: str = None):
        key = key or load_test_key()
        if not re.match(r"^(sk|rk)_test_[A-Za-z0-9]+$", key):
            raise ValueError("refusing a non-test Stripe key: this processor only runs in test mode")
        pk = publishable or _env("STRIPE_PUBLISHABLE_KEY")
        if pk and not re.match(r"^pk_test_[A-Za-z0-9]+$", pk):
            raise ValueError("refusing a non-test publishable key: this processor only runs in test mode")
        self._key, self._pk = key, pk       # tokenise with the publishable key (how Stripe.js does it); charge with the server key
        self._http = httpx.Client(base_url=API, timeout=30, transport=transport)

    def __repr__(self):
        return "StripeTestProcessor(test-mode)"

    def __call__(self, req: dict) -> dict:
        meta = req["meta"]
        form = [(k, v) for k, v in parse_qsl(req["body"], keep_blank_values=True) if k != "amount"]     # PaymentMethods rejects unknown params
        if not any(k == "type" for k, _ in form):
            form.append(("type", "card"))
        auth = {"Authorization": f"Bearer {self._key}"}
        pm_auth = {"Authorization": f"Bearer {self._pk or self._key}"}
        r = self._http.post("/v1/payment_methods", content=urlencode(form), headers={**pm_auth, "Content-Type": "application/x-www-form-urlencoded"})
        if r.status_code != 200:
            return self._err(r)
        pm = r.json()
        c = self._http.post("/v1/payment_intents", headers={**auth, "Idempotency-Key": meta["idempotency_key"]}, data={
            "amount": meta["amount_cents"], "currency": meta["currency"], "payment_method": pm["id"], "confirm": "true",
            "automatic_payment_methods[enabled]": "true", "automatic_payment_methods[allow_redirects]": "never",
            "description": "vault-harness test payment"})
        if c.status_code != 200:
            return self._err(c)
        pi = c.json()
        if pi.get("livemode"):
            return {"status": 500, "json": {"error": "livemode payment returned by a test processor; stopping"}}
        return {"status": 200, "json": {"id": pi["id"], "status": pi["status"], "amount": pi.get("amount_received", pi["amount"]),
                                        "last4": (pm.get("card") or {}).get("last4")}}

    def get_payment(self, pi_id: str) -> dict:
        """Independent read-back for reconciliation (does the processor agree with what we were told?)."""
        r = self._http.get(f"/v1/payment_intents/{pi_id}", headers={"Authorization": f"Bearer {self._key}"})
        r.raise_for_status()
        return r.json()

    @staticmethod
    def _err(r: httpx.Response) -> dict:
        try:
            msg = r.json().get("error", {}).get("message", "")
        except Exception:
            msg = ""
        return {"status": r.status_code, "json": {"error": redact(msg)[:400] or f"stripe http {r.status_code}"}}
