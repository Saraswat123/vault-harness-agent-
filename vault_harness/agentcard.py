"""Agentcard Vault REST client. Written from docs.agentcard.com/api-reference/vault/* (2026-10-28).

UNVERIFIED against the live sandbox: every shape below comes from the docs, not from a real response, because no
builder client_id/secret has been issued yet. The tests run against httpx.MockTransport fixtures built from the docs.

What the docs establish (and this client relies on):
  - One base URL; sandbox vs production is decided by the credential, never the host.
  - OAuth2 client-credentials, 1h bearer. An API key is refused (400 client_credentials_required).
  - A checkout authorization carries the CAPTURED processor request (url, method, headers, body). The user approves on
    their device with a passkey; the device decrypts the card and submits ("submitted_on_device"). The server never holds the PAN.
  - Idempotency is NOT documented for authorizations. This client therefore never retries a create. A generic failure does
    not prove "no charge": reconcile with get_authorization before trying again.
"""
import os
import time
from typing import Callable, Optional
from urllib.parse import urlparse

import httpx

BASE_URL = "https://api.agentcard.sh"


class AgentcardError(Exception):
    def __init__(self, status: int, code: str, message: str = "", body: Optional[dict] = None):
        super().__init__(f"{status} {code}: {message}"[:300])
        self.status, self.code, self.body = status, code, body or {}


def _err(r: httpx.Response) -> AgentcardError:
    try:
        b = r.json()
    except Exception:
        b = {}
    e = b.get("error", b) if isinstance(b, dict) else {}
    code = (e.get("code") if isinstance(e, dict) else e) or b.get("code") or "unknown_error"
    msg = (e.get("message") if isinstance(e, dict) else "") or b.get("message", "")
    return AgentcardError(r.status_code, str(code), str(msg), b if isinstance(b, dict) else {})


class AgentcardClient:
    def __init__(self, client_id: str = None, client_secret: str = None, base_url: str = None,
                 transport: httpx.BaseTransport = None, clock: Callable[[], float] = time.time):
        self._id = client_id or os.environ.get("AGENTCARD_CLIENT_ID", "")
        self._secret = client_secret or os.environ.get("AGENTCARD_CLIENT_SECRET", "")
        if not self._id or not self._secret:
            raise RuntimeError("AGENTCARD_CLIENT_ID / AGENTCARD_CLIENT_SECRET not set (put them in .env, never in chat)")
        self._http = httpx.Client(base_url=base_url or os.environ.get("AGENTCARD_BASE_URL", BASE_URL), timeout=30, transport=transport)
        self._clock = clock
        self._tok, self._exp = None, 0.0

    def __repr__(self):                              # never print the secret or a token
        return f"AgentcardClient(client_id={self._id[:4]}…, token={'set' if self._tok else 'none'})"

    # --- auth: POST /api/v2/oauth/token, form body, 1h bearer, no refresh. 30 req / 5 min / IP, so cache. ---
    def _token(self, force: bool = False) -> str:
        if not force and self._tok and self._clock() < self._exp - 60:
            return self._tok
        r = self._http.post("/api/v2/oauth/token", data={"grant_type": "client_credentials",
                                                           "client_id": self._id, "client_secret": self._secret})
        if r.status_code != 200:
            raise _err(r)
        j = r.json()
        self._tok, self._exp = j["access_token"], self._clock() + int(j.get("expires_in", 3600))
        return self._tok

    def _req(self, method: str, path: str, **kw) -> dict:
        for attempt in (0, 1):
            r = self._http.request(method, path, headers={"Authorization": f"Bearer {self._token(force=bool(attempt))}"}, **kw)
            if r.status_code == 401 and attempt == 0:
                continue                             # token expired server-side: 401 means not processed, safe to retry once
            if r.status_code >= 400:
                raise _err(r)
            return r.json()

    # --- vault sessions (card save) ---
    def create_vault_session(self, user_id: str = None, external_user_id: str = None, steps: list = None,
                             expires_in: int = None, approval_mode: str = "customer") -> dict:
        if approval_mode not in ("customer", "partner"):
            raise ValueError("approval_mode must be customer or partner")
        body = {k: v for k, v in dict(user_id=user_id, external_user_id=external_user_id, steps=steps,
                                      expires_in=expires_in, approval_mode=approval_mode).items() if v is not None}
        if expires_in is not None and not 60 <= expires_in <= 172800:
            raise ValueError("expires_in must be 60..172800 seconds")
        return self._req("POST", "/api/v2/vault_sessions", json=body)

    def get_vault_session(self, session_id: str) -> dict:     # use the vs_ id, not the token in url
        return self._req("GET", f"/api/v2/vault_sessions/{session_id}")

    def list_vault_cards(self, user_id: str) -> list:
        """Display fields only (brand, last4, expiry). The API never returns a PAN; we assert that again."""
        cards = self._req("GET", "/api/v2/vault_cards", params={"user_id": user_id}).get("data", [])
        for c in cards:
            if any(k in c for k in ("number", "pan", "card_number", "cvc", "cvv")):
                raise AgentcardError(502, "pan_in_response", "refusing a response that carries card-number fields")
        return cards

    def disconnect_user(self, user_id: str) -> dict:
        return self._req("DELETE", f"/api/v2/vault_users/{user_id}/connection")

    # --- checkout authorizations (pay) ---
    def create_authorization(self, *, user: str, merchant: str, psp: str, request: dict, amount: int, currency: str,
                             checkout_origin: str, card_id: str = None, mode: str = "token") -> dict:
        """NEVER retried by this client: idempotency is undocumented (see module docstring)."""
        u = urlparse(checkout_origin)
        if u.scheme != "https" or u.path not in ("", "/") or u.port or checkout_origin != checkout_origin.lower() or checkout_origin.endswith("/"):
            raise ValueError("checkout_origin must be https://lowercase-host with no path, trailing slash or port")
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise ValueError("amount must be a positive integer in the smallest currency unit")
        if len(merchant) > 120:
            raise ValueError("merchant is limited to 120 characters")
        if not {"url", "method", "headers", "body"} <= set(request):
            raise ValueError("request needs url, method, headers, body")
        body = {"user": user, "merchant": merchant, "psp": psp.lower(), "mode": mode, "request": request,
                "amount": amount, "currency": currency.lower(), "checkout_origin": checkout_origin}
        if card_id:
            body["card_id"] = card_id
        r = self._http.post("/api/v2/checkout/authorizations", json=body,
                            headers={"Authorization": f"Bearer {self._token()}"})
        if r.status_code >= 400:
            raise _err(r)
        return r.json()

    def get_authorization(self, auth_id: str) -> dict:
        return self._req("GET", f"/api/v2/checkout/authorizations/{auth_id}")

    def cancel_authorization(self, auth_id: str) -> dict:     # idempotent; 409 outcome_unknown once the device started sending
        return self._req("POST", f"/api/v2/checkout/authorizations/{auth_id}/cancel", json={})

    def wait_for_authorization(self, auth_id: str, timeout: float = 900, sleep: Callable[[float], None] = time.sleep) -> dict:
        """Poll no faster than poll_interval_ms (else 400 slow_down). Authorizations expire after 15 min."""
        deadline = self._clock() + timeout
        while True:
            a = self.get_authorization(auth_id)
            if a.get("status") != "awaiting_approval":
                return a
            if self._clock() >= deadline:
                return a
            sleep(max(a.get("poll_interval_ms", 2000), 1000) / 1000)


def reconcile(auth: dict, intent) -> Optional[str]:
    """Problem string or None. Checks what Agentcard says happened against what WE approved. Never trust the step's own claim."""
    st = auth.get("status")
    if st in ("declined", "expired"):
        return None if (auth.get("settlement") or {}).get("status") in (None, "not_settled") else "declined/expired but settlement says otherwise"
    s = auth.get("settlement") or {}
    if s.get("status") != "settled" or not s.get("final"):
        return f"not settled (status={s.get('status')!r}, final={s.get('final')!r}); do not retry until resolved"
    if s.get("settled_amount") != intent.amount_cents:
        return f"settled {s.get('settled_amount')} but approved {intent.amount_cents}"
    if (auth.get("currency") or "").lower() != intent.currency:
        return "currency differs from the approved intent"
    if auth.get("amount_verified") is False:
        return "amount was not verified by the processor"
    return None
