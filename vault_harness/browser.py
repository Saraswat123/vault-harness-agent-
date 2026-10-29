"""Stateless Kernel browser for the checkout step.

Stateless by construction, and verified on a real Kernel session (2026-10-28 probe):
  - every session is created with NO profile and NO vaults, so nothing is loaded in and nothing is saved back
  - one session per payment, deleted in `finally` (a session bills until deleted; timeout_seconds is only the backstop)
The agent's hands are code here: the page is driven by fixed Playwright snippets, and the cart total is READ from the DOM by
code, not decided by a model. The browser only ever types the placeholder, then the request is captured and handed to the enclave.
"""
import json
import os
from pathlib import Path
from typing import Optional

import httpx

KERNEL = "https://api.onkernel.com"
FORBIDDEN_CREATE_KEYS = {"profile", "vaults", "pool", "extensions", "proxy"}      # anything that could carry state or identity in


def _api_key() -> str:
    k = os.environ.get("KERNEL_API_KEY")
    if not k:
        f = Path(__file__).resolve().parent.parent / ".env"
        if f.is_file():
            k = dict(l.split("=", 1) for l in f.read_text().splitlines() if "=" in l and not l.startswith("#")).get("KERNEL_API_KEY")
    if not k:
        raise RuntimeError("KERNEL_API_KEY not set (put it in .env)")
    return k.strip()


class KernelSession:
    def __init__(self, api_key: str = None, transport: httpx.BaseTransport = None, timeout_seconds: int = 120, name: str = None, headless: bool = True):
        self._http = httpx.Client(base_url=KERNEL, timeout=90, transport=transport,
                                  headers={"Authorization": f"Bearer {api_key or _api_key()}", "Content-Type": "application/json"})
        self._timeout, self._headless = timeout_seconds, headless
        self._name = f"{name}-{os.urandom(3).hex()}" if name else None      # Kernel session names must be unique among active sessions
        self.cdp_ws_url, self.live_view_url = None, None
        self.session_id: Optional[str] = None
        self.deleted = False

    def __repr__(self):
        return f"KernelSession(id={self.session_id}, deleted={self.deleted})"

    def __enter__(self):
        body = {"headless": self._headless, "timeout_seconds": self._timeout}
        if self._name:
            body["name"] = self._name
        assert not (FORBIDDEN_CREATE_KEYS & set(body)), "a payment browser must not load a profile, vault, pool or proxy"
        r = self._http.post("/browsers", json=body)
        r.raise_for_status()
        j = r.json()
        self.session_id, self.cdp_ws_url, self.live_view_url = j["session_id"], j.get("cdp_ws_url"), j.get("browser_live_view_url")
        return self

    def __exit__(self, *exc):
        if self.session_id and not self.deleted:
            try:
                self._http.delete(f"/browsers/{self.session_id}").raise_for_status()
                self.deleted = True
            except Exception:
                pass                                            # the timeout backstop will end it; never mask the original error
        self._http.close()
        return False

    def run(self, code: str, timeout_sec: int = 45) -> str:
        r = self._http.post(f"/browsers/{self.session_id}/playwright/execute", json={"code": code, "timeout_sec": timeout_sec})
        r.raise_for_status()
        j = r.json()
        if not j.get("success"):
            raise RuntimeError(f"playwright error: {str(j.get('error'))[:300]}")
        return j["result"]

    def storage_snapshot(self) -> dict:
        """Cookies and web storage visible to the current page. Used by tests to prove a fresh session starts empty."""
        return json.loads(self.run("""
            await page.goto('https://example.com');
            const cookies = await context.cookies();
            const st = await page.evaluate(() => ({ls: Object.keys(localStorage), ss: Object.keys(sessionStorage)}));
            return JSON.stringify({cookies: cookies.map(c => c.name), local: st.ls, session: st.ss});
        """))

    def capture_checkout(self, html: str, placeholder, pay_url_host: str = "api.stripe.com") -> dict:
        """Load a checkout page, read the total from the DOM (#total[data-cents]), type ONLY the placeholder, submit, and return the
        captured processor request. The request is fulfilled locally with a stub so nothing real is sent from the browser."""
        code = f"""
            const captured = [];
            const p = await context.newPage();      // blank tab: the default start page carries a strict CSP that blocks fetch
            await p.route('https://{pay_url_host}/**', async route => {{
              const r = route.request();
              captured.push({{url: r.url(), method: r.method(), headers: r.headers(), body: r.postData() || ''}});
              await route.fulfill({{status: 200, contentType: 'application/json', headers: {{'access-control-allow-origin': '*'}}, body: '{{"stub":true}}'}});
            }});
            await p.setContent({json.dumps(html)});
            const total = await p.$eval('#total', el => el.dataset.cents);
            await p.fill('#number', {json.dumps(placeholder.number)});
            await p.fill('#exp_month', {json.dumps(placeholder.exp_month)});
            await p.fill('#exp_year', {json.dumps(placeholder.exp_year)});
            await p.fill('#cvc', {json.dumps(placeholder.cvc)});
            await p.click('#pay');
            await p.waitForTimeout(800);
            await p.close();
            return JSON.stringify({{total_cents: parseInt(total, 10), request: captured[0] || null}});
        """
        out = json.loads(self.run(code))
        if not out["request"]:
            raise RuntimeError("checkout did not issue a processor request")
        return out


def checkout_page(total_cents: int, form_amount_cents: Optional[int] = None, attack_text: str = "") -> str:
    """A tiny test checkout. `form_amount_cents` lets a test make the page lie (show one total, submit another)."""
    amt = total_cents if form_amount_cents is None else form_amount_cents
    return f"""<html><body>
<div id="total" data-cents="{total_cents}">Total ${total_cents/100:.2f}</div>
<p>{attack_text}</p>
<input id="number"><input id="exp_month"><input id="exp_year"><input id="cvc">
<button id="pay" onclick="pay()">Pay</button>
<script>
function pay() {{
  const b = 'card[number]=' + number.value + '&card[cvc]=' + cvc.value + '&card[exp_month]=' + exp_month.value +
            '&card[exp_year]=' + exp_year.value + '&type=card&amount={amt}';
  fetch('https://api.stripe.com/v1/payment_methods', {{method: 'POST', headers: {{'content-type': 'application/x-www-form-urlencoded'}}, body: b}});
}}
</script></body></html>"""
