"""Hosted-checkout payments (Stripe Checkout / Payment Links) through the enclave.

How it works (the same idea as Agentcard's "tokenization request pauses"):
  1. A fresh Kernel browser (headful, no profile) opens the checkout page. Code reads the total from the page.
  2. The browser types ONLY a placeholder card. Stripe's own page JS then sends POST api.stripe.com/v1/payment_methods.
  3. We intercept that one request over CDP (local Playwright), hand it to the enclave. The enclave opens the stored ciphertext card,
     swaps the real card in, sends the request to Stripe, and returns Stripe's reply (a PaymentMethod id; card.last4 only).
  4. We give that reply back to the page. The page carries on and confirms the payment with the PaymentMethod id. It never saw a card.
Nothing here defeats bot protection: if a captcha challenge appears, a human solves it in the live view.
UNVERIFIED until run against the real page; capture_only=True stops before anything reaches Stripe's PaymentMethod API.
"""
import json
import re
from typing import Callable, Optional

import httpx

from vault_harness import enclave as E
from vault_harness.browser import KernelSession
from vault_harness.forward import ForwardProcessor  # noqa: F401  (re-exported; lives in its own module so the enclave image stays small)
from vault_harness.enclave_vault import EnclaveVault
from vault_harness.policy import Intent

LINK_CODE = re.compile(r"(enter the code sent to|confirm it.?s you|logging in as)", re.I)          # Stripe Link asking for an emailed one-time code
PM_URL = re.compile(r"^https://api\.stripe\.com/v1/payment_methods(\?.*)?$")
SUCCESS = re.compile(r"(thank you|thanks for|payment (was )?successful|successfully paid|payment complete|you.?re all set|paid)", re.I)


def fulfill_headers(origin: str, ctype: str) -> dict:
    return {"content-type": ctype, "access-control-allow-origin": origin, "access-control-allow-credentials": "true", "vary": "Origin"}


def drive(cdp_url: str, url: str, billing: dict, ph: E.Placeholder, total_cents: int, on_tokenize: Callable[[dict], Optional[dict]],
          say: Callable[[str], None] = print, wait_s: int = 90, html: str = None) -> dict:
    from playwright.sync_api import sync_playwright
    st = {"calls": 0, "pm_id": None, "last4": None, "aborted": None, "success": False}
    with sync_playwright() as pw:
        br = pw.chromium.connect_over_cdp(cdp_url)
        ctx = br.contexts[0]
        page = ctx.pages[0] if ctx.pages else ctx.new_page()

        def handler(route):
            req = route.request
            if req.method != "POST":                                     # preflight and anything else go straight to Stripe
                return route.continue_()
            st["calls"] += 1
            captured = {"url": req.url.split("?")[0], "method": "POST", "body": req.post_data or "",
                        "headers": {k: v for k, v in req.headers.items() if k.lower() in ("content-type", "accept", "accept-language", "user-agent")}}
            res = on_tokenize(captured)
            if not res or res.get("status") != "forwarded":
                st["aborted"] = (res or {}).get("reason", "blocked")
                return route.abort()
            try:
                j = json.loads(res["body"])
                st["pm_id"], st["last4"] = j.get("id"), (j.get("card") or {}).get("last4")
            except Exception:
                pass
            route.fulfill(status=res["http_status"], headers=fulfill_headers(req.headers.get("origin", "https://buy.stripe.com"), res["content_type"]), body=res["body"])

        ctx.route(PM_URL, handler)
        if html:                                                           # rehearsal: serve a local stand-in checkout at `url`
            ctx.route(url, lambda r: r.fulfill(status=200, content_type="text/html", body=html))
        for attempt in range(3):                                         # loading through a cloud browser is flaky; retry the LOAD only (nothing typed yet)
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=45000)
                page.wait_for_selector("#cardNumber", timeout=30000)
                break
            except Exception:
                if attempt == 2:
                    raise
                say(f"checkout page did not load (attempt {attempt + 1}/3); retrying")
        shown, text, tries = None, "", 0
        for _ in range(40):                                              # the total renders after the card field; wait for it
            text = page.inner_text("body")
            m = re.search(r"Total due[^$]{0,40}\$([\d,]+\.\d\d)", text)
            if m:
                shown = int(round(float(m.group(1).replace(",", "")) * 100)); break
            if "Choose currency" in text and tries < 8 and _ % 3 == 0:    # adaptive pricing showed another currency: pick USD, never trust it
                tries += 1
                for loc in (page.get_by_role("radio", name=re.compile(r"USD|\$")), page.get_by_text(re.compile(r"^\$\d+\.\d\d$"))):
                    try:
                        if loc.count():
                            loc.first.click(timeout=3000); break
                    except Exception:
                        continue
            page.wait_for_timeout(500)
        if shown != total_cents:
            return {**st, "error": f"page total {shown} != approved {total_cents}", "snippet": re.sub(r"\s+", " ", text)[:200]}
        say(f"page total ${shown/100:.2f} matches the approved amount")
        page.fill("#email", billing["email"])
        page.wait_for_timeout(2500)                                       # Stripe looks the email up in Link right after it is entered
        if LINK_CODE.search(page.inner_text("body")):
            return {**st, "error": "Stripe Link wants a one-time code emailed to " + billing["email"] + ". That email is a Link account: use a different email."}
        page.fill("#cardNumber", ph.number)
        page.fill("#cardExpiry", f"{ph.exp_month}/{ph.exp_year[-2:]}")
        page.fill("#cardCvc", ph.cvc)
        page.fill("#billingName", billing["name"])
        if page.locator("#billingCountry").count():
            page.select_option("#billingCountry", billing["country"])
        for sel, key in (("#billingAddressLine1", "address"), ("#billingLocality", "city"), ("#billingPostalCode", "zip")):
            if billing.get(key) and page.locator(sel).count():
                page.fill(sel, billing[key])
        if billing.get("state"):                                          # state/province: a <select> for some countries, a text box for others
            page.wait_for_timeout(1200)                                   # the options load after the country changes
            area = page.locator("#billingAdministrativeArea")
            if area.count():
                tag = area.first.evaluate("e => e.tagName")
                if tag == "SELECT":
                    opts = area.first.evaluate("e => Array.from(e.options).map(o => [o.value, o.text.trim()])")
                    want = billing["state"].strip().lower()
                    pick = next((v for v, t in opts if t.lower() == want or v.lower() == want), None) or next((v for v, t in opts if want in t.lower()), None)
                    if pick is None:
                        return {**st, "error": f"state {billing['state']!r} not among the options: " + ", ".join(t for _, t in opts if t)[:300]}
                    area.first.select_option(value=pick)
                else:
                    area.first.fill(billing["state"])
        if page.locator("#enableStripePass").count() and page.locator("#enableStripePass").is_checked():
            page.uncheck("#enableStripePass")                                                # never opt in to saving the card with Stripe Link
        page.locator("button.SubmitButton, button[type=submit]").first.click()
        for i in range(wait_s):
            page.wait_for_timeout(1000)
            if st["aborted"]:
                break
            body = ""
            try:
                body = page.inner_text("body")
            except Exception:
                pass
            if not st["calls"] and LINK_CODE.search(body):
                st["error"] = "Stripe Link wants a one-time code emailed to " + billing["email"] + ". That email is a Link account: use a different email."
                break
            if i == 6 and not st["calls"]:                                   # the page's own validation usually explains a silent submit
                try:
                    errs = [t.strip() for t in page.locator("[role=alert], [class*=FieldError], [class*=Error]").all_inner_texts() if t.strip()]
                except Exception:
                    errs = []
                st["form_errors"] = sorted(set(errs))[:6]
                say("the page did not send the payment request. Form messages: " + (" | ".join(st["form_errors"]) if st["form_errors"] else "none visible (a captcha may be waiting; check the live view)"))
            left = "buy.stripe.com" not in page.url and "checkout.stripe.com" not in page.url and page.url.startswith("http")       # redirected to the merchant's own page
            if st["calls"] and st.get("pm_id") and (SUCCESS.search(body) or "/success" in page.url or "complete" in page.url or left):
                st["success"] = True
                break
        st["final"] = page.url.split("?")[0].split("#")[0]
        try:
            st["snippet"] = re.sub(r"\s+", " ", page.inner_text("body"))[:160]
        except Exception:
            st["snippet"] = ""
    return st


class HostedCheckoutVault(EnclaveVault):
    """Same interface as EnclaveVault (so the graph is unchanged), but pays through a hosted checkout page."""

    def __init__(self, enclave, *, checkout_url: str, billing: dict, capture_only: bool = False, say: Callable[[str], None] = print, page_html: str = None,
                 cvc_box_provider: Callable[[], tuple] = None, **kw):
        super().__init__(enclave, **kw)
        self._url, self._billing, self._capture_only, self._say, self._html = checkout_url, billing, capture_only, say, page_html
        self._cvc_boxes = cvc_box_provider                            # web app: (sealed_box, aad) made in the user's browser
        self.observed = {}

    def pay(self, ph: E.Placeholder, intent: Intent) -> dict:
        self.sync_revocations()
        approval = self._make_approval(ph, intent)
        sealed = self._store.sealed(self._card_id)
        cvc_sealed, cvc_aad = None, None
        if self._cvc_boxes:
            cvc_sealed, cvc_aad = self._cvc_boxes()
        elif self._cvc:
            cvc_sealed = E.seal(bytes.fromhex(self._enc.attest()["pubkey"]), {"cvc": self._cvc()}, aad=f"cvc:{ph.token}".encode())

        fwd = {"done": False}

        def on_tokenize(captured: dict):
            from urllib.parse import parse_qsl
            pairs = parse_qsl(captured["body"], keep_blank_values=True)
            self.observed = {"url": captured["url"], "fields": sorted({k.split("[")[0] + ("[" + k.split("[", 1)[1] if "[" in k else "") for k, _ in pairs}),
                             "has_placeholder": any(k == "card[number]" and re.sub(r"\D", "", v) == ph.number for k, v in pairs)}
            if self._capture_only:
                return {"status": "blocked", "reason": "capture-only: nothing was sent to Stripe"}
            try:
                res = self._enc.pay(sealed=sealed, placeholder=ph, intent=intent, request=captured, approval=approval,
                                    card_id=self._card_id, cvc_sealed=cvc_sealed, mode="forward", cvc_aad=cvc_aad)
                if res.get("status") == "forwarded":
                    fwd["done"] = True                                   # from here on, money may move: never report 'refused'
                return res
            except E.EnclaveRefused as e:
                return {"status": "refused", "reason": str(e)}

        with KernelSession(name="vault-harness-hosted", headless=False, timeout_seconds=600) as br:
            if br.live_view_url:
                self._say("live view (open it if a captcha or error needs a human): " + br.live_view_url.split("?")[0] + "?…  [full link saved]")
                from pathlib import Path
                f = Path(__file__).resolve().parent.parent / "output" / "live_view_url.txt"
                f.parent.mkdir(exist_ok=True); f.write_text(br.live_view_url + "\n"); f.chmod(0o600)
            try:
                st = drive(br.cdp_ws_url, self._url, self._billing, ph, intent.amount_cents, on_tokenize, self._say, html=self._html)
            except Exception as e:                                       # browser/network error: decide by whether the card was already forwarded
                st = {"success": False, "calls": int(fwd["done"]), "error": None if fwd["done"] else f"browser error before any card was sent: {type(e).__name__}",
                      "final": "", "forwarded": fwd["done"], "exception": f"{type(e).__name__}: {str(e)[:120]}"}
        st["forwarded"] = fwd["done"]
        self.last = st
        if self._capture_only:
            return {"status": "refused", "reason": "capture-only", "observed": self.observed}
        if st.get("error") or st.get("aborted"):
            return {"status": "refused", "card_sent": st["forwarded"], "reason": st.get("error") or st.get("aborted")}
        if not st["success"]:
            return {"status": "unconfirmed" if st["forwarded"] else "refused", "card_sent": st["forwarded"], "reason": (f"card was sent but no success page was seen (final={st.get('final')}); check the receipt before any retry" if st["forwarded"] else "page never reached the payment step")}
        return {"status": "done", "charge_id": st["pm_id"] or "pm_unknown", "merchant": intent.merchant, "amount_cents": intent.amount_cents,
                "currency": intent.currency, "card_last4": st["last4"]}
