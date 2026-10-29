"""Kernel Vault client (api.onkernel.com /vaults). Agentcard card storage and approvals via Kernel's managed integration.
Written from kernel.sh/docs/integrations/payments/agentcard + Kernel's OpenAPI spec (2026-10-29).

Rules taken from the docs and kept here:
  - at most ONE agentcard wallet per vault: list first, reuse
  - enrollment and approval links go to the USER through a trusted surface, never to the browser agent or the checkout browser
  - the agent receives only `state.aliases` (stand-ins); the card number and CVC stay with Agentcard
  - AGENTCARD_MODE is OUR assertion (Kernel-managed credentials do not expose the mode): fail closed if it is missing or wrong
"""
import os
import time
from typing import Optional

import httpx

from vault_harness.browser import _api_key

KERNEL = "https://api.onkernel.com"


class KernelVaultError(Exception):
    pass


def require_mode(expected: str) -> str:
    mode = os.environ.get("AGENTCARD_MODE", "")
    if mode not in ("sandbox", "live") or mode != expected:
        raise KernelVaultError(f"AGENTCARD_MODE must be set to {expected!r} (got {mode!r}); refusing to continue")
    return mode


class KernelVault:
    def __init__(self, api_key: str = None, transport: httpx.BaseTransport = None):
        self._http = httpx.Client(base_url=KERNEL, timeout=60, transport=transport,
                                  headers={"Authorization": f"Bearer {api_key or _api_key()}", "Content-Type": "application/json"})

    def __repr__(self):
        return "KernelVault(...)"

    def _ok(self, r: httpx.Response) -> dict:
        if r.status_code >= 400:
            try:
                msg = r.json()
            except Exception:
                msg = {}
            raise KernelVaultError(f"{r.status_code} {str(msg)[:300]}")
        return r.json()

    def upsert_vault(self, name: str) -> dict:
        return self._ok(self._http.post("/vaults", json={"name": name}))

    def items(self, vault: str) -> list:
        j = self._ok(self._http.get(f"/vaults/{vault}/items"))
        return j if isinstance(j, list) else j.get("items", j.get("data", []))

    def upsert_wallet(self, vault: str, key: str = "agentcard-wallet") -> dict:
        existing = [i for i in self.items(vault) if i.get("type") == "wallet" and (i.get("spec") or {}).get("provider") == "agentcard"]
        if existing:
            return self.get_item(vault, existing[0].get("key", key))          # reuse: one agentcard wallet per vault
        return self._ok(self._http.put(f"/vaults/{vault}/items/{key}", json={"type": "wallet", "spec": {"provider": "agentcard"}}))

    def get_item(self, vault: str, key: str, wait: Optional[int] = None) -> dict:
        return self._ok(self._http.get(f"/vaults/{vault}/items/{key}", params={"wait": wait} if wait else None, timeout=(wait or 0) + 30))

    def upsert_card(self, vault: str, key: str, *, wallet: str, merchant: str, amount: int, currency: str,
                    checkout_origin: str, card_id: str = None) -> dict:
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise ValueError("amount must be a positive integer in minor units")
        spec = {"provider": "agentcard", "wallet": wallet, "merchant": merchant, "amount": amount,
                "currency": currency.lower(), "checkout_origin": checkout_origin}
        if card_id:
            spec["card_id"] = card_id
        return self._ok(self._http.put(f"/vaults/{vault}/items/{key}", json={"type": "card", "spec": spec}))

    def wait_ready(self, vault: str, key: str, timeout: int = 120, interval: float = 2.0) -> dict:
        end = time.time() + timeout
        while True:
            it = self.get_item(vault, key)
            if (it.get("state") or {}).get("status") == "ready" or time.time() > end:
                return it
            time.sleep(interval)

    def events(self, vault: str, key: str) -> list:
        j = self._ok(self._http.get(f"/vaults/{vault}/items/{key}/events"))
        return j if isinstance(j, list) else j.get("events", j.get("data", []))
