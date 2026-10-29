"""Kernel Vault client against a fake transport (shapes from kernel.sh docs + OpenAPI). The live calls are in kernel_enroll.py."""
import json

import httpx
import pytest

from vault_harness.kernel_vault import KernelVault, KernelVaultError, require_mode


def kv(handler):
    calls = []

    def h(r):
        calls.append((r.method, r.url.path, json.loads(r.content) if r.content else None))
        return handler(r)
    return KernelVault("k_secret", transport=httpx.MockTransport(h)), calls


def test_existing_agentcard_wallet_is_reused_not_duplicated():
    def h(r):
        if r.method == "GET" and r.url.path.endswith("/items"):
            return httpx.Response(200, json=[{"key": "w1", "type": "wallet", "spec": {"provider": "agentcard"}}])
        return httpx.Response(200, json={"key": "w1", "type": "wallet", "state": {"status": "connected"}})
    k, calls = kv(h)
    assert k.upsert_wallet("v")["key"] == "w1" and not [c for c in calls if c[0] == "PUT"]


def test_new_wallet_is_created_with_provider_agentcard_only():
    def h(r):
        return httpx.Response(200, json=[]) if r.method == "GET" else httpx.Response(200, json={"key": "agentcard-wallet"})
    k, calls = kv(h)
    k.upsert_wallet("v")
    assert [c for c in calls if c[0] == "PUT"][0][2] == {"type": "wallet", "spec": {"provider": "agentcard"}}


def test_card_item_carries_the_purchase_not_the_card():
    k, calls = kv(lambda r: httpx.Response(200, json={"key": "o1"}))
    k.upsert_card("v", "o1", wallet="w1", merchant="shop", amount=100, currency="USD", checkout_origin="https://shop.example.com")
    body = calls[0][2]
    assert body["type"] == "card" and body["spec"] == {"provider": "agentcard", "wallet": "w1", "merchant": "shop", "amount": 100,
                                                       "currency": "usd", "checkout_origin": "https://shop.example.com"}


@pytest.mark.parametrize("amt", [0, -1, 1.5, True, "100"])
def test_bad_amount_never_sent(amt):
    k, calls = kv(lambda r: httpx.Response(200, json={}))
    with pytest.raises(ValueError):
        k.upsert_card("v", "o", wallet="w", merchant="m", amount=amt, currency="usd", checkout_origin="https://a.com")
    assert calls == []


def test_http_error_is_raised_and_key_never_shown():
    k, _ = kv(lambda r: httpx.Response(409, json={"error": "conflict"}))
    with pytest.raises(KernelVaultError, match="409"):
        k.upsert_vault("v")
    assert "k_secret" not in repr(k)


def test_agentcard_mode_fails_closed(monkeypatch):
    monkeypatch.delenv("AGENTCARD_MODE", raising=False)
    with pytest.raises(KernelVaultError):
        require_mode("sandbox")
    monkeypatch.setenv("AGENTCARD_MODE", "live")
    with pytest.raises(KernelVaultError):
        require_mode("sandbox")
    monkeypatch.setenv("AGENTCARD_MODE", "sandbox")
    assert require_mode("sandbox") == "sandbox"
