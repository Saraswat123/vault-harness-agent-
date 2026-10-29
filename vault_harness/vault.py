"""The vault boundary. The agent only ever holds a Placeholder. The real card is swapped in inside pay(), at the last step.

Same shape as Agentcard Vault: agent -> placeholder -> (vault swaps real card at the edge) -> processor.
MockVault proves the contract offline. LiveVault is the Agentcard + Kernel adapter (needs keys, see below).
Later the swap in MockVault._charge moves into an AWS Nitro Enclave; the agent-facing interface does not change.
"""
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass

from vault_harness.policy import Intent

PLACEHOLDER_TTL = 600
STRIPE_TEST_PAN = "4242424242424242"       # Stripe's public test card. Never put a real card number in code or env files.


@dataclass(frozen=True)
class Placeholder:
    token: str                              # opaque. Carries no card data.


def _bind(i: Intent) -> str:
    return hashlib.sha256(json.dumps([i.merchant, i.amount_cents, i.currency], sort_keys=True).encode()).hexdigest()


class MockVault:
    """In-process stand-in. The PAN lives only in a private attribute and is used only inside _charge."""

    def __init__(self, pan: str = STRIPE_TEST_PAN):
        self.__pan = pan
        self._tokens = {}                   # token -> {bind, exp, used}

    def issue_placeholder(self, intent: Intent) -> Placeholder:
        t = "ph_" + secrets.token_hex(12)
        self._tokens[t] = {"bind": _bind(intent), "exp": time.time() + PLACEHOLDER_TTL, "used": False}
        return Placeholder(t)

    def pay(self, ph: Placeholder, intent: Intent) -> dict:
        rec = self._tokens.get(ph.token)
        if rec is None:
            return {"status": "refused", "reason": "unknown placeholder"}
        if rec["used"]:
            return {"status": "refused", "reason": "placeholder already used"}
        if time.time() > rec["exp"]:
            return {"status": "refused", "reason": "placeholder expired"}
        if rec["bind"] != _bind(intent):
            return {"status": "refused", "reason": "placeholder not bound to this payment"}
        rec["used"] = True                  # single use, burned before the charge: a retry cannot double-charge
        return self._charge(intent)

    def _charge(self, intent: Intent) -> dict:
        pan = self.__pan                    # the swap. Only this frame sees the real number.
        charge_id = "ch_mock_" + secrets.token_hex(6)
        return {"status": "done", "charge_id": charge_id, "merchant": intent.merchant,
                "amount_cents": intent.amount_cents, "currency": intent.currency, "card_last4": pan[-4:]}


class LiveVault:
    """Agentcard Vault via Kernel browser. NOT IMPLEMENTED: written from public docs only, nothing here is verified.

    Documented (docs.agentcard.com / agentcard.com/vault / kernel.sh):
      - Agentcard OAuth2 client-credentials: POST /api/v2/oauth/token  (client_id, client_secret) -> 1h bearer token
      - Kernel: vaults.items.upsert(name, {type:'card', spec:{provider:'agentcard', merchant, amount, currency}})
                browsers.create({vaults:[{id}]})  -> browser whose card fields are filled with a placeholder
      - Agentcard pauses the processor request, sends approval_url to the user (passkey), then releases it.
    Missing before this can be built: Agentcard builder credentials, KERNEL_API_KEY, the base URL, the Python call shapes.
    """

    def __init__(self):
        raise NotImplementedError("LiveVault needs AGENTCARD_CLIENT_ID/SECRET and KERNEL_API_KEY; not built yet")


def get_vault():
    kind = os.environ.get("VAULT", "mock")
    if kind == "mock":
        return MockVault()
    if kind == "live":
        return LiveVault()
    raise ValueError(f"VAULT must be mock or live, got {kind!r}")
