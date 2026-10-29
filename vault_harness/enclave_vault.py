"""EnclaveVault: the wiring behind the graph's act() step.

   placeholder (from the enclave) -> stateless Kernel browser types it, we capture the processor request -> verify the page total
   equals the approved amount -> sealed card (from the card store, or sealed now) -> enclave swaps, replays, returns a masked result.

Cards: `enroll()` seals a card to the enclave key bound to its card id and stores CIPHERTEXT ONLY (cardstore.py). Payments then use
`card_id`; no card is ever asked for again. Without a card_id the old per-payment mode still works (card_source).
Freezes: sync_revocations() mirrors the host freeze list into the enclave as USER-signed commands before every payment.
SIGNING: `user_key` / `policy_key` are software stand-ins for the passkey and the policy signer. In the real build the user key never
leaves the user's device; holding it in the harness process is the weakest link and is labelled as such in the PRT.
"""
import secrets
from typing import Callable

from vault_harness import enclave as E
from vault_harness import guard
from vault_harness.cardstore import CardStore
from vault_harness.policy import Intent


class EnclaveVault:
    def __init__(self, enclave: E.MockEnclave, *, user_key, policy_key, make_browser: Callable, make_page: Callable[[Intent], str],
                 auto_limit_cents: int, card_source: Callable[[], dict] = None, card_store: CardStore = None, card_id: str = None,
                 freezes: guard.Freezes = None, cvc_source: Callable[[], str] = None):
        self._enc, self._user, self._pol = enclave, user_key, policy_key
        self._card, self._browser, self._page, self._auto = card_source, make_browser, make_page, auto_limit_cents
        self._store, self._card_id, self._frz, self._pushed = card_store, card_id, freezes, set()
        self._cvc = cvc_source                                       # asked per payment; the CVC is never stored

    def __repr__(self):
        return "EnclaveVault(...)"

    # ---- card on file ----
    def enroll(self, card: dict, card_id: str = None) -> dict:
        """Runs where the card is entered (the user's device in the real build). Returns display fields; stores ciphertext."""
        card_id = card_id or CardStore.new_id()
        card = {k: v for k, v in card.items() if k != "cvc"}                       # CVC is never stored
        sealed = E.seal(bytes.fromhex(self._enc.attest()["pubkey"]), card, aad=card_id.encode())
        display = self._enc.enroll(sealed, card_id)
        self._store.add(card_id, display, sealed)
        self._card_id = self._card_id or card_id
        return {"card_id": card_id, **display}

    # ---- revocation ----
    def _signed(self, verb: str, scope: str):
        nonce = secrets.token_hex(8)
        return nonce, self._user.sign(f"{verb}:{scope}:{nonce}".encode()).hex()

    def sync_revocations(self):
        want = {r["scope"] for r in (self._frz or guard.Freezes()).active() if r["scope"] == "all" or r["scope"].startswith(("card:", "merchant:"))}
        for sc in want - self._pushed:
            self._enc.revoke(sc, *self._signed("revoke", sc))
        for sc in self._pushed - want:
            self._enc.lift(sc, *self._signed("lift", sc))
        self._pushed = want

    def issue_placeholder(self, intent: Intent) -> E.Placeholder:
        return self._enc.issue_placeholder(intent)

    def pay(self, ph: E.Placeholder, intent: Intent) -> dict:
        self.sync_revocations()
        with self._browser() as br:                                  # fresh, profile-less session; deleted when this block ends
            cap = br.capture_checkout(self._page(intent), ph)
        if cap["total_cents"] != intent.amount_cents:                # the agent's amount must equal what the page actually charges
            return {"status": "refused", "reason": f"page total {cap['total_cents']} != approved {intent.amount_cents}"}
        if self._card_id and self._store:
            sealed = self._store.sealed(self._card_id)               # ciphertext from the card store
        else:
            sealed = E.seal(bytes.fromhex(self._enc.attest()["pubkey"]), self._card())
        cvc_sealed = None
        if self._card_id and self._cvc:
            cvc_sealed = E.seal(bytes.fromhex(self._enc.attest()["pubkey"]), {"cvc": self._cvc()}, aad=f"cvc:{ph.token}".encode())
        signer = "user" if intent.amount_cents >= self._auto else "policy"
        key = self._user if signer == "user" else self._pol
        approval = {"signer": signer, "sig": key.sign(E.approval_message(intent, ph.token)).hex()}
        try:
            return self._enc.pay(sealed=sealed, placeholder=ph, intent=intent, request=cap["request"], approval=approval, card_id=self._card_id, cvc_sealed=cvc_sealed)
        except E.EnclaveRefused as e:
            return {"status": "refused", "reason": str(e)}
        finally:
            sealed = None
