"""The ONLY place with a real side effect: a payment. Dry run is the default.
The agent's intent goes in; a placeholder is issued; the vault swaps in the real card inside pay(). No card data comes back out."""
from vault_harness import policy, vault

_vault = None


def _get():
    global _vault
    if _vault is None:
        _vault = vault.get_vault()
    return _vault


def use(v):
    """Inject a configured vault (EnclaveVault). The graph still calls only perform()."""
    global _vault
    _vault = v


def reset():
    global _vault
    _vault = None


def perform(intent: dict, dry_run: bool = True) -> dict:
    i = policy.Intent(**intent)
    if dry_run:
        return {"status": "dry_run", "merchant": i.merchant, "amount_cents": i.amount_cents}
    v = _get()
    return v.pay(v.issue_placeholder(i), i)
