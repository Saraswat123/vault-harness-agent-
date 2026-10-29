"""Deterministic checks on what the model proposed: parse it, then apply freezes, the spending policy, velocity caps and the risk score.
Code, not an LLM."""
from vault_harness import guard, policy


def check(draft: str, spent_cents: int, pol: policy.Policy = None, card_id: str = ""):
    """-> (intent | None, parse_violations, verdict | None)"""
    intent, v = policy.parse_intent(draft)
    if v:
        return None, v, None
    return intent, [], guard.decide(intent, pol or policy.load_policy(), spent_cents, card_id=card_id)
