"""Spending guardrails. Deterministic code, no LLM. The agent proposes an Intent; this decides auto / approve / deny.

Mirrors Agentcard "Autopilot": auto-approve under a limit, a total budget, an expiry; at or above the limit a human approves.
"""
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

PAN_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")        # 13-19 digits, optional spaces/dashes: conservative on purpose


def contains_pan(text) -> bool:
    return bool(PAN_RE.search(str(text or "")))


def redact(text) -> str:
    return PAN_RE.sub("[REDACTED-CARD]", str(text or ""))


BUDGET_FILE = Path(os.environ.get("VAULT_BUDGET_FILE", Path(__file__).resolve().parent.parent / "output" / "budget.json"))


@dataclass(frozen=True)
class Intent:
    merchant: str
    amount_cents: int
    currency: str = "usd"
    description: str = ""


@dataclass
class Policy:
    auto_approve_under_cents: int = 5000       # $50: below this, no human needed
    max_single_cents: int = 10000              # $100: hard cap per purchase
    budget_total_cents: int = 20000            # $200 across the whole period
    allowed_merchants: tuple = ("buy.stripe.com",)
    allowed_currencies: tuple = ("usd",)
    expires_at: Optional[float] = None         # epoch seconds; None = no expiry
    velocity: Optional[dict] = None            # per_minute / per_hour / per_day payments, spend_per_hour_cents / spend_per_day_cents
    risk: Optional[dict] = None                # step_up_at / deny_at (0-100)


@dataclass
class Verdict:
    action: str                                # "auto" | "approve" | "deny"
    reasons: list = field(default_factory=list)
    risk: int = 0


def parse_intent(text: str):
    """Model output -> (Intent | None, violations). Strict: any unknown or mistyped field is a violation."""
    try:
        d = json.loads(text)
    except Exception:
        return None, ["draft is not valid JSON"]
    if not isinstance(d, dict):
        return None, ["draft must be a JSON object"]
    extra = set(d) - {"merchant", "amount_cents", "currency", "description"}
    if extra:
        return None, [f"unexpected fields: {sorted(extra)}"]     # the agent may not smuggle e.g. a card number in
    if not isinstance(d.get("merchant"), str) or not d["merchant"].strip():
        return None, ["merchant must be a non-empty string"]
    if not isinstance(d.get("amount_cents"), int) or isinstance(d.get("amount_cents"), bool):
        return None, ["amount_cents must be an integer"]
    return Intent(d["merchant"].strip().lower(), d["amount_cents"], str(d.get("currency", "usd")).lower(), str(d.get("description", ""))[:200]), []


def evaluate(i: Intent, p: Policy, spent_cents: int, now: Optional[float] = None) -> Verdict:
    now = time.time() if now is None else now
    deny = []
    if i.amount_cents <= 0:
        deny.append("amount must be positive")
    if p.expires_at is not None and now >= p.expires_at:
        deny.append("spending authority expired")
    if i.merchant not in p.allowed_merchants:
        deny.append(f"merchant {i.merchant!r} not on allowlist")
    if i.currency not in p.allowed_currencies:
        deny.append(f"currency {i.currency!r} not allowed")
    if i.amount_cents > p.max_single_cents:
        deny.append(f"amount {i.amount_cents} over per-purchase cap {p.max_single_cents}")
    if spent_cents + i.amount_cents > p.budget_total_cents:
        deny.append(f"budget exhausted: spent {spent_cents} + {i.amount_cents} > {p.budget_total_cents}")
    if deny:
        return Verdict("deny", deny)
    if i.amount_cents < p.auto_approve_under_cents:
        return Verdict("auto", [f"under auto-approve limit {p.auto_approve_under_cents}"])
    return Verdict("approve", [f"at or above auto-approve limit {p.auto_approve_under_cents}"])


class Budget:
    """Running total. Written only after a payment succeeded. A file so the browser/agent process can stay stateless."""

    def __init__(self, path: Path = None):
        self.path = Path(path or BUDGET_FILE)

    def spent(self) -> int:
        try:
            return int(json.loads(self.path.read_text()).get("spent_cents", 0))
        except Exception:
            return 0

    def record(self, intent: Intent, charge_id: str):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        d = {"spent_cents": self.spent() + intent.amount_cents}
        self.path.write_text(json.dumps(d))


def load_policy() -> Policy:
    """Policy from VAULT_POLICY (JSON path or inline) else defaults."""
    raw = os.environ.get("VAULT_POLICY", "")
    if not raw:
        return Policy()
    d = json.loads(raw if raw.lstrip().startswith("{") else Path(raw).read_text())     # inline JSON, or a path to a JSON file
    for k in ("allowed_merchants", "allowed_currencies"):
        if k in d:
            d[k] = tuple(d[k])
    return Policy(**d)


def intent_dict(i: Intent) -> dict:
    return asdict(i)
