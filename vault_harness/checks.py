"""What the kernel verifies about the WORLD after the payment, not what the step says about itself.
A failed check engages the halt switch for this agent, so a resume cannot pay twice."""
import re
from typing import Optional

PAN_LIKE = re.compile(r"(?<!\d)\d{13,19}(?!\d)")


def post_act(s, out) -> Optional[str]:
    if not out:                                   # resume path: already paid, node returned {}
        return None
    res = out.get("result") or {}
    status = res.get("status")
    if PAN_LIKE.search(repr(out)):
        return "card-number-like digits in the action output"
    if not s.get("live"):
        return None if status == "dry_run" else f"dry run came back with status {status!r}"
    if status == "refused":
        return None                               # the vault refused; nothing was charged
    if status != "done":
        return f"unexpected status {status!r}"
    i = s["intent"]
    if res.get("amount_cents") != i["amount_cents"] or res.get("merchant") != i["merchant"] or res.get("currency") != i["currency"]:
        return "charge does not match the approved intent"
    if not res.get("charge_id"):
        return "reported done but no charge id"
    return None


POSTCONDITIONS = {"act": post_act}
SCREENS = {}
