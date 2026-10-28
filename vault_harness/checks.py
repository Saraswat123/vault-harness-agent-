"""What the kernel verifies about the WORLD after the irreversible step, not what the step says about itself.
Return a problem string, or None when the world agrees. A failed check engages the halt switch for this agent,
so a resume cannot repeat a half-done side effect. Rewrite this when you replace actions.perform()."""
from pathlib import Path
from typing import Optional


def post_act(s, out) -> Optional[str]:
    if not out:                                   # resume path: the action already ran, node returned {}
        return None
    res = out.get("result") or {}
    status = res.get("status")
    if not s.get("live"):
        return None if status in (None, "dry_run") else f"dry run came back with status {status!r}"
    if status == "done":
        p = Path(res.get("path", ""))
        if not p.is_file():
            return f"reported done but {p} does not exist"
        if p.read_text() != s.get("draft"):
            return f"reported done but {p} does not contain the approved draft"
    return None


POSTCONDITIONS = {"act": post_act}
SCREENS = {}      # {"node name": lambda out: text-from-untrusted-source}; instruction-like text is flagged in the ledger
