"""Transaction alerts. Every payment, denial, step-up and freeze hit is written as one JSON line and, if configured, POSTed to a webhook.
Card-like digits are redacted before anything is written. The webhook is best-effort and UNVERIFIED against a real receiver."""
import json
import os
import time
from pathlib import Path

from vault_harness import policy

ROOT = Path(__file__).resolve().parent.parent


def path() -> Path:
    return Path(os.environ.get("VAULT_ALERTS_FILE", ROOT / "output" / "alerts.jsonl"))


def emit(kind: str, severity: str = "info", **fields) -> dict:
    ev = {"ts": round(time.time(), 3), "kind": kind, "severity": severity}
    ev.update({k: (policy.redact(v) if isinstance(v, str) else v) for k, v in fields.items()})
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as f:
        f.write(json.dumps(ev) + "\n")
    hook = os.environ.get("VAULT_ALERT_WEBHOOK")
    if hook:
        try:
            import httpx
            httpx.post(hook, json=ev, timeout=3)
        except Exception:
            pass                                    # an alert channel being down must never block or hide a payment decision
    return ev


def read(kind: str = None) -> list:
    p = path()
    rows = [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []
    return [r for r in rows if kind is None or r["kind"] == kind]
