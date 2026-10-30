"""Incident reports: what failed, which control failed, how to stop it recurring, and the runtime change.
The report is a markdown file a human can read and share; a pointer is written into the ledger."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

SEVERITIES = ("low", "medium", "high", "critical")


def create_incident(directory: str, title: str, severity: str, what_happened: str, controls_failed: List[str],
                    root_cause: str = "unknown yet", fix: str = "not decided", runtime_change: str = "none yet",
                    ledger=None, actor: str = "human") -> Path:
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    d = Path(directory).expanduser()
    d.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:50] or "incident"
    path = d / f"{now.strftime('%Y%m%d-%H%M%S')}-{slug}.md"
    n = 1
    while path.exists():
        n += 1
        path = d / f"{now.strftime('%Y%m%d-%H%M%S')}-{slug}-{n}.md"
    body = f"""# Incident: {title}

- **When (UTC):** {now.isoformat()}
- **Severity:** {severity}
- **Status:** open

## What happened
{what_happened}

## Controls that failed or were missing
{chr(10).join('- ' + c for c in controls_failed) or '- none identified yet'}

## Root cause
{root_cause}

## Fix
{fix}

## Change to agent behaviour at runtime
{runtime_change}

## Who needs to know
(people or systems affected; fill in before sharing)

## What others can learn
(a short, shareable version: no secrets, no personal data)
"""
    path.write_text(body, encoding="utf-8")
    if ledger is not None:
        ledger.append(actor, "incident", {"title": title, "severity": severity, "report": str(path),
                                          "controls_failed": controls_failed})
    return path
