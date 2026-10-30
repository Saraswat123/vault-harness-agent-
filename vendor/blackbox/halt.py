"""Containment: an emergency brake that lives OUTSIDE the agent.

A halt is a small file in a control directory. Agents call Halt.check(agent) before every step; the person (or a
supervisor) creates the file with `blackbox halt`. The agent cannot clear it by reasoning, and a missing control
directory means "not halted" only if nobody created it: the check is a file existence test, not a model decision.

Limit: this stops a *cooperating* loop at its next step boundary. It does not stop a call already in flight and it
does not contain a process that ignores the check. Pair it with a supervisor that can kill the process
(`/crew` supervise.py) and with a container for anything untrusted.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional


class Halted(RuntimeError):
    def __init__(self, scope: str, info: dict):
        self.scope, self.info = scope, info
        super().__init__(f"HALTED ({scope}): {info.get('reason', 'no reason given')} [by {info.get('by', '?')} at {info.get('ts', '?')}]")


class Halt:
    def __init__(self, control_dir: Optional[str] = None):
        self.dir = Path(control_dir or os.environ.get("AGENT_CONTROL_DIR", "~/.agent-control")).expanduser()

    def _file(self, agent: Optional[str]) -> Path:
        if agent and ("/" in agent or agent.startswith(".")):
            raise ValueError(f"bad agent name {agent!r}")
        return self.dir / (f"HALT.{agent}" if agent else "HALT")

    def engage(self, agent: Optional[str] = None, reason: str = "", by: str = "human") -> dict:
        self.dir.mkdir(parents=True, exist_ok=True)
        info = {"reason": reason, "by": by, "ts": datetime.now(timezone.utc).isoformat()}
        self._file(agent).write_text(json.dumps(info))
        return info

    def release(self, agent: Optional[str] = None) -> bool:
        f = self._file(agent)
        if f.exists():
            f.unlink()
            return True
        return False

    def status(self) -> dict:
        out = {}
        if self.dir.exists():
            for f in sorted(self.dir.glob("HALT*")):
                try:
                    out[f.name] = json.loads(f.read_text())
                except Exception:
                    out[f.name] = {"reason": "unreadable halt file (treated as halted)"}
        return out

    def check(self, agent: str) -> None:
        """Raise Halted if the global halt or this agent's halt is set. An unreadable halt file counts as halted."""
        for scope, f in (("global", self._file(None)), (agent, self._file(agent))):
            if f.exists():
                try:
                    info = json.loads(f.read_text())
                except Exception:
                    info = {"reason": "unreadable halt file"}
                raise Halted(scope, info)

    def guard(self, agent: str) -> Callable:
        """Decorator: check the halt before every call."""
        def deco(fn):
            def wrapper(*a, **k):
                self.check(agent)
                return fn(*a, **k)
            wrapper.__name__ = getattr(fn, "__name__", "guarded")
            return wrapper
        return deco
