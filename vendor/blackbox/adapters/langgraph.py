"""Wrap LangGraph node functions so every step leaves evidence and respects the halt switch.

    from blackbox import Ledger, Halt
    from blackbox.adapters.langgraph import wrap_node
    g.add_node("write", wrap_node("write", write_fn, ledger, halt, agent="outreach"))

Evidence per step: a node.start with the input's keys and a sha256 of the full input, then node.end with a truncated,
secret-redacted view of the output plus a sha256 of the full output, or node.error. The hashes let you prove later
that a stored output is the one produced, without keeping every payload in the log.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Optional

from blackbox.ledger import Ledger, redact

MAX_CHARS = 1500
PAUSES = {"GraphInterrupt", "NodeInterrupt", "GraphBubbleUp"}


def _digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def _view(obj: Any) -> str:
    s = json.dumps(redact(obj), sort_keys=True, default=str, ensure_ascii=False)
    return s if len(s) <= MAX_CHARS else s[:MAX_CHARS] + f"...[+{len(s) - MAX_CHARS} chars]"


def wrap_node(name: str, fn: Callable, ledger: Ledger, halt=None, agent: str = "agent") -> Callable:
    def wrapped(state, *a, **k):
        if halt is not None:
            halt.check(agent)
        ledger.append(agent, "node.start", {"node": name, "input_keys": sorted(state.keys()) if hasattr(state, "keys") else [],
                                            "input_sha256": _digest(state)})
        try:
            out = fn(state, *a, **k)
        except Exception as e:
            if type(e).__name__ in PAUSES:        # a human-approval pause is expected control flow, not a failure
                ledger.append(agent, "node.interrupt", {"node": name, "reason": "paused for human decision"})
            else:
                ledger.append(agent, "node.error", {"node": name, "error": f"{type(e).__name__}: {str(e)[:300]}"})
            raise
        ledger.append(agent, "node.end", {"node": name, "output": _view(out), "output_sha256": _digest(out)})
        return out
    wrapped.__name__ = getattr(fn, "__name__", name)
    return wrapped
