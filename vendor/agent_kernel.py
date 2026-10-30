"""agent_kernel: the trusted layer an agent's steps run through. No model inside.

    k = Kernel("outreach", postconditions={"send": post_send})
    graph = build(checkpointer, wrap=k.wrap)          # every node: halt -> budget -> run -> screen -> verify -> ledger
    out = k.call("read_file", read_file, name)         # tool-style agents: the same guards around one tool call

What one wrapped step does, in order:
  1. halt switch (a file outside the agent; blackbox.Halt)            -> raises Halted, step never runs
  2. step + wall-clock budget                                         -> raises BudgetExceeded, step never runs
  3. ledger node.start, run the step, ledger node.end (blackbox, hash-chained, secrets redacted)
  4. screen: text the step returned from untrusted sources is checked for instruction-like content; flags go to
     the ledger and a warning list, they do not block (the agent cannot act on text it has no authority for)
  5. postcondition: a check of the WORLD, not of what the step claims. On failure the kernel records it, engages
     the halt switch for this agent (so a resume cannot repeat a half-done side effect), and raises.

Also: egress allowlist (egress.py, socket-level, this process only), graded scores (Kernel.score and per-node `scorers`; grader = code,
llm or human; see score.py to add one after the fact) and OpenTelemetry spans per step/tool call (no-ops until a provider such as
Phoenix is configured via the agent's tracing module).

Limits, stated plainly: halt and budget stop a cooperating loop at the next step boundary, not a call in flight.
Screening is pattern matching and misses new phrasings. A postcondition is only as good as the check you write.
Token budget is not enforced here (the kernel does not see model usage).
"""
from __future__ import annotations

import os
import sys
import contextlib
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional


def _import_from(env: str, default: Path, module: str):
    src = Path(os.environ.get(env, str(default)))
    if src.exists() and str(src) not in sys.path:
        sys.path.insert(0, str(src))
    return __import__(module)


_import_from("AGENT_BLACKBOX_SRC", Path(__file__).resolve().parent, "blackbox")      # vendored next to this file (was ~/agent-blackbox)
from blackbox.adapters.langgraph import _digest, _view, wrap_node  # noqa: E402
from blackbox.halt import Halt, Halted  # noqa: E402
from blackbox.ledger import Ledger  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent)) if str(Path(__file__).resolve().parent) not in sys.path else None
import egress as _egress  # noqa: E402

__all__ = ["Kernel", "KernelError", "BudgetExceeded", "PostconditionFailed", "EgressDenied", "Halted", "GRADERS"]
GRADERS = ("code", "llm", "human")


class KernelError(RuntimeError):
    pass


class BudgetExceeded(KernelError):
    pass


class PostconditionFailed(KernelError):
    pass


class EgressDenied(KernelError, _egress.EgressDenied):
    pass


def default_detector() -> Callable[[str], List[str]]:
    _import_from("AGENT_MEMORY_SRC", Path.home() / "agent-memory", "agent_memory")
    from agent_memory.guard import injection_flags
    return injection_flags


class Kernel:
    def __init__(self, agent: str, ledger_dir: Optional[str] = None, control_dir: Optional[str] = None,
                 max_steps: int = 40, max_wall_s: float = 900.0,
                 postconditions: Optional[Dict[str, Callable]] = None,
                 screens: Optional[Dict[str, Callable]] = None,
                 detector: Optional[Callable[[str], List[str]]] = None,
                 halt_on_postcondition: bool = True,
                 egress_allow: Optional[Iterable[str]] = None, allow_loopback: bool = True, allow_private: bool = False,
                 scorers: Optional[Dict[str, Callable]] = None, tracer=None):
        self.agent = agent
        self.ledger = Ledger(str(Path(ledger_dir or os.environ.get("BLACKBOX_DIR", "~/.blackbox/ledger")).expanduser()))
        self.halt = Halt(control_dir)
        self.max_steps, self.max_wall_s = max_steps, max_wall_s
        self.postconditions = dict(postconditions or {})
        self.screens = dict(screens or {})
        self.detector = detector if detector is not None else (default_detector() if self.screens else None)
        self.halt_on_postcondition = halt_on_postcondition
        self.steps = 0
        self.started = time.monotonic()
        self.warnings: List[str] = []
        self.scorers = dict(scorers or {})
        self.tracer = tracer
        self.egress = (_egress.EgressPolicy(list(egress_allow), allow_loopback, allow_private, on_event=self._egress_event, error_cls=EgressDenied)
                       if egress_allow is not None else None)

    # ---- egress: where this process may send data ------------------------
    def _egress_event(self, kind: str, host: str, port) -> None:
        self.ledger.append(self.agent, f"egress.{kind}", {"host": host, "port": port})

    def install_egress(self) -> bool:
        """Enforce the allowlist for this whole process (stays until uninstall_egress). False when no policy was given."""
        if self.egress is None:
            return False
        self.egress.install()
        return True

    def uninstall_egress(self) -> None:
        if self.egress is not None:
            self.egress.uninstall()

    @contextlib.contextmanager
    def enforce_egress(self):
        self.install_egress()
        try:
            yield self
        finally:
            self.uninstall_egress()

    # ---- graded scores: code, LLM judge, human ----------------------------
    def score(self, dimension: str, value: float, grader: str = "code", run_id: Optional[str] = None, note: str = "") -> dict:
        """Record a graded judgement in the ledger. value in [0, 1]; grader is who judged: code, llm or human.
        Scores are evidence, appended later if need be (a human or judge can score a run after it finished)."""
        if grader not in GRADERS:
            raise ValueError(f"grader must be one of {GRADERS}, got {grader!r}")
        if not dimension or len(dimension) > 64:
            raise ValueError("dimension must be 1-64 characters")
        v = float(value)
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"score must be between 0 and 1, got {value}")
        return self.ledger.append(self.agent, "score", {"dimension": dimension, "value": v, "grader": grader, "run_id": run_id, "note": str(note)[:300]})

    def _score(self, name: str, state, out) -> None:
        fn = self.scorers.get(name)
        if not fn:
            return
        for item in fn(state, out) or []:
            dim, val, grader, run_id, note = (tuple(item) + (None,) * 5)[:5] if not isinstance(item, dict) else (
                item["dimension"], item["value"], item.get("grader", "code"), item.get("run_id"), item.get("note", ""))
            self.score(dim, val, grader or "code", run_id, note or "")

    # ---- tracing (OpenTelemetry; spans are no-ops until a provider such as Phoenix is configured) ----
    def _span(self, name: str, **attrs):
        tracer = self.tracer
        if tracer is None:
            try:
                from opentelemetry import trace
                tracer = trace.get_tracer("agent_kernel")
            except Exception:
                return contextlib.nullcontext()
        cm = tracer.start_as_current_span(f"{self.agent}.{name}", attributes={"agent.name": self.agent, "agent.step": self.steps, **attrs})
        return cm

    # ---- run bookkeeping -------------------------------------------------
    def start_run(self, **meta) -> None:
        self.ledger.append(self.agent, "run.start", meta)

    def end_run(self, outcome: str, **meta) -> None:
        self.ledger.append(self.agent, "run.end", {"outcome": outcome, "steps": self.steps, **meta})

    def status(self) -> dict:
        return {"agent": self.agent, "steps": f"{self.steps}/{self.max_steps}",
                "wall_s": f"{time.monotonic() - self.started:.1f}/{self.max_wall_s:g}",
                "halts": self.halt.status(), "ledger": self.ledger.verify()}

    # ---- the wrapper -----------------------------------------------------
    def _charge(self, name: str) -> None:
        self.steps += 1
        wall = time.monotonic() - self.started
        if self.steps > self.max_steps:
            raise BudgetExceeded(f"step budget spent before '{name}': {self.steps - 1}/{self.max_steps}")
        if wall > self.max_wall_s:
            raise BudgetExceeded(f"wall-clock budget spent before '{name}': {wall:.0f}s/{self.max_wall_s:g}s")

    def _screen(self, name: str, out) -> None:
        pick = self.screens.get(name)
        if not pick or not out:
            return
        text = pick(out)
        flags = self.detector(text) if text else []
        if flags:
            self.warnings.append(f"{name}: instruction-like text in untrusted input")
            self.ledger.append(self.agent, "untrusted.flagged", {"node": name, "patterns": flags[:5]})

    def _verify(self, name: str, state, out) -> None:
        check = self.postconditions.get(name)
        if not check:
            return
        problem = check(state, out)
        if not problem:
            self.ledger.append(self.agent, "postcondition.ok", {"node": name})
            self.score("postcondition", 1.0, "code", None, name)
            return
        self.ledger.append(self.agent, "postcondition.failed", {"node": name, "problem": str(problem)[:300]})
        self.score("postcondition", 0.0, "code", None, f"{name}: {str(problem)[:200]}")
        if self.halt_on_postcondition:
            self.halt.engage(self.agent, reason=f"postcondition failed at '{name}': {problem}", by="kernel")
        raise PostconditionFailed(f"{name}: {problem}")

    def call(self, name: str, fn: Callable, *a, **k):
        """Guard one tool call (for agents whose steps are model-chosen tool calls, not graph nodes).
        Same order as wrap(): halt -> budget -> ledger -> run -> screen -> postcondition ('tool:<name>')."""
        self.halt.check(self.agent)
        self._charge(name)
        self.ledger.append(self.agent, "tool.call", {"tool": name, "args": _view({"args": a, "kwargs": k})})
        with self._span("tool." + name, **{"tool.name": name}):
            try:
                out = fn(*a, **k)
            except Exception as e:
                self.ledger.append(self.agent, "tool.error", {"tool": name, "error": f"{type(e).__name__}: {str(e)[:300]}"})
                raise
            self.ledger.append(self.agent, "tool.result", {"tool": name, "output": _view(out), "output_sha256": _digest(out)})
            self._screen("tool:" + name, out)
            self._verify("tool:" + name, {"args": a, "kwargs": k}, out)
            self._score("tool:" + name, {"args": a, "kwargs": k}, out)
            return out

    def wrap(self, name: str, fn: Callable) -> Callable:
        def inner(state, *a, **k):
            self._charge(name)
            with self._span("node." + name, **{"node.name": name}):
                out = fn(state, *a, **k)
                self._screen(name, out)
                self._verify(name, state, out)
                self._score(name, state, out)
                return out
        return wrap_node(name, inner, self.ledger, self.halt, agent=self.agent)
