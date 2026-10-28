"""Vault Harness — YOU decide the steps in code; the model only writes text.

    work -> check -(violations, <3 tries)-> work
                  `-(clean)-> review (human pauses here) -> act -> end

Why this style: the model cannot skip the check or the human, and cannot choose to do the real action.
Use it for anything with a side effect. For open-ended exploration use the `deep` style instead.
"""
from typing import TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from vault_harness import actions, kernel_setup, rules, tracing
from vault_harness.fake_model import ScriptedWriter
from vault_harness.models import build_model

MAX_ATTEMPTS = 3
SYSTEM = "TODO: describe the job. Write the requested text only. No preamble."


class S(TypedDict, total=False):
    task: str
    live: bool
    draft: str
    violations: list
    feedback: str
    attempts: int
    decision: str
    outcome: str
    result: dict


def build(checkpointer=None, model=None, wrap="auto"):
    """wrap="auto": every node runs through the agent kernel (halt, budget, ledger, post-check). wrap=None: unguarded."""
    tracing.enable()
    if wrap == "auto":
        k = kernel_setup.get_kernel()
        wrap = k.wrap if k else None
    model = model or build_model(ScriptedWriter)

    def work(s: S):
        user = s["task"] + (f"\n\nYour previous draft was rejected; fix:\n{s['feedback']}" if s.get("feedback") else "")
        resp = model.invoke([("system", SYSTEM), ("user", user)])
        return {"draft": str(resp.content).strip(), "attempts": s.get("attempts", 0) + 1}

    def check(s: S):
        v = rules.validate(s["draft"])
        return {"violations": v, "feedback": "\n".join(f"- {x}" for x in v)}

    def review(s: S):
        ans = interrupt({"draft": s["draft"], "mode": "LIVE" if s.get("live") else "dry run", "options": "approve | reject"})
        return {"decision": (ans or {}).get("decision", "reject")}

    def act(s: S):
        if s.get("result"):                       # resume safety: never act twice
            return {}
        res = actions.perform(s["draft"], dry_run=not s.get("live"))
        return {"result": res, "outcome": "done" if res.get("status") == "done" else "dry_run_previewed"}

    def after_check(s: S):
        if not s["violations"]:
            return "review"
        return "give_up" if s.get("attempts", 0) >= MAX_ATTEMPTS else "work"

    def give_up(s: S):
        return {"outcome": "failed_validation"}

    def rejected(s: S):
        return {"outcome": "rejected"}

    g = StateGraph(S)
    g.add_node("work", wrap("work", work) if wrap else work)
    g.add_node("check", wrap("check", check) if wrap else check)
    g.add_node("review", wrap("review", review) if wrap else review)
    g.add_node("act", wrap("act", act) if wrap else act)
    g.add_node("give_up", wrap("give_up", give_up) if wrap else give_up)
    g.add_node("rejected", wrap("rejected", rejected) if wrap else rejected)
    g.add_edge(START, "work")
    g.add_edge("work", "check")
    g.add_conditional_edges("check", after_check, ["review", "work", "give_up"])
    g.add_conditional_edges("review", lambda s: "act" if s.get("decision") == "approve" else "rejected", ["act", "rejected"])
    for n in ("act", "give_up", "rejected"):
        g.add_edge(n, END)
    return g.compile(checkpointer=checkpointer or MemorySaver())


graph = build()
