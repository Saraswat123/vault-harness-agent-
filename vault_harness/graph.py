"""Vault Harness - the agent proposes a payment; code decides, a human approves, the vault pays.

    work -> check -(bad JSON, <3 tries)-> work
                  |-(policy deny)-> denied
                  |-(auto: under limit)-> act
                  `-(needs approval)-> review (human pauses here) -> act -> end

The model never sees a card number and never chooses to pay. act() is the only side effect; it hands the vault a
placeholder and the vault swaps in the real card at the last step.
"""
from typing import TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from vault_harness import actions, alerts, guard, kernel_setup, policy, rules, tracing
from vault_harness.fake_model import ScriptedWriter
from vault_harness.models import build_model

MAX_ATTEMPTS = 3
SYSTEM = ("You turn a purchase request into ONE JSON object with exactly these keys: merchant (domain), "
          "amount_cents (integer), currency, description. Output the JSON only. Never include card details.")


class S(TypedDict, total=False):
    task: str
    live: bool
    draft: str
    leak_flag: bool
    card_id: str
    input_redacted: bool
    intent: dict
    verdict: dict
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
        raw = str(resp.content).strip()
        return {"draft": policy.redact(raw), "leak_flag": policy.contains_pan(raw), "attempts": s.get("attempts", 0) + 1}   # a card number never enters state

    def check(s: S):
        if s.get("leak_flag"):
            v = ["model output contained card-number-like digits (redacted); never put card data in a proposal"]
            return {"violations": v, "feedback": "\n".join(f"- {x}" for x in v)}
        intent, v, verdict = rules.check(s["draft"], policy.Budget().spent(), card_id=s.get("card_id", ""))
        if v:
            return {"violations": v, "feedback": "\n".join(f"- {x}" for x in v)}
        what = dict(merchant=intent.merchant, amount_cents=intent.amount_cents, card=s.get("card_id", ""))
        if verdict.action == "deny":
            if s.get("live"):
                guard.EventStore().add(merchant=intent.merchant, amount=intent.amount_cents, outcome="denied", card=s.get("card_id", ""))
            alerts.emit("payment_denied", "critical" if verdict.reasons[0].startswith("frozen") else "warn", reasons="; ".join(verdict.reasons), risk=verdict.risk, **what)
        elif verdict.reasons and verdict.reasons[0].startswith("step-up"):
            alerts.emit("step_up_required", "warn", reasons="; ".join(verdict.reasons), risk=verdict.risk, **what)
        return {"violations": [], "intent": policy.intent_dict(intent), "verdict": {"action": verdict.action, "reasons": verdict.reasons, "risk": verdict.risk}}

    def review(s: S):
        ans = interrupt({"intent": s["intent"], "why_approval": s["verdict"]["reasons"], "mode": "LIVE" if s.get("live") else "dry run", "options": "approve | reject"})
        return {"decision": (ans or {}).get("decision", "reject")}

    def act(s: S):
        if s.get("result"):                       # resume safety: never act twice
            return {}
        i, card = s["intent"], s.get("card_id", "")
        what = dict(merchant=i["merchant"], amount_cents=i["amount_cents"], card=card)
        hit = guard.Freezes().match(agent=kernel_setup.AGENT, card=card, merchant=i["merchant"]) if s.get("live") else None
        if hit:                                   # instant revocation: a freeze placed AFTER approval still stops the payment
            res = {"status": "refused", "reason": f"frozen at execution time: {hit['scope']}"}
            guard.EventStore().add(merchant=i["merchant"], amount=i["amount_cents"], outcome="denied", card=card)
            alerts.emit("payment_denied", "critical", reasons=res["reason"], **what)
            return {"result": res, "outcome": "refused"}
        res = actions.perform(i, dry_run=not s.get("live"))
        if res.get("status") == "done":
            policy.Budget().record(policy.Intent(**i), res["charge_id"])
        if s.get("live"):
            ok = res.get("status") == "done"
            kind = "done" if ok else ("refused" if res.get("card_sent", True) else "aborted")      # no card sent = not a failed payment
            guard.EventStore().add(merchant=i["merchant"], amount=i["amount_cents"], outcome=kind, card=card)
            alerts.emit("payment_done" if ok else "payment_refused", "info" if ok else "warn", charge=res.get("charge_id", ""), reason=res.get("reason", ""), **what)
        return {"result": res, "outcome": {"done": "done", "dry_run": "dry_run_previewed"}.get(res.get("status"), "refused")}

    def after_check(s: S):
        if s["violations"]:
            return "give_up" if s.get("attempts", 0) >= MAX_ATTEMPTS else "work"
        return {"deny": "denied", "auto": "act", "approve": "review"}[s["verdict"]["action"]]

    def give_up(s: S):
        return {"outcome": "failed_validation"}

    def denied(s: S):
        return {"outcome": "denied"}

    def rejected(s: S):
        return {"outcome": "rejected"}

    g = StateGraph(S)
    g.add_node("work", wrap("work", work) if wrap else work)
    g.add_node("check", wrap("check", check) if wrap else check)
    g.add_node("review", wrap("review", review) if wrap else review)
    g.add_node("act", wrap("act", act) if wrap else act)
    g.add_node("give_up", wrap("give_up", give_up) if wrap else give_up)
    g.add_node("denied", wrap("denied", denied) if wrap else denied)
    g.add_node("rejected", wrap("rejected", rejected) if wrap else rejected)
    g.add_edge(START, "work")
    g.add_edge("work", "check")
    g.add_conditional_edges("check", after_check, ["review", "act", "denied", "work", "give_up"])
    g.add_conditional_edges("review", lambda s: "act" if s.get("decision") == "approve" else "rejected", ["act", "rejected"])
    for n in ("act", "give_up", "denied", "rejected"):
        g.add_edge(n, END)
    return g.compile(checkpointer=checkpointer or MemorySaver())



def start(g, task: str, live: bool = False, cfg: dict = None, card_id: str = ""):
    """The ONLY way to begin a run. A card number typed into the task is redacted before it reaches graph state, checkpoints, the ledger or traces."""
    clean = policy.redact(task)
    return g.invoke({"task": clean, "live": live, "input_redacted": clean != task, "card_id": card_id}, cfg or {"configurable": {"thread_id": "run"}})


graph = build()
