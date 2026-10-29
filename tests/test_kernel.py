"""The kernel around the scaffolded flow agent. Keep these when you edit the agent: they prove the guards still hold."""
import pytest
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from vault_harness import actions, kernel_setup
from vault_harness.fake_model import ScriptedWriter
from vault_harness.graph import build

GOOD = '{"merchant": "buy.stripe.com", "amount_cents": 5000, "currency": "usd"}'
CFG = {"configurable": {"thread_id": "t"}}


@pytest.fixture(autouse=True)
def out_dir(tmp_path, monkeypatch):
    from vault_harness import policy
    monkeypatch.setattr(policy, "BUDGET_FILE", tmp_path / "budget.json")
    monkeypatch.setenv("VAULT", "mock")
    actions.reset()
    return tmp_path / "budget.json"


def start(live=False, drafts=(GOOD,)):
    w = ScriptedWriter(drafts=list(drafts))
    g = build(MemorySaver(), w)
    g.invoke({"task": "write it", "live": live}, CFG)
    return g, w


def test_every_step_is_recorded_and_the_ledger_verifies(out_dir):
    g, _ = start()
    g.invoke(Command(resume={"decision": "approve"}), CFG)
    k = kernel_setup.get_kernel()
    kinds = [(r["kind"], r["data"].get("node")) for r in k.ledger.records()]
    assert ("node.start", "work") in kinds and ("node.end", "act") in kinds and ("node.interrupt", "review") in kinds
    assert k.ledger.verify()["ok"] is True


def test_halt_stops_the_run_before_the_model_is_called(out_dir):
    from agent_kernel import Halted
    kernel_setup.get_kernel().halt.engage("vault-harness", reason="stop", by="test")
    with pytest.raises(Halted):
        start()


def test_halt_between_approval_and_action_prevents_the_action(out_dir):
    from agent_kernel import Halted
    g, _ = start(live=True)
    kernel_setup.get_kernel().halt.engage(reason="global stop", by="test")
    with pytest.raises(Halted):
        g.invoke(Command(resume={"decision": "approve"}), CFG)
    assert not out_dir.exists()


def test_an_action_that_claims_done_but_did_not_is_caught_and_cannot_be_retried(out_dir, monkeypatch):
    from agent_kernel import Halted, PostconditionFailed
    calls = []
    monkeypatch.setattr(actions, "perform", lambda i, dry_run=True: calls.append(1) or {"status": "done", "charge_id": "ch_x", "merchant": "buy.stripe.com", "amount_cents": 1, "currency": "usd"})
    g, _ = start(live=True)
    with pytest.raises(PostconditionFailed):
        g.invoke(Command(resume={"decision": "approve"}), CFG)
    with pytest.raises(Halted):                       # the kernel engaged the halt: a resume cannot act twice
        g.invoke(Command(resume={"decision": "approve"}), CFG)
    assert len(calls) == 1


def test_the_step_budget_stops_a_runaway(out_dir):
    from agent_kernel import BudgetExceeded
    kernel_setup.get_kernel().max_steps = 1
    with pytest.raises(BudgetExceeded):
        start()
