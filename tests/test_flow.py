import pytest
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from vault_harness import actions
from vault_harness.fake_model import ScriptedWriter
from vault_harness.graph import build

GOOD = "A short, clean draft."
BAD = "TODO fill this in"


@pytest.fixture(autouse=True)
def out_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "OUT_DIR", tmp_path / "out")
    return tmp_path / "out"


def run(drafts, live=False):
    w = ScriptedWriter(drafts=drafts)
    g = build(MemorySaver(), w)
    cfg = {"configurable": {"thread_id": "t"}}
    g.invoke({"task": "write it", "live": live}, cfg)
    return g, cfg, w


def pending(g, cfg):
    return any(t.interrupts for t in g.get_state(cfg).tasks)


def test_bad_draft_retried_then_reaches_review(out_dir):
    g, cfg, w = run([BAD, GOOD])
    assert w.calls == 2 and pending(g, cfg) and not out_dir.exists()


def test_three_bad_drafts_give_up_without_review(out_dir):
    g, cfg, w = run([BAD])
    assert w.calls == 3 and g.get_state(cfg).values["outcome"] == "failed_validation" and not pending(g, cfg)


def test_approve_is_a_dry_run_by_default(out_dir):
    g, cfg, _ = run([GOOD])
    g.invoke(Command(resume={"decision": "approve"}), cfg)
    assert g.get_state(cfg).values["outcome"] == "dry_run_previewed" and not out_dir.exists()


def test_live_needs_flag_and_approval(out_dir):
    g, cfg, _ = run([GOOD], live=True)
    assert not out_dir.exists()                       # live, but nothing happens before approval
    g.invoke(Command(resume={"decision": "approve"}), cfg)
    assert (out_dir / "result.txt").read_text() == GOOD


def test_reject_does_nothing(out_dir):
    g, cfg, _ = run([GOOD], live=True)
    g.invoke(Command(resume={"decision": "reject"}), cfg)
    assert g.get_state(cfg).values["outcome"] == "rejected" and not out_dir.exists()
