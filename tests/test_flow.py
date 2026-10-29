import json

import pytest
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from vault_harness import actions, policy
from vault_harness.fake_model import ScriptedWriter
from vault_harness.graph import build

CFG = {"configurable": {"thread_id": "t"}}


def intent(cents, merchant="buy.stripe.com", **kw):
    return json.dumps({"merchant": merchant, "amount_cents": cents, "currency": "usd", "description": "t", **kw})


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, "BUDGET_FILE", tmp_path / "budget.json")
    monkeypatch.setenv("VAULT", "mock")
    monkeypatch.delenv("VAULT_POLICY", raising=False)
    actions.reset()


def run(drafts, live=True):
    w = ScriptedWriter(drafts=drafts)
    g = build(MemorySaver(), w)
    g.invoke({"task": "buy it", "live": live}, CFG)
    return g, w


def vals(g):
    return g.get_state(CFG).values


def pending(g):
    return any(t.interrupts for t in g.get_state(CFG).tasks)


def test_one_dollar_is_auto_approved_and_charged():
    g, _ = run([intent(100)])
    assert not pending(g) and vals(g)["outcome"] == "done"
    assert vals(g)["result"]["amount_cents"] == 100 and policy.Budget().spent() == 100


def test_at_the_limit_needs_a_human_and_nothing_is_charged_before_approval():
    g, _ = run([intent(5000)])
    assert pending(g) and policy.Budget().spent() == 0
    g.invoke(Command(resume={"decision": "approve"}), CFG)
    assert vals(g)["outcome"] == "done" and policy.Budget().spent() == 5000


def test_reject_charges_nothing():
    g, _ = run([intent(5000)])
    g.invoke(Command(resume={"decision": "reject"}), CFG)
    assert vals(g)["outcome"] == "rejected" and policy.Budget().spent() == 0


@pytest.mark.parametrize("draft,why", [
    (intent(100, merchant="evil.example"), "allowlist"),
    (intent(10001), "cap"),
    (intent(0), "positive"),
    (json.dumps({"merchant": "buy.stripe.com", "amount_cents": 100, "currency": "eur"}), "currency"),
])
def test_policy_denies_without_review_or_charge(draft, why):
    g, _ = run([draft])
    assert vals(g)["outcome"] == "denied" and not pending(g) and policy.Budget().spent() == 0
    assert why in " ".join(vals(g)["verdict"]["reasons"])


def test_budget_exhausted_denies():
    policy.Budget().path.write_text(json.dumps({"spent_cents": 19950}))
    g, _ = run([intent(100)])
    assert vals(g)["outcome"] == "denied" and "budget" in " ".join(vals(g)["verdict"]["reasons"])


def test_expired_authority_denies(monkeypatch):
    monkeypatch.setenv("VAULT_POLICY", json.dumps({"expires_at": 1.0}))
    g, _ = run([intent(100)])
    assert vals(g)["outcome"] == "denied" and "expired" in " ".join(vals(g)["verdict"]["reasons"])


def test_budget_accumulates_across_runs():
    for n in range(3):
        actions.reset()
        w = ScriptedWriter(drafts=[intent(4000)])
        build(MemorySaver(), w).invoke({"task": "x", "live": True}, {"configurable": {"thread_id": f"t{n}"}})
    assert policy.Budget().spent() == 12000


def test_bad_json_is_retried_then_gives_up():
    g, w = run(["not json"])
    assert w.calls == 3 and vals(g)["outcome"] == "failed_validation"


def test_smuggling_a_card_number_into_the_intent_is_rejected():
    g, _ = run([intent(100, card_number="4242424242424242")])
    assert vals(g)["outcome"] == "failed_validation" and policy.Budget().spent() == 0


def test_dry_run_default_never_touches_the_vault():
    g, _ = run([intent(100)], live=False)
    assert vals(g)["outcome"] == "dry_run_previewed" and policy.Budget().spent() == 0


def test_card_number_never_appears_in_state_result_or_ledger():
    from vault_harness import kernel_setup
    g, _ = run([intent(100)])
    blob = repr(vals(g)) + repr([r for r in kernel_setup.get_kernel().ledger.records()])
    assert "4242424242424242" not in blob
    assert vals(g)["result"]["card_last4"] == "4242"      # last4 is allowed; the full number is not


def test_card_number_in_the_task_is_redacted_before_it_reaches_state():
    from vault_harness.graph import start
    w = ScriptedWriter(drafts=[intent(100)])
    g = build(MemorySaver(), w)
    start(g, "buy it with card 4242 4242 4242 4242 exp 12/30", True, CFG)
    st = vals(g)
    assert "4242 4242" not in repr(st) and st["input_redacted"] is True and st["outcome"] == "done"


def test_card_number_echoed_by_the_model_is_blocked_and_redacted():
    g, _ = run([intent(100, description="pay with 4242-4242-4242-4242")])
    assert vals(g)["outcome"] == "failed_validation" and "4242-4242" not in repr(vals(g)) and policy.Budget().spent() == 0
