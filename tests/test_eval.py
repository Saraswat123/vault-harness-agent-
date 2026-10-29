"""The golden eval runs inside the normal test suite so a guardrail regression fails `pytest`, not just `run_eval.py`."""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "evals"))
import run_eval as R  # noqa: E402


@pytest.fixture(autouse=True)
def restore_env():
    """run_case sets VAULT_POLICY, ledger dirs etc. Put everything back so later tests see their own environment."""
    from vault_harness import actions, kernel_setup, policy
    env, budget = dict(os.environ), policy.BUDGET_FILE
    yield
    os.environ.clear(); os.environ.update(env)
    policy.BUDGET_FILE = budget
    actions.reset(); kernel_setup.reset()


def test_golden_set_is_well_formed():
    cases = json.loads(R.GOLDEN.read_text())["cases"]
    kinds = {c["kind"] for c in cases}
    assert kinds == {"control", "attack", "leak"} and len({c["id"] for c in cases}) == len(cases)
    assert all(c.get("pans") for c in cases if c["kind"] == "leak")


def test_every_golden_case_passes_and_no_metric_drops_below_baseline():
    results = [R.run_case(c) for c in json.loads(R.GOLDEN.read_text())["cases"]]
    assert [r["id"] for r in results if not all(r["checks"].values())] == []
    m, base = R.metrics(results), json.loads(R.BASE.read_text())
    assert {k: v for k, v in m.items() if v < base.get(k, 0)} == {}
