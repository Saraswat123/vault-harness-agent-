"""Golden eval for the payment agent. Pattern from /agent-eval: control + planted defects + baseline regression gate.
Offline and deterministic: the model is a scripted writer, so this scores the GUARDRAILS and the plumbing, not model quality.

  python evals/run_eval.py                  run and compare with evals/baseline.json
  python evals/run_eval.py --update-baseline
  python evals/run_eval.py --verify-golden  check the answer key itself
Exit 1 if any metric's pass rate dropped against the baseline, or any case failed on a clean tree with no baseline.
"""
import argparse
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
GOLDEN = ROOT / "evals" / "golden" / "payment_cases.json"
BASE = ROOT / "evals" / "baseline.json"
POLICY = json.loads((ROOT / "config" / "policy.interview.json").read_text())


def run_case(c: dict) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="eval-"))
    os.environ.update(BLACKBOX_DIR=str(tmp / "ledger"), AGENT_CONTROL_DIR=str(tmp / "control"), VAULT="mock",
                      VAULT_EVENTS_DB=str(tmp / "events.db"), VAULT_FREEZE_FILE=str(tmp / "freezes.json"),
                      VAULT_ALERTS_FILE=str(tmp / "alerts.jsonl"), VAULT_CARD_STORE=str(tmp / "cards.json"),
                      VAULT_POLICY=json.dumps({**POLICY, **c.get("policy", {})}))
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.types import Command

    from vault_harness import actions, guard, kernel_setup, policy
    from vault_harness.fake_model import ScriptedWriter
    from vault_harness.graph import build, start
    policy.BUDGET_FILE = tmp / "budget.json"
    if c.get("spent_cents"):
        policy.BUDGET_FILE.write_text(json.dumps({"spent_cents": c["spent_cents"]}))
    actions.reset(); kernel_setup.reset()
    store, now = guard.EventStore(), time.time()
    for e in c.get("seed_events", []):                          # prior history: {"ago_s", "merchant", "amount", "outcome"}
        store.add(merchant=e.get("merchant", "stripe-test-mode"), amount=e["amount"], outcome=e["outcome"], ts=now - e["ago_s"])
    for sc in c.get("freeze", []):
        guard.Freezes().freeze(sc, "eval case")
    g, cfg = build(MemorySaver(), ScriptedWriter(drafts=c["drafts"])), {"configurable": {"thread_id": c["id"]}}
    start(g, c["task"], True, cfg)
    pending = any(t.interrupts for t in g.get_state(cfg).tasks)
    if pending and c.get("resume"):
        g.invoke(Command(resume={"decision": c["resume"]}), cfg)
        pending = any(t.interrupts for t in g.get_state(cfg).tasks)
    st = g.get_state(cfg).values
    outcome = "awaiting_approval" if pending else st.get("outcome")
    recs = list(kernel_setup.get_kernel().ledger.records())
    ledger_full = repr(recs)                                    # literal test PANs are searched everywhere, hash chain included
    ledger_data = repr([(r["kind"], r["data"]) for r in recs])  # the pattern scan skips hash/prev: hex digit runs are not card numbers
    HASHES = re.compile(r"\b[0-9a-f]{24,}\b|\b(?:vc|ph|pi|pm|ch|cs|cauth|cprep|sess)_[0-9A-Za-z_]+")                   # sha256 digests (input_sha256, hash, prev...) are not card numbers
    blob = HASHES.sub("", repr(st) + ledger_data)
    pans = [p for p in c.get("pans", [])]
    if c.get("allow_last4"):
        pans = [p for p in pans if len(p) > 4]                  # last4 is allowed; the full number is not
    leaked = [p for p in pans if p in blob or p in ledger_full] or ([m.group(0) for m in [policy.PAN_RE.search(blob)] if m])
    checks = {"outcome": outcome == c["expect"]["outcome"], "no_leak": not leaked}
    if c["expect"].get("alert"):
        checks["alert"] = c["expect"]["alert"] in ([json.loads(l)["kind"] for l in (tmp / "alerts.jsonl").read_text().splitlines()] if (tmp / "alerts.jsonl").exists() else [])
    for k, v in c["expect"].get("flags", {}).items():
        checks[f"flag_{k}"] = st.get(k) == v
    return {"id": c["id"], "kind": c["kind"], "got": outcome, "want": c["expect"]["outcome"], "checks": checks, "leaked": leaked and ["<redacted>"]}


def metrics(results: list) -> dict:
    m = {}
    for kind, name in (("control", "control:no_false_alarm"), ("attack", "attack:no_miss"), ("leak", "leak:outcome_ok")):
        rs = [r for r in results if r["kind"] == kind]
        m[name] = sum(r["checks"]["outcome"] for r in rs) / len(rs)
    m["all:no_card_leak"] = sum(r["checks"]["no_leak"] for r in results) / len(results)
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--verify-golden", action="store_true")
    a = ap.parse_args()
    gold = json.loads(GOLDEN.read_text())["cases"]
    if a.verify_golden:
        bad = 0
        ids = [c["id"] for c in gold]
        for c in gold:
            ok = c["kind"] in ("control", "attack", "leak") and c["drafts"] and c["expect"].get("outcome") and ids.count(c["id"]) == 1
            ok = ok and (c["kind"] != "leak" or c.get("pans"))
            print(("ok  " if ok else "BAD ") + c["id"]); bad += not ok
        kinds = {k: sum(c["kind"] == k for c in gold) for k in ("control", "attack", "leak")}
        print(kinds, "-> control and leak cases present" if kinds["control"] and kinds["leak"] else "-> MISSING control or leak")
        sys.exit(1 if bad or not (kinds["control"] and kinds["leak"]) else 0)
    results = [run_case(c) for c in gold]
    for r in results:
        bad = not all(r["checks"].values())
        print(("FAIL " if bad else "pass ") + r["id"].ljust(48), f"got={r['got']} want={r['want']}" + (f" LEAK={r['leaked']}" if r["leaked"] else ""))
    m = metrics(results)
    print("\nmetrics:"); [print(f"  {k:28s} {v:6.1%}") for k, v in m.items()]
    out = ROOT / "evals" / "results" / f"{time.strftime('%Y%m%d-%H%M%S')}-scripted.json"
    out.write_text(json.dumps({"metrics": m, "results": results}, indent=1))
    failed = [r["id"] for r in results if not all(r["checks"].values())]
    if a.update_baseline:
        BASE.write_text(json.dumps(m, indent=1)); print(f"baseline saved ({len(results)} cases)"); sys.exit(1 if failed else 0)
    if BASE.exists():
        base = json.loads(BASE.read_text())
        dropped = {k: (base[k], m[k]) for k in base if m.get(k, 0) < base[k]}
        print("regression gate:", "FAIL " + str(dropped) if dropped else "ok (no metric dropped)")
        sys.exit(1 if dropped or failed else 0)
    print("no baseline saved yet"); sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
