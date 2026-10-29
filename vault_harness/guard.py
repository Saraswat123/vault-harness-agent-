"""Real-time guard: freezes, velocity caps and a risk score, layered ON TOP of the spending policy (policy.evaluate).
Order of decision: freeze -> policy (allowlist/cap/budget/expiry) -> velocity caps -> risk score. Plain code, no model.
  risk >= deny_at  -> deny        risk >= step_up_at -> a human must approve even if the amount is under the auto limit
"""
import json
import os
import sqlite3
import statistics
import time
from contextlib import closing
from pathlib import Path
from typing import Optional

from vault_harness import policy

ROOT = Path(__file__).resolve().parent.parent
SCORED = ("done", "refused")                         # attempts that actually reached the processor


class EventStore:
    """Every payment attempt and denial, in SQLite. Holds merchant/amount/outcome only, never card data."""

    def __init__(self, path=None):
        self.path = Path(path or os.environ.get("VAULT_EVENTS_DB", ROOT / "output" / "events.db"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as c, c:
            c.execute("CREATE TABLE IF NOT EXISTS events(ts REAL, agent TEXT, card TEXT, merchant TEXT, amount INT, outcome TEXT)")

    def add(self, *, merchant, amount, outcome, agent="vault-harness", card="", ts=None):
        with closing(sqlite3.connect(self.path)) as c, c:
            c.execute("INSERT INTO events VALUES (?,?,?,?,?,?)", (ts or time.time(), agent, card or "", merchant, int(amount), outcome))

    def _q(self, sql, args=()):
        with closing(sqlite3.connect(self.path)) as c:
            return c.execute(sql, args).fetchall()

    def count(self, window_s, now, outcomes, max_amount=None, card=None):
        q, a = "SELECT COUNT(*) FROM events WHERE ts>? AND outcome IN (%s)" % ",".join("?" * len(outcomes)), [now - window_s, *outcomes]
        if max_amount is not None:
            q += " AND amount<=?"; a.append(max_amount)
        if card:
            q += " AND card=?"; a.append(card)
        return self._q(q, a)[0][0]

    def spend(self, window_s, now):
        return self._q("SELECT COALESCE(SUM(amount),0) FROM events WHERE ts>? AND outcome='done'", (now - window_s,))[0][0]

    def amounts_done(self):
        return [r[0] for r in self._q("SELECT amount FROM events WHERE outcome='done'")]

    def seen_merchant(self, merchant):
        return bool(self._q("SELECT 1 FROM events WHERE merchant=? AND outcome='done' LIMIT 1", (merchant,)))


class Freezes:
    """Instant revocation. Scopes: all | agent:<name> | card:<id> | merchant:<host>. A JSON file, checked at decision time,
    again right before the payment, and mirrored into the enclave as signed revocations."""

    def __init__(self, path=None):
        self.path = Path(path or os.environ.get("VAULT_FREEZE_FILE", ROOT / "output" / "freezes.json"))

    def _load(self) -> list:
        try:
            return json.loads(self.path.read_text())
        except Exception:
            return []

    def freeze(self, scope: str, reason: str = "", by: str = "operator"):
        rows = [r for r in self._load() if r["scope"] != scope] + [{"scope": scope, "reason": reason, "by": by, "ts": time.time()}]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(rows))

    def lift(self, scope: str):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps([r for r in self._load() if r["scope"] != scope]))

    def active(self) -> list:
        return self._load()

    def match(self, *, agent="", card="", merchant="") -> Optional[dict]:
        scopes = {"all", f"agent:{agent}", f"card:{card}", f"merchant:{merchant}"}
        return next((r for r in self._load() if r["scope"] in scopes), None)


def check_velocity(pol, store, intent, now, card="") -> list:
    v, why = pol.velocity or {}, []
    for key, win, label in (("per_minute", 60, "minute"), ("per_hour", 3600, "hour"), ("per_day", 86400, "day")):
        if v.get(key) is not None and store.count(win, now, SCORED) >= v[key]:
            why.append(f"velocity: {store.count(win, now, SCORED)} payments in the last {label} (cap {v[key]})")
    for key, win, label in (("spend_per_hour_cents", 3600, "hour"), ("spend_per_day_cents", 86400, "day")):
        if v.get(key) is not None and store.spend(win, now) + intent.amount_cents > v[key]:
            why.append(f"velocity: spend {store.spend(win, now)} + {intent.amount_cents} over the {label} cap {v[key]}")
    return why


def risk_score(intent, pol, store, now) -> tuple:
    s, why = 0, []
    if not store.seen_merchant(intent.merchant):
        s += 20; why.append("first completed payment to this merchant")
    hist = store.amounts_done()
    if len(hist) >= 3 and intent.amount_cents > 3 * statistics.median(hist):
        s += 25; why.append(f"amount {intent.amount_cents} is over 3x the usual ({int(statistics.median(hist))})")
    n_burst = (pol.risk or {}).get("burst_count", 3)
    if store.count(300, now, ("done",), max_amount=200) >= n_burst:
        s += 40; why.append(f"{n_burst}+ small payments in 5 minutes (card-testing pattern)")
    fails = store.count(600, now, ("refused", "denied"))
    if fails >= 4:
        s += 45; why.append(f"{fails} refused or denied attempts in 10 minutes")
    elif fails >= 2:
        s += 25; why.append(f"{fails} refused or denied attempts in 10 minutes")
    return min(s, 100), why


def decide(intent, pol, spent, *, card_id="", agent="vault-harness", store=None, frz=None, now=None):
    now = time.time() if now is None else now
    store, frz = store or EventStore(), frz or Freezes()
    hit = frz.match(agent=agent, card=card_id, merchant=intent.merchant)
    if hit:
        return policy.Verdict("deny", [f"frozen: {hit['scope']} ({hit['reason'] or 'no reason given'})"], risk=100)
    v = policy.evaluate(intent, pol, spent, now)
    if v.action == "deny":
        return v
    vel = check_velocity(pol, store, intent, now, card_id)
    if vel:
        return policy.Verdict("deny", vel, risk=80)
    score, why = risk_score(intent, pol, store, now)
    r = pol.risk or {}
    if score >= r.get("deny_at", 70):
        return policy.Verdict("deny", [f"risk score {score}"] + why, risk=score)
    if score >= r.get("step_up_at", 40) and v.action == "auto":
        return policy.Verdict("approve", [f"step-up: risk score {score}"] + why, risk=score)
    v.risk = score
    return v
