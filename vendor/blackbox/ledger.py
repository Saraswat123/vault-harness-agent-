"""Append-only, hash-chained evidence ledger stored as sealed segments.

Layout (one directory):
    seg-000001.jsonl   header line, N record lines, then a seal line once full
    seg-000002.jsonl   header carries the previous segment's last hash
    anchors.jsonl      head hash + seq at chosen moments (keep a copy OUTSIDE this directory)

Every record's hash = sha256(prev_hash + canonical_json(record without hash)). Editing, deleting,
reordering or inserting a record breaks every hash after it. Sealed segments are immutable chunks that can be
copied to other storage; verify() checks the whole chain across them.

Honest limit: this is tamper-EVIDENT, not tamper-PROOF. Someone who can rewrite the whole directory can rebuild a
consistent chain. Anchors stored somewhere the agent cannot write (a pushed git repo, an email, another host) are
what turn evidence into something an outsider can trust. Truncating the tail is detected only against an anchor.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

GENESIS = "0" * 64
SEG_RE = re.compile(r"^seg-(\d{6})\.jsonl$")
_SECRET_KEY = re.compile(r"(api[_-]?key|token|secret|password|passwd|authorization|cookie|credential)", re.I)
_REDACTIONS = [(re.compile(p, f), r) for p, f, r in (
    # PEM private keys: a complete block, then a truncated one (header + base64 with no END line)
    (r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----", re.S, "[REDACTED PRIVATE KEY]"),
    (r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[A-Za-z0-9+/=\s]*", 0, "[REDACTED PRIVATE KEY]"),
    (r"\b([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@", re.I, r"\1[REDACTED]@"),                 # user:pass@host in URLs
    (r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", 0, "[REDACTED]"),         # JWT
    (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0, "[REDACTED]"),                                          # AWS access key id
    (r"sk-or-v1-[A-Za-z0-9]+", 0, "[REDACTED]"), (r"gsk_[A-Za-z0-9]+", 0, "[REDACTED]"), (r"sk-ant-[A-Za-z0-9_-]+", 0, "[REDACTED]"),
    (r"gh[pousr]_[A-Za-z0-9]{20,}", 0, "[REDACTED]"), (r"AIza[0-9A-Za-z_-]{30,}", 0, "[REDACTED]"), (r"Bearer\s+[A-Za-z0-9._-]+", 0, "[REDACTED]"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", 0, "[REDACTED]"), (r"sk_live_[A-Za-z0-9]{10,}", 0, "[REDACTED]"),
    # NAME_PASSWORD=value (value may contain spaces, as Gmail app passwords do), then "password is/=/: value" in prose
    (r"^(\s*[A-Z0-9_]*(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|API_?KEY)[A-Z0-9_]*\s*=\s*).*$", re.M, r"\1[REDACTED]"),
    (r"\b(password|passwd|passphrase|secret|api[_ -]?key|token)\b(\s*(?:is|=|:)\s*)[^\s,;]+", re.I, r"\1\2[REDACTED]"),
)]


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def redact(obj: Any) -> Any:
    """Remove secrets BEFORE hashing: an evidence log must never become a credential store."""
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if _SECRET_KEY.search(str(k)) else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        for pat, repl in _REDACTIONS:
            obj = pat.sub(repl, obj)
    return obj


def record_hash(prev: str, rec: Dict[str, Any]) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256((prev + canonical(body)).encode("utf-8")).hexdigest()


def _segments(root: Path) -> List[Path]:
    return sorted(p for p in root.glob("seg-*.jsonl") if SEG_RE.match(p.name))


def _seg_no(p: Path) -> int:
    return int(SEG_RE.match(p.name).group(1))


def _read_lines(p: Path) -> List[dict]:
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


class Ledger:
    def __init__(self, root: str, max_records: int = 500):
        self.root = Path(root).expanduser()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_records = max_records
        self._lock = self.root / ".lock"

    # -- writing ---------------------------------------------------------------------------------
    def _tail(self):
        """(segment path or None, record count in it, last seq, last hash). Read from disk every time so
        several processes can append safely under the lock."""
        segs = _segments(self.root)
        if not segs:
            return None, 0, 0, GENESIS
        last = segs[-1]
        lines = _read_lines(last)
        recs = [l for l in lines if l.get("type") == "rec"]
        sealed = any(l.get("type") == "seal" for l in lines)
        if recs:
            return (None if sealed else last), len(recs), recs[-1]["seq"], recs[-1]["hash"]
        header = lines[0] if lines else {"prev": GENESIS, "start_seq": 1}
        return (None if sealed else last), 0, header["start_seq"] - 1, header["prev"]

    def append(self, actor: str, kind: str, data: Optional[dict] = None) -> dict:
        with open(self._lock, "a+") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            seg, count, seq, prev = self._tail()
            if seg is not None and count >= self.max_records:
                self._seal(seg, count, prev)
                seg = None
            if seg is None:
                n = (_seg_no(_segments(self.root)[-1]) + 1) if _segments(self.root) else 1
                seg = self.root / f"seg-{n:06d}.jsonl"
                self._write(seg, {"type": "segment", "n": n, "start_seq": seq + 1, "prev": prev})
            rec = {"type": "rec", "seq": seq + 1, "ts": datetime.now(timezone.utc).isoformat(), "actor": actor,
                   "kind": kind, "data": redact(data or {}), "prev": prev}
            rec["hash"] = record_hash(prev, rec)
            self._write(seg, rec)
            return rec

    def _seal(self, seg: Path, count: int, last_hash: str):
        self._write(seg, {"type": "seal", "n": _seg_no(seg), "count": count, "last": last_hash})

    @staticmethod
    def _write(path: Path, obj: dict):
        with open(os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600), "a", encoding="utf-8", closefd=True) as f:
            f.write(canonical(obj) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def anchor(self, path: Optional[str] = None) -> dict:
        """Record the current head hash. Copy this line somewhere the agent cannot write."""
        with open(self._lock, "a+") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            _, _, seq, head = self._tail()
        a = {"seq": seq, "hash": head, "ts": datetime.now(timezone.utc).isoformat()}
        target = Path(path).expanduser() if path else self.root / "anchors.jsonl"
        with open(target, "a", encoding="utf-8") as f:
            f.write(canonical(a) + "\n")
        return a

    def records(self) -> List[dict]:
        out = []
        for s in _segments(self.root):
            out += [l for l in _read_lines(s) if l.get("type") == "rec"]
        return out

    def verify(self, anchors: Optional[str] = None, check_anchors: bool = True) -> dict:
        return verify(str(self.root), anchors, check_anchors)


def verify(root: str, anchors: Optional[str] = None, check_anchors: bool = True) -> dict:
    """Walk every segment and report every problem found, never just the first."""
    rootp = Path(root).expanduser()
    problems: List[str] = []
    segs = _segments(rootp)
    prev, seq_expected, total = GENESIS, 1, 0
    head = {"seq": 0, "hash": GENESIS}
    nos = [_seg_no(s) for s in segs]
    if nos and nos != list(range(1, len(nos) + 1)):
        missing = sorted(set(range(1, max(nos) + 1)) - set(nos))
        problems.append(f"segment numbering is not 1..{max(nos)} (missing: {missing or 'none; first segment gone'})")
    for i, seg in enumerate(segs):
        try:
            lines = _read_lines(seg)
        except Exception as e:  # unreadable or edited into invalid JSON
            problems.append(f"{seg.name}: unreadable ({type(e).__name__})")
            continue
        if not lines or lines[0].get("type") != "segment":
            problems.append(f"{seg.name}: missing header")
            continue
        h = lines[0]
        if h.get("prev") != prev:
            problems.append(f"{seg.name}: header prev hash does not match the previous segment's end")
            prev = h.get("prev", prev)
        if h.get("start_seq") != seq_expected:
            problems.append(f"{seg.name}: starts at seq {h.get('start_seq')}, expected {seq_expected}")
            seq_expected = h.get("start_seq", seq_expected)
        recs = [l for l in lines[1:] if l.get("type") == "rec"]
        seals = [l for l in lines[1:] if l.get("type") == "seal"]
        for r in recs:
            if r.get("prev") != prev:
                problems.append(f"{seg.name}: seq {r.get('seq')} prev hash broken (record removed, inserted or reordered)")
            if r.get("seq") != seq_expected:
                problems.append(f"{seg.name}: seq {r.get('seq')} out of order, expected {seq_expected}")
            if record_hash(r.get("prev", ""), r) != r.get("hash"):
                problems.append(f"{seg.name}: seq {r.get('seq')} content does not match its hash (edited)")
            prev = r.get("hash", prev)
            seq_expected = r.get("seq", seq_expected) + 1
            total += 1
            head = {"seq": r.get("seq"), "hash": r.get("hash")}
        last_segment = i == len(segs) - 1
        if seals:
            s = seals[-1]
            if s.get("count") != len(recs) or s.get("last") != (recs[-1]["hash"] if recs else h.get("prev")):
                problems.append(f"{seg.name}: seal does not match contents (records changed or cut)")
        elif not last_segment:
            problems.append(f"{seg.name}: not sealed but a later segment exists (tail cut or seal removed)")
    if check_anchors:
        ap = Path(anchors).expanduser() if anchors else rootp / "anchors.jsonl"
        if ap.exists():
            by_seq = {}
            for s in segs:
                try:
                    for l in _read_lines(s):
                        if l.get("type") == "rec":
                            by_seq[l["seq"]] = l["hash"]
                except Exception:
                    pass
            for line in ap.read_text().splitlines():
                if not line.strip():
                    continue
                a = json.loads(line)
                if a["seq"] == 0:
                    continue
                if a["seq"] not in by_seq:
                    problems.append(f"anchor seq {a['seq']}: that record is gone (log truncated or rewritten shorter)")
                elif by_seq[a["seq"]] != a["hash"]:
                    problems.append(f"anchor seq {a['seq']}: hash differs (history rewritten after the anchor)")
    return {"ok": not problems, "segments": len(segs), "records": total, "head": head, "problems": problems}
