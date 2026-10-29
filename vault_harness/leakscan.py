"""Leak scanner: finds card numbers in files. Run it over every place a run can write (ledger, alerts, events DB, card store, checkpoints,
logs, traces). A hit is a Luhn-valid 13-19 digit run (spaces/dashes allowed), or a literal you name. Hex strings of 24+ chars (digests, nonces, ciphertext) and id tokens such as vc_/ph_/pi_ are ignored: a card number is at most 19 digits.
SCOPE: files only. It cannot see process memory, swap, or core dumps; those are covered by the enclave design, not by this test."""
import re
import sys
from pathlib import Path

from vault_harness import policy

HEX = re.compile(rb"\b[0-9a-fA-F]{24,}\b")
TOKEN = re.compile(rb"\b(?:vc|ph|pi|pm|ch|cs|cauth|cprep|sess)_[0-9A-Za-z_]+")          # our own and Stripe's id formats: random alphanumerics, not cards
SKIP = {".git", ".venv", "__pycache__", "node_modules"}


def luhn_ok(s: str) -> bool:
    d = [int(c) for c in s][::-1]
    return sum(x if i % 2 == 0 else (x * 2 - 9 if x * 2 > 9 else x * 2) for i, x in enumerate(d)) % 10 == 0


def scan(paths, literals=()) -> list:
    out = []
    for root in map(Path, paths):
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and not (SKIP & set(p.parts))] if root.exists() else []
        for f in files:
            try:
                raw = f.read_bytes()
            except OSError:
                continue
            text = HEX.sub(b"", TOKEN.sub(b"", raw)).decode("latin-1")
            for lit in literals:
                if lit in text:
                    out.append((str(f), "literal", "****" + lit[-4:]))
            for m in policy.PAN_RE.finditer(text):
                digits = re.sub(r"\D", "", m.group(0))
                if luhn_ok(digits):
                    out.append((str(f), "card-number", "****" + digits[-4:]))      # never echo the number itself
    return out


if __name__ == "__main__":
    hits = scan(sys.argv[1:] or ["output"])
    for h in hits:
        print("LEAK", *h)
    print(f"{len(hits)} finding(s)")
    sys.exit(1 if hits else 0)
