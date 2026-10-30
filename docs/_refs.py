"""Render docs/_src/*.md into the repo, replacing [[path::symbol]] with `path:line` taken from the real source, and VERIFYING that every
test name and golden-eval case id mentioned in the docs actually exists. Exits non-zero on any dangling reference, so documentation cannot drift
from the code.   python docs/_refs.py"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "_src"
OUT = {"README.md": ROOT / "README.md", "CREDENTIAL_ISOLATION.md": ROOT / "docs" / "CREDENTIAL_ISOLATION.md", "GUARDRAILS.md": ROOT / "docs" / "GUARDRAILS.md"}
errors = []


def line_of(path: str, symbol: str) -> int:
    f = ROOT / path
    if not f.is_file():
        errors.append(f"missing file: {path}"); return 0
    pat = re.compile(rf"^\s*(?:def|class|async def|export async function|export function|function)\s+{re.escape(symbol)}\b")
    for n, l in enumerate(f.read_text().splitlines(), 1):
        if pat.match(l):
            return n
    errors.append(f"symbol not found: {path}::{symbol}"); return 0


tests = "\n".join(p.read_text() for p in (ROOT / "tests").glob("*.py"))
cases = {c["id"] for c in json.loads((ROOT / "evals" / "golden" / "payment_cases.json").read_text())["cases"]}
for name, dest in OUT.items():
    text = (SRC / name).read_text()
    text = re.sub(r"\[\[([^\]:]+)::([^\]]+)\]\]", lambda m: f"`{m.group(1)}:{line_of(m.group(1), m.group(2))}`", text)
    for t in sorted(set(re.findall(r"\b(test_[a-z0-9_]*[a-z0-9])\b", text))):
        if t.startswith("test_") and not re.search(rf"def {t}\b", tests) and not (ROOT / "tests" / f"{t}.py").exists():
            errors.append(f"{name}: test not found: {t}")
    for c in sorted(set(re.findall(r"`((?:ctl|atk|leak)_[a-z0-9_]*[a-z0-9])`", text))):
        if c not in cases:
            errors.append(f"{name}: eval case not found: {c}")
    dest.write_text(text)
    print("rendered", dest.relative_to(ROOT))
if errors:
    print("\nDANGLING REFERENCES:"); [print("  -", e) for e in sorted(set(errors))]; sys.exit(1)
print("all code references, test names and eval cases resolve")
