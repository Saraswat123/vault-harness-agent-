"""The ONLY place with a real side effect. Dry run is the default. Replace the body with your real
action (send, post, write to a system) and keep it behind this one function."""
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent / "output"


def perform(text: str, dry_run: bool = True) -> dict:
    if dry_run:
        return {"status": "dry_run", "chars": len(text)}
    OUT_DIR.mkdir(exist_ok=True)
    f = OUT_DIR / "result.txt"
    f.write_text(text)
    return {"status": "done", "path": str(f)}
