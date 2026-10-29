"""Instant revocation from the command line.
  python freeze.py freeze all --reason "incident"          stop every payment
  python freeze.py freeze merchant:shop.example --reason x stop one merchant
  python freeze.py freeze card:vc_abc...                   stop one stored card
  python freeze.py freeze agent:vault-harness              stop this agent
  python freeze.py lift all | list
Checked when a payment is decided, again right before it is made, and mirrored into the enclave as a user-signed revocation."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vault_harness import alerts, guard  # noqa: E402


def main(a):
    f = guard.Freezes()
    if not a or a[0] == "list":
        for r in f.active():
            print(f"{r['scope']:34s} {r.get('reason','')}  (by {r.get('by','?')})")
        print(f"{len(f.active())} active freeze(s)"); return 0
    if a[0] == "freeze" and len(a) >= 2:
        reason = a[a.index("--reason") + 1] if "--reason" in a else ""
        f.freeze(a[1], reason); alerts.emit("freeze_set", "critical", scope=a[1], reason=reason); print("frozen:", a[1]); return 0
    if a[0] == "lift" and len(a) >= 2:
        f.lift(a[1]); alerts.emit("freeze_lifted", "warn", scope=a[1]); print("lifted:", a[1]); return 0
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
