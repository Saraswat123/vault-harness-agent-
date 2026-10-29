"""Step 1 of the Kernel + Agentcard Vault flow: vault, agentcard wallet, and the card-enrollment link for the USER.
The link is written to output/enroll_url.txt (mode 600) and NOT printed: it must reach the user, never an agent.
  python kernel_enroll.py            create/reuse the vault and wallet, save the link
  python kernel_enroll.py --status   wait up to 60 s and report whether the wallet is connected and has payment methods
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from vault_harness.kernel_vault import KernelVault  # noqa: E402

VAULT = "vault-harness-test"


def find_urls(x, path=""):
    if isinstance(x, dict):
        for k, v in x.items():
            yield from find_urls(v, f"{path}.{k}")
    elif isinstance(x, str) and x.startswith("http"):
        yield path, x


def main():
    kv = KernelVault()
    v = kv.upsert_vault(VAULT)
    w = kv.upsert_wallet(VAULT)
    if "--status" in sys.argv:
        w = kv.get_item(VAULT, w.get("key", "agentcard-wallet"), wait=60)
    state = w.get("state") or {}
    print(f"vault: {v.get('name')} id={str(v.get('id'))[:12]}…")
    print(f"wallet: key={w.get('key')} type={w.get('type')} state.status={state.get('status')!r}")
    print("wallet fields:", sorted(w.keys()))
    print("state fields:", sorted(state.keys()), "| available operations:", [o.get("name", o) if isinstance(o, dict) else o for o in (w.get("available_operations") or [])])
    act = w.get("action")
    if act:
        print("action:", {k: ("<hidden>" if isinstance(val, str) and val.startswith("http") else val) for k, val in act.items()} if isinstance(act, dict) else act)
        urls = list(find_urls(act))
        if urls:
            out = ROOT / "output" / "enroll_url.txt"
            out.parent.mkdir(exist_ok=True)
            out.write_text(urls[0][1] + "\n"); out.chmod(0o600)
            print(f"enrollment link saved to {out} (not printed). Open it yourself:  open \"$(cat {out})\"")
    else:
        print("no action pending")


if __name__ == "__main__":
    main()
