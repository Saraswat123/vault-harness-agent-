"""python -m blackbox <command>   (ledger dir: --dir, or $BLACKBOX_DIR, default ~/.blackbox/ledger)"""
from __future__ import annotations

import argparse
import json
import os
import sys

from blackbox.halt import Halt
from blackbox.incident import create_incident
from blackbox.ledger import Ledger


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="blackbox")
    ap.add_argument("--dir", default=os.environ.get("BLACKBOX_DIR", "~/.blackbox/ledger"))
    ap.add_argument("--control-dir", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("append"); a.add_argument("--actor", required=True); a.add_argument("--kind", required=True); a.add_argument("--data", default="{}")
    v = sub.add_parser("verify"); v.add_argument("--anchors", default=None)
    s = sub.add_parser("show"); s.add_argument("--tail", type=int, default=20)
    an = sub.add_parser("anchor"); an.add_argument("--to", default=None, help="write the anchor here (use a path the agent cannot write)")
    h = sub.add_parser("halt"); h.add_argument("--agent", default=None); h.add_argument("--reason", required=True)
    r = sub.add_parser("resume"); r.add_argument("--agent", default=None)
    sub.add_parser("status")
    i = sub.add_parser("incident"); i.add_argument("--title", required=True); i.add_argument("--severity", default="medium")
    i.add_argument("--what", required=True); i.add_argument("--controls-failed", nargs="*", default=[]); i.add_argument("--dir-out", default="~/.blackbox/incidents")
    args = ap.parse_args(argv)

    led, halt = Ledger(args.dir), Halt(args.control_dir)
    if args.cmd == "append":
        print(json.dumps(led.append(args.actor, args.kind, json.loads(args.data))))
    elif args.cmd == "verify":
        rep = led.verify(args.anchors)
        print(f"{'OK' if rep['ok'] else 'TAMPERED OR BROKEN'}: {rep['records']} records in {rep['segments']} segments; head seq {rep['head']['seq']}")
        for p in rep["problems"]:
            print("  problem:", p)
        return 0 if rep["ok"] else 1
    elif args.cmd == "show":
        for rec in led.records()[-args.tail:]:
            print(f"{rec['seq']:>6} {rec['ts'][:19]} {rec['actor']:<14} {rec['kind']:<14} {json.dumps(rec['data'], ensure_ascii=False)[:110]}")
    elif args.cmd == "anchor":
        print(json.dumps(led.anchor(args.to)))
    elif args.cmd == "halt":
        info = halt.engage(args.agent, args.reason, by=os.environ.get("USER", "human"))
        led.append("human", "halt", {"scope": args.agent or "global", **info})
        print(f"HALT engaged ({args.agent or 'global'}): {args.reason}")
    elif args.cmd == "resume":
        ok = halt.release(args.agent)
        led.append("human", "resume", {"scope": args.agent or "global", "was_halted": ok})
        print("released" if ok else "nothing to release")
    elif args.cmd == "status":
        st = halt.status()
        if not st:
            print("halts: none (agents are free to run)")
        for name, info in st.items():
            scope = "GLOBAL HALT (every agent)" if name == "HALT" else f"HALT for agent '{name[5:]}'"
            print(f"{scope}: {info.get('reason', '?')}  [by {info.get('by', '?')} at {info.get('ts', '?')[:19]}]")
        rep = led.verify()
        print(f"ledger: {'OK' if rep['ok'] else 'PROBLEMS'}, {rep['records']} records, {rep['segments']} segments")
    elif args.cmd == "incident":
        path = create_incident(args.dir_out, args.title, args.severity, args.what, args.controls_failed, ledger=led, actor="human")
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
