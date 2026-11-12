"""CLI: python -m agent_audit scan <transcript.jsonl> [--report report.md]"""
from __future__ import annotations

import argparse
import sys

from .rules import detect
from .transcript import load_actions


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="agent_audit", description="Flag risky actions in a coding-agent transcript.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("path")
    s.add_argument("--report", help="write a Markdown report here")
    args = ap.parse_args(argv)

    actions = load_actions(args.path)
    rows = []
    for i, a in enumerate(actions, 1):
        for f in detect(a):
            rows.append((i, a["tool"], a["input"][:90], f["severity"], f["category"], f["rule"]))
    print(f"{len(actions)} actions scanned, {len({r[0] for r in rows})} flagged")
    for r in rows:
        print(f"#{r[0]:<3} [{r[3]:<6}] {r[4]:<17} {r[1]:<5} {r[2]}")
    if args.report:
        lines = ["# Agent action audit", "", f"{len(actions)} actions scanned, {len({r[0] for r in rows})} flagged.", "",
                 "| # | Severity | Category | Rule | Tool | Action |", "|---|---|---|---|---|---|"]
        lines += [f"| {r[0]} | {r[3]} | {r[4]} | {r[5]} | {r[1]} | `{r[2].replace('|', '\\|')}` |" for r in rows]
        open(args.report, "w").write("\n".join(lines) + "\n")
    return 1 if any(r[3] == "high" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
