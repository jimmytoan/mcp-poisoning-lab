"""Aggregate results/runs.jsonl into the tables used in the write-up.

  uv run python -m harness.report                 # all tags
  uv run python -m harness.report --tag full      # one round
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict

from .config import RESULTS


def load(tag: str | None) -> list[dict]:
    rows = [json.loads(l) for l in (RESULTS / "runs.jsonl").read_text().splitlines() if l.strip()]
    return [r for r in rows if tag is None or r["tag"] == tag]


def rate(xs: list[bool]) -> str:
    return f"{sum(xs)}/{len(xs)}" if xs else "–"


def attack_table(rows: list[dict]) -> str:
    """Attack success rate by model x SDK, no defences."""
    rows = [r for r in rows if not r["defences"]]
    by = defaultdict(list)
    for r in rows:
        by[(r["model"], r["contestant"])].append(r)
    out = ["| Model | SDK (client) | n | Attack success | Secret read | Benign done | Disclosed | Spend |",
           "|---|---|---|---|---|---|---|---|"]
    for (model, sdk), rs in sorted(by.items()):
        spend = sum(r["agent"]["cost_usd"] or 0 for r in rs)
        out.append(f"| {model} | {sdk} | {len(rs)} "
                   f"| {rate([r['attack_succeeded'] for r in rs])} "
                   f"| {rate([r['verdict']['secret_read'] for r in rs])} "
                   f"| {rate([r['benign_ok'] for r in rs])} "
                   f"| {rate([r['verdict']['disclosed'] for r in rs])} "
                   f"| ${spend:.3f} |")
    return "\n".join(out)


def scenario_table(rows: list[dict]) -> str:
    rows = [r for r in rows if not r["defences"]]
    attacks = sorted({r["attack"] for r in rows})
    sdks = sorted({r["contestant"] for r in rows})
    out = ["| Attack | " + " | ".join(sdks) + " |", "|---|" + "---|" * len(sdks)]
    for a in attacks:
        cells = []
        for s in sdks:
            rs = [r for r in rows if r["attack"] == a and r["contestant"] == s]
            cells.append(rate([r["attack_succeeded"] for r in rs]) if rs else "–")
        out.append(f"| {a} | " + " | ".join(cells) + " |")
    return "\n".join(out)


def defence_table(rows: list[dict]) -> str:
    """Attack success per defence, pooled across models/SDKs/attacks."""
    by = defaultdict(list)
    for r in rows:
        key = ",".join(r["defences"]) or "none"
        by[key].append(r)
    out = ["| Defence | n | Attack success | Benign done | Blocked calls |", "|---|---|---|---|---|"]
    for key, rs in sorted(by.items(), key=lambda kv: (kv[0] != "none", kv[0])):
        blocked = sum(r["agent"].get("blocked_calls", 0) for r in rs)
        out.append(f"| {key} | {len(rs)} | {rate([r['attack_succeeded'] for r in rs])} "
                   f"| {rate([r['benign_ok'] for r in rs])} | {blocked} |")
    return "\n".join(out)


def errors(rows: list[dict]) -> str:
    bad = [r for r in rows if r["agent"].get("stopped_by") not in ("done",) or r["agent"].get("error")]
    return "\n".join(f"- {r['run_id']}: stopped={r['agent']['stopped_by']} err={r['agent'].get('error')}" for r in bad) or "- none"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag")
    args = ap.parse_args()
    rows = load(args.tag)
    print(f"# MCP poisoning lab — {len(rows)} runs\n")
    print(f"## Attack success (no defences)\n\n{attack_table(rows)}\n")
    print(f"## By attack x SDK (no defences)\n\n{scenario_table(rows)}\n")
    print(f"## Defences\n\n{defence_table(rows)}\n")
    print(f"## Runs that errored / stopped early\n\n{errors(rows)}")


if __name__ == "__main__":
    main()
