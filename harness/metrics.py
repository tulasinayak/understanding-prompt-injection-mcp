"""Attack success rate and utility per (model, defense), computed from run_end audit records.

    uv run python -m harness.metrics                 # results/audit.jsonl
    uv run python -m harness.metrics results/x.jsonl
"""
from __future__ import annotations

import math
import sys
from collections import defaultdict
from pathlib import Path

from audit.logger import read_records, verify_chain


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _rate(successes: int, n: int) -> dict:
    lo, hi = wilson(successes, n)
    return {"k": successes, "n": n, "rate": successes / n if n else None, "lo": lo, "hi": hi}


def run_ends(path) -> list[dict]:
    """Finished runs, with defense labels in their current spelling (old logs say d1, all, ...)
    and the fields newer logs added filled in from the scenario files where missing."""
    from defenses.config import DefenseConfig
    from harness.scenarios import load_scenarios
    known = {s.id: s for s in load_scenarios("all")}
    runs = []
    for r in read_records(path):
        if r.get("type") != "run_end":
            continue
        r["defense"] = DefenseConfig.parse(r["defense"]).label
        s = known.get(r["scenario_id"])
        r.setdefault("source", s.source if s else "unknown")
        r.setdefault("goal", s.goal if s else "")
        r.setdefault("attack_kind", s.attack_kind if s else "tool")
        r.setdefault("aux_calls", 0)
        runs.append(r)
    return runs


def summarize(runs: list[dict]) -> list[dict]:
    """One row per (model, defense). Runs that errored count as not hijacked / task failed.
    asr_tool / asr_answer split the attacks by what the attacker wanted: an action, or a
    wrong answer to the user."""
    groups = defaultdict(list)
    for r in runs:
        groups[(r["model"], r["defense"])].append(r)
    rows = []
    for (model, defense), rs in sorted(groups.items()):
        attacked = [r for r in rs if r["injected"]]
        benign = [r for r in rs if not r["injected"]]
        tool = [r for r in attacked if r.get("attack_kind", "tool") == "tool"]
        answer = [r for r in attacked if r.get("attack_kind") == "answer"]
        rows.append({
            "model": model, "defense": defense,
            "asr": _rate(sum(r["hijacked"] for r in attacked), len(attacked)),
            "asr_tool": _rate(sum(r["hijacked"] for r in tool), len(tool)),
            "asr_answer": _rate(sum(r["hijacked"] for r in answer), len(answer)),
            "attempted": _rate(sum(r["attack_attempted"] for r in attacked), len(attacked)),
            "utility_attacked": _rate(sum(r["task_ok"] for r in attacked), len(attacked)),
            "utility_benign": _rate(sum(r["task_ok"] for r in benign), len(benign)),
            "mean_seconds": round(sum(r["duration_s"] for r in rs) / len(rs), 1),
            "mean_model_calls": round(sum(r["model_calls"] + r["guard_calls"] + r.get("aux_calls", 0) for r in rs) / len(rs), 1),
            "errors": sum(1 for r in rs if r.get("error")),
        })
    return rows


def fmt_rate(x: dict) -> str:
    if not x["n"]:
        return "-"
    return f"{x['rate']:.0%} ({x['k']}/{x['n']}, {x['lo']:.0%}-{x['hi']:.0%})"


def to_markdown(rows: list[dict]) -> str:
    head = ("| model | defense | ASR | attempted | utility (attacked) | utility (benign) | s/run | calls/run | errors |\n"
            "|---|---|---|---|---|---|---|---|---|\n")
    return head + "\n".join(
        f"| {r['model']} | {r['defense']} | {fmt_rate(r['asr'])} | {fmt_rate(r['attempted'])} | "
        f"{fmt_rate(r['utility_attacked'])} | {fmt_rate(r['utility_benign'])} | "
        f"{r['mean_seconds']} | {r['mean_model_calls']} | {r['errors']} |"
        for r in rows)


def main() -> None:
    from harness.run import DEFAULT_AUDIT
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_AUDIT
    runs = run_ends(path)
    if not runs:
        print(f"No finished runs in {path}")
        return
    chain = verify_chain(path)
    print(to_markdown(summarize(runs)))
    print(f"\n{len(runs)} runs. Rates show (count, Wilson 95% interval).")
    print("Audit hash chain: " + ("intact" if chain["ok"] else f"BROKEN at line {chain['bad_line']}"))


if __name__ == "__main__":
    main()
