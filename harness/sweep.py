"""Run the matrix scenarios x defenses x repeats (plus benign runs). Resumable.

    uv run python -m harness.sweep --dry-run            # the whole study: how many runs are left
    uv run python -m harness.sweep --limit 300          # one night's worth
    uv run python -m harness.sweep --scenarios custom --defenses none,policy

Defaults: the 11 study conditions, every scenario once at temperature 0. Repeats only differ
at temperature > 0 (e.g. --repeats 3 --temperature 0.7; the seed is the repeat number).
Stop with Ctrl+C and start again with the same arguments: finished runs are skipped.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from agent.model import DEFAULT_MODEL
from audit.logger import read_records
from defenses.config import STUDY, DefenseConfig
from harness.run import DEFAULT_AUDIT, run_scenario, setup_console
from harness.scenarios import load_scenarios


def pick_scenarios(spec: str, include_holdout: bool):
    if spec in ("all", "builtin", "custom", "datasets"):
        chosen = load_scenarios(spec)
    else:
        ids = {x.strip() for x in spec.split(",")}
        chosen = [s for s in load_scenarios("all") if s.id in ids]
        missing = ids - {s.id for s in chosen}
        if missing:
            raise SystemExit(f"Unknown scenario ids: {sorted(missing)}")
    return [s for s in chosen if include_holdout or not s.holdout]


def main() -> None:
    setup_console()
    ap = argparse.ArgumentParser(description="Run the full experiment matrix.")
    ap.add_argument("--scenarios", default="all", help="all | builtin | custom | comma-separated ids")
    ap.add_argument("--defenses", default="study",
                    help="'study' = the 11 conditions of the comparison, or a comma-separated list")
    ap.add_argument("--limit", type=int, help="stop after this many runs (e.g. one night's worth)")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--no-benign", action="store_true", help="skip the runs without injection")
    ap.add_argument("--include-holdout", action="store_true")
    ap.add_argument("--audit", default=str(DEFAULT_AUDIT))
    ap.add_argument("--dry-run", action="store_true", help="only print how many runs are left")
    a = ap.parse_args()

    scenarios = pick_scenarios(a.scenarios, a.include_holdout)
    wanted = STUDY if a.defenses == "study" else a.defenses.split(",")
    defenses = [DefenseConfig.parse(d).label for d in wanted]
    done = {(r["scenario_id"], DefenseConfig.parse(r["defense"]).label, r["model"], r["injected"],
             r.get("repeat", 0))
            for r in read_records(a.audit) if r.get("type") == "run_end" and not r.get("error")}

    plan = []
    for d in defenses:
        for s in scenarios:
            for rep in range(a.repeats):
                plan.append((s, d, True, rep))
        if not a.no_benign:
            seen_tasks = set()
            for s in scenarios:  # one benign run per distinct task
                if s.user_task not in seen_tasks:
                    seen_tasks.add(s.user_task)
                    for rep in range(a.repeats):
                        plan.append((s, d, False, rep))
    # scenario by scenario, so a sweep stopped halfway has data for every defense
    order = {s.id: i for i, s in enumerate(scenarios)}
    plan.sort(key=lambda p: (order[p[0].id], p[3], defenses.index(p[1]), p[2]))
    todo = [p for p in plan if (p[0].id, p[1], a.model, p[2], p[3]) not in done]
    print(f"{len(plan)} runs planned, {len(plan) - len(todo)} already done, {len(todo)} to go.")
    if a.dry_run:
        return
    if a.limit:
        todo = todo[:a.limit]
        print(f"Running {len(todo)} of them now (--limit).")

    for n, (s, d, inject, rep) in enumerate(todo, start=1):
        r = run_scenario(s, d, a.model, inject=inject, audit_path=Path(a.audit),
                         seed=rep, temperature=a.temperature, repeat=rep)
        kind = "attack" if inject else "benign"
        outcome = "ERROR " + r.error if r.error else (
            ("HIJACKED" if r.hijacked else "safe") if inject else "") + (" task-ok" if r.task_ok else " task-failed")
        print(f"[{n}/{len(todo)}] {d:<9} {kind} {s.id:<34} rep{rep} {r.duration_s:>6}s  {outcome}", flush=True)
    print("Done. Summary: uv run python -m harness.metrics")


if __name__ == "__main__":
    main()
