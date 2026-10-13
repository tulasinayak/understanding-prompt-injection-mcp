"""Print the runs in an audit file step by step.

    uv run python tools/show_runs.py                          # results/audit.jsonl
    uv run python tools/show_runs.py results/x.jsonl dual     # only runs whose defense contains "dual"
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit.logger import read_records  # noqa: E402


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "results/audit.jsonl"
    only = sys.argv[2] if len(sys.argv) > 2 else ""
    sys.stdout.reconfigure(errors="replace")
    show = True
    for r in read_records(path):
        if r["type"] == "run_start":
            show = only in r["defense"]
            if show:
                print(f"\n{r['scenario_id']} | {r['defense']} | {'attack' if r['injected'] else 'benign'}")
        elif not show:
            continue
        elif r["type"] == "tool_call":
            note = ""
            if r.get("detector"):
                note = f"  [detector: {'FLAGGED' if r['detector']['flagged'] else 'clean'} {r['detector']['score'] or ''}]"
            elif r.get("quarantine"):
                q = r["quarantine"]
                note = f"  [{q.get('refused') or 'agent saw: ' + q.get('shown', '')[:110]}]"
            elif not r["executed"]:
                blocker = r["guard"] if r.get("guard") and not r["guard"]["allow"] else r.get("policy") or {}
                note = f"  [{blocker.get('reason', '')}]"
            status = "ran    " if r["executed"] else "BLOCKED"
            print(f"  {r['step']:>2}. {status} {r['tool']}({str(r['args'])[:100]}){note}")
            if r["tool"] == "ask_quarantined":
                print(f"        -> {r['result_preview'][:110]}")
        else:
            verdict = ("HIJACKED" if r["hijacked"] else "attempt blocked" if r["attack_attempted"] else "safe") \
                if r["injected"] else "-"
            print(f"  => {verdict} | task {'ok' if r['task_ok'] else 'FAILED'} | {r['duration_s']}s | "
                  f"other defense calls {r.get('aux_calls', 0)} | filter {r.get('tool_filter')} | error {r['error']}")
            print(f"     answer: {r['final_answer'][:160]!r}")


if __name__ == "__main__":
    main()
