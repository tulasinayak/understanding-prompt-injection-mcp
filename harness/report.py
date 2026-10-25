"""Build the comparison report from the audit trail.

    uv run python -m harness.report                       # results/audit.jsonl -> results/REPORT.md
    uv run python -m harness.report results/x.jsonl --model qwen3:8b

The report has the main table (one row per defense), breakdowns by attack source and
attacker goal, and per-defense evidence: which attacks got through and which benign tasks
broke, each with a real trace from the log. The numbers are generated; the interpretation
section at the end of REPORT.md is kept between runs and is written by hand.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from audit.logger import read_records, verify_chain
from defenses.config import STUDY
from harness.metrics import _rate, fmt_rate, infra_errors, run_ends, summarize
from harness.run import DEFAULT_AUDIT

MARK = "<!-- interpretation: everything below this line is kept when the report is regenerated -->"

WHAT = {
    "none": ("-", "no defense"),
    "spotlight": ("what the model reads", "tool output wrapped in tagged data markers"),
    "sandwich": ("what the model reads", "user's request repeated after each tool result"),
    "toolfilter": ("what the model may do", "model picks its tools before reading anything"),
    "detect-llm": ("what the model reads", "a model flags injected tool output; flagged output is withheld"),
    "detect-clf": ("what the model reads", "a classifier flags injected tool output; flagged output is withheld"),
    "summarize": ("what the model reads", "naive quarantine: agent sees a summary of tool output"),
    "dual": ("what the model never sees", "strict Dual LLM: agent sees handles, a tool-less model reads"),
    "policy": ("what the model may do", "allow-list + taint rule, in code"),
    "guard": ("what the model may do", "a second model approves each side-effect call"),
}


def _layer(defense: str) -> tuple[str, str]:
    if defense in WHAT:
        return WHAT[defense]
    return ("layered", "combination: " + defense)


def _order(defense: str) -> int:
    return STUDY.index(defense) if defense in STUDY else len(STUDY)


def _trace(records_by_run: dict, run_id: str) -> str:
    lines = []
    for r in records_by_run.get(run_id, []):
        status = "ran" if r["executed"] else "BLOCKED"
        note = ""
        if r.get("detector") and r["detector"]["flagged"]:
            note = "  [detector withheld the result]"
        elif r.get("quarantine") and r["quarantine"].get("refused"):
            note = f"  [{r['quarantine']['refused']}]"
        elif not r["executed"]:
            blocker = r["guard"] if r.get("guard") and not r["guard"]["allow"] else r.get("policy")
            note = f"  [{blocker['reason']}]" if blocker else ""
        lines.append(f"{r['step']}. {status} {r['tool']}({json.dumps(r['args'], ensure_ascii=False)[:140]}){note}")
    return "\n".join(lines) or "(no tool calls)"


def _breakdown(runs: list[dict], key: str) -> str:
    values = sorted({r[key] or "-" for r in runs if r["injected"]})
    defenses = sorted({r["defense"] for r in runs}, key=_order)
    head = f"| defense | {' | '.join(values)} |\n|---|{'---|' * len(values)}\n"
    body = []
    for d in defenses:
        cells = []
        for v in values:
            rs = [r for r in runs if r["injected"] and r["defense"] == d and (r[key] or "-") == v]
            x = _rate(sum(r["hijacked"] for r in rs), len(rs))
            cells.append(f"{x['rate']:.0%} ({x['k']}/{x['n']})" if x["n"] else "-")
        body.append(f"| {d} | {' | '.join(cells)} |")
    return head + "\n".join(body)


def _source_table(runs: list[dict]) -> str:
    """ASR per attack source (dataset) and defense, with Wilson intervals."""
    sources = sorted({r["source"] for r in runs if r["injected"]})
    defenses = sorted({r["defense"] for r in runs}, key=_order)
    out = [f"| defense | {' | '.join(sources)} |", f"|---|{'---|' * len(sources)}"]
    for d in defenses:
        cells = []
        for s in sources:
            rs = [r for r in runs if r["injected"] and r["defense"] == d and r["source"] == s]
            cells.append(fmt_rate(_rate(sum(r["hijacked"] for r in rs), len(rs))))
        out.append(f"| {d} | {' | '.join(cells)} |")
    return "\n".join(out)


def _attack_matrix(runs: list[dict]) -> str:
    """One row per attack: what happened under each defense.
    H = hijacked, b = the model tried and the defense blocked it, . = model did not try, ? = not run."""
    from harness.scenarios import load_scenarios
    info = {s.id: s for s in load_scenarios("all")}
    defenses = sorted({r["defense"] for r in runs}, key=_order)
    cell = {(r["scenario_id"], r["defense"]): ("H" if r["hijacked"] else "b" if r["attack_attempted"] else ".")
            for r in runs if r["injected"]}
    ids = sorted({r["scenario_id"] for r in runs if r["injected"]},
                 key=lambda i: (info[i].source if i in info else "~", i))
    out = [f"| attack | source | goal | style | {' | '.join(defenses)} | beat |",
           f"|---|---|---|---|{'---|' * len(defenses)}---|"]
    for i in ids:
        s = info.get(i)
        marks = [cell.get((i, d), "?") for d in defenses]
        beat = sum(m == "H" for m in marks[1:])
        out.append(f"| {i} | {s.source if s else '?'} | {s.goal if s else ''} | {s.style if s else ''} | "
                   f"{' | '.join(marks)} | {beat}/{len(marks) - 1} |")
    return "\n".join(out)


def _intent_table(runs: list[dict]) -> str:
    """Attacks grouped by malicious intent (the scenario `goal`). For each group: how many
    distinct attacks, then under no defense and under the layered defense, the attack success
    rate and the share of attacked runs where the user's own task was still completed."""
    attacked = [r for r in runs if r["injected"]]
    goals = sorted({r["goal"] or "(unlabelled)" for r in attacked})
    out = ["| malicious intent | attacks | ASR (none) | task kept (none) | "
           "ASR (layered) | task kept (layered) |", "|---|---|---|---|---|---|"]

    def row(label, rs):
        n_attacks = len({r["scenario_id"] for r in rs})
        none = [r for r in rs if r["defense"] == "none"]
        layered = [r for r in rs if r["defense"] == "spotlight+policy+guard"]
        return (f"| {label} | {n_attacks} | "
                f"{fmt_rate(_rate(sum(r['hijacked'] for r in none), len(none)))} | "
                f"{fmt_rate(_rate(sum(r['task_ok'] for r in none), len(none)))} | "
                f"{fmt_rate(_rate(sum(r['hijacked'] for r in layered), len(layered)))} | "
                f"{fmt_rate(_rate(sum(r['task_ok'] for r in layered), len(layered)))} |")

    for g in goals:
        out.append(row(g, [r for r in attacked if (r["goal"] or "(unlabelled)") == g]))
    out.append(row("**all attacks**", attacked))
    return "\n".join(out)


def _lang_table(runs: list[dict]) -> str:
    """Language x defense: ASR, attempted, utility under attack, benign utility (Wilson intervals).
    Benign utility for a language is measured on the user tasks that language's attacks use."""
    from harness.scenarios import load_scenarios
    task_of = {s.id: s.user_task for s in load_scenarios("all")}
    langs = sorted({r.get("lang", "en") for r in runs if r["injected"]})
    out = ["| language | defense | ASR | attempted | utility under attack | benign utility |",
           "|---|---|---|---|---|---|"]
    for lang in langs:
        attacked_all = [r for r in runs if r["injected"] and r.get("lang", "en") == lang]
        tasks = {task_of.get(r["scenario_id"]) for r in attacked_all}
        for d in sorted({r["defense"] for r in attacked_all}, key=_order):
            att = [r for r in attacked_all if r["defense"] == d]
            ben = [r for r in runs if not r["injected"] and r["defense"] == d
                   and task_of.get(r["scenario_id"]) in tasks]
            out.append(f"| {lang} | {d} | {fmt_rate(_rate(sum(r['hijacked'] for r in att), len(att)))} | "
                       f"{fmt_rate(_rate(sum(r['attack_attempted'] for r in att), len(att)))} | "
                       f"{fmt_rate(_rate(sum(r['task_ok'] for r in att), len(att)))} | "
                       f"{fmt_rate(_rate(sum(r['task_ok'] for r in ben), len(ben)))} |")
    return "\n".join(out)


def _setup(audit_path: Path, model: str) -> list[str]:
    """What the numbers were produced with, read from the run_start records."""
    starts = [r for r in read_records(audit_path) if r.get("type") == "run_start" and r.get("model") == model]
    digests = sorted({r.get("model_digest") or "unknown" for r in starts})
    temps = sorted({r.get("temperature") for r in starts if r.get("temperature") is not None})
    servers = sorted({", ".join(r.get("servers") or ["inbox", "files", "calendar"]) for r in starts})
    first, last = (starts[0]["ts"][:10], starts[-1]["ts"][:10]) if starts else ("-", "-")
    return [
        "## Setup", "",
        f"- **Agent model:** `{model}` served locally by Ollama"
        + (f" (digest `{digests[0][:12]}`)" if len(digests) == 1 else f" (digests: {', '.join(d[:12] for d in digests)})"),
        f"- **Decoding:** temperature {', '.join(str(x) for x in temps) or '-'}, fixed seed, context 8192 tokens, "
        "at most 512 new tokens per call; Qwen3 thinking mode off",
        "- **Defense models:** the guard, the LLM detector, the summarizer, the quarantined model and the tool "
        "filter use the same model as the agent; `detect-clf` uses `protectai/deberta-v3-base-prompt-injection-v2`",
        f"- **MCP servers:** {'; '.join(servers) or '-'}",
        "- **Hardware:** CPU only (no GPU)",
        f"- **Runs:** {first} to {last}; one run per scenario and condition",
        "",
    ]


def build(audit_path: Path, model: str | None = None) -> str:
    runs = run_ends(audit_path)
    models = sorted({r["model"] for r in runs})
    if model is None and models:
        model = max(models, key=lambda m: sum(r["model"] == m for r in runs))
    runs = [r for r in runs if r["model"] == model]
    if not runs:
        return f"# Comparison report\n\nNo finished runs for model {model!r} in {audit_path.name}.\n"

    by_run = defaultdict(list)
    for rec in read_records(audit_path):
        if rec.get("type") == "tool_call":
            by_run[rec["run_id"]].append(rec)
    rows = sorted(summarize(runs), key=lambda r: _order(r["defense"]))
    base = next((r for r in rows if r["defense"] == "none"), None)
    chain = verify_chain(audit_path)

    out = ["# Understanding Prompt Injection through MCP Tools: comparison report", ""]
    out.append(f"Model: `{model}`. Source: `{audit_path.name}`, {len(runs)} finished runs. "
               f"Audit hash chain: {'intact' if chain['ok'] else 'BROKEN at line ' + str(chain['bad_line'])}.")
    out.append("")
    failed = infra_errors(audit_path)
    if failed:
        out.append(f"{failed} runs that failed outside the agent (for example Ollama not running) are not "
                   "counted anywhere below.")
        out.append("")
    out += _setup(audit_path, model)
    missing = [d for d in STUDY if d not in {r["defense"] for r in rows}]
    if missing:
        out.append(f"**Incomplete:** no runs yet for: {', '.join(missing)}.")
        out.append("")
    counts = {r["defense"]: r["asr"]["n"] for r in rows}
    if len(set(counts.values())) > 1:
        out.append("**Uneven coverage:** the defenses were not all run on the same number of attacks "
                   f"({', '.join(f'{d}: {n}' for d, n in counts.items())}), so rows are not yet comparable.")
        out.append("")

    out += ["## Main table", "",
            "Rates are shown as rate (count, Wilson 95% interval). *ASR* (attack success rate): the attack "
            "achieved its goal, by either route. *Tool hijack*: the attacker's tool call "
            "was executed. *Wrong answer*: the attacker's text reached the user's answer. *Attempted*: the "
            "model went for the attack, whether or not a defense then stopped it.", "",
            "| defense | acts on | ASR | tool hijack | wrong answer | attempted | utility under attack | "
            "benign utility | calls/run | s/run |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| **{r['defense']}** | {_layer(r['defense'])[0]} | {fmt_rate(r['asr'])} | {fmt_rate(r['asr_tool'])} | "
                   f"{fmt_rate(r['asr_answer'])} | {fmt_rate(r['attempted'])} | "
                   f"{fmt_rate(r['utility_attacked'])} | {fmt_rate(r['utility_benign'])} | "
                   f"{r['mean_model_calls']} | {r['mean_seconds']} |")
    out.append("")
    if base:
        out.append(f"Baseline cost: {base['mean_model_calls']} model calls and {base['mean_seconds']} s per run "
                   "with no defense; the last two columns show what each defense adds.")
        out.append("")

    out += ["## Attack success by attack source", "", _breakdown(runs, "source"), "",
            "## Attack success by attacker goal", "", _breakdown(runs, "goal"), "",
            "## Language x defense", "",
            "Scenarios carry a `lang` field (default `en`). Benign utility per language is measured on the "
            "user tasks used by that language's attacks.", "", _lang_table(runs), "",
            "## Attacks grouped by malicious intent", "",
            "How many distinct attacks fall under each intent, and what happens to them with no "
            "defense and with the layered defense (`spotlight+policy+guard`). *ASR* is attack success "
            "rate; *task kept* is the share of attacked runs where the user's own request was still "
            "answered, which separates \"the defense worked\" from \"the attack broke the task\".", "",
            _intent_table(runs), "",
            "## ASR per dataset", "", "Attack success rate by attack source (count, Wilson 95% interval).", "",
            _source_table(runs), "",
            "## Every attack", "",
            "`H` hijacked · `b` the model tried, the defense blocked it · `.` the model did not try · "
            "`?` not run yet. *beat*: how many defenses the attack got past (the first column is no defense).", "",
            _attack_matrix(runs), "",
            "## Evidence per defense", ""]
    for r in rows:
        d = r["defense"]
        rs = [x for x in runs if x["defense"] == d]
        through = [x for x in rs if x["injected"] and x["hijacked"]]
        blocked = [x for x in rs if x["injected"] and x["attack_attempted"] and not x["hijacked"]]
        broken = [x for x in rs if not x["injected"] and not x["task_ok"]]
        out += [f"### {d}", "", f"*{_layer(d)[1]}*", "",
                f"- Attacks that got through ({len(through)}): "
                + (", ".join(sorted(x["scenario_id"] for x in through)) or "none"),
                f"- Attempts stopped by the defense ({len(blocked)}): "
                + (", ".join(sorted(x["scenario_id"] for x in blocked)) or "none"),
                f"- Benign tasks that failed ({len(broken)}): "
                + (", ".join(sorted(x["scenario_id"] for x in broken)) or "none"), ""]
        for title, group in (("An attack that got through", through), ("A stopped attempt", blocked),
                             ("A benign task that failed", broken)):
            if group:
                x = group[0]
                out += [f"{title} (`{x['scenario_id']}`):", "", "```", _trace(by_run, x["run_id"]),
                        f"answer: {x['final_answer'][:200]!r}", "```", ""]
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description="Write results/REPORT.md from the audit trail.")
    ap.add_argument("audit", nargs="?", default=str(DEFAULT_AUDIT))
    ap.add_argument("--model")
    ap.add_argument("--out")
    a = ap.parse_args()
    audit = Path(a.audit)
    name = "REPORT.md" if audit.stem == "audit" else f"REPORT-{audit.stem.removeprefix('audit-')}.md"
    out = Path(a.out) if a.out else audit.parent / name
    kept = ""
    if out.exists() and MARK in out.read_text(encoding="utf-8"):
        kept = out.read_text(encoding="utf-8").split(MARK, 1)[1]
    default_tail = ("\n\n## Interpretation\n\n_Not written yet. Fill this in once every defense has been "
                    "run on the full attack set._\n")
    out.write_text(build(audit, a.model) + "\n" + MARK + (kept or default_tail), encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
