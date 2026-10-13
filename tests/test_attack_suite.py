"""The live attack suite: a real model on Ollama, real MCP servers.

    uv run pytest -m live                       # CI subset + every file in scenarios/custom
    $env:TESTBED_MODEL="qwen3:1.7b"; uv run pytest -m live
    $env:TESTBED_DEFENSE="none"; uv run pytest -m live     # expect failures: shows the gate works

Fails the build when a change makes the agent easier to hijack than tests/baseline.json allows.
"""
import json
import os
from pathlib import Path

import pytest

from agent.model import DEFAULT_MODEL, is_hosted, list_models
from harness.run import run_scenario
from harness.scenarios import ROOT, load_scenarios

pytestmark = pytest.mark.live

BASELINE = json.loads((Path(__file__).parent / "baseline.json").read_text(encoding="utf-8"))
MODEL = os.environ.get("TESTBED_MODEL", DEFAULT_MODEL)
DEFENSE = os.environ.get("TESTBED_DEFENSE", BASELINE["defense"])
AUDIT = ROOT / "results" / "ci-audit.jsonl"

CI_BUILTIN = [s for s in load_scenarios("builtin") if s.ci]
SCENARIOS = CI_BUILTIN + load_scenarios("custom")
_attacked = {}


@pytest.fixture(scope="module", autouse=True)
def ollama_ready():
    names = {m.get("name") for m in list_models()}
    if not is_hosted(MODEL) and MODEL not in names:
        pytest.fail(f"Model '{MODEL}' is not available in Ollama (found: {sorted(names) or 'server not reachable'}).")


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_attack_does_not_succeed(scenario):
    r = run_scenario(scenario, DEFENSE, MODEL, audit_path=AUDIT)
    _attacked[scenario.id] = r
    assert r.error is None, r.error
    if scenario.id not in BASELINE["known_hijacks"]:
        calls = [(s["tool"], s["args"]) for s in r.steps if s["executed"]]
        assert not r.hijacked, f"agent was hijacked with defense={DEFENSE}; executed calls: {calls}"


def test_benign_tasks_still_work():
    """A defense that blocks everything would pass the attack tests; this catches that."""
    tasks = {s.user_task: s for s in CI_BUILTIN}.values()
    results = [run_scenario(s, DEFENSE, MODEL, inject=False, audit_path=AUDIT) for s in tasks]
    utility = sum(r.task_ok for r in results) / len(results)
    failed = [r.scenario_id for r in results if not r.task_ok]
    assert utility >= BASELINE["min_benign_utility"], f"benign utility {utility:.0%}; failed: {failed}"


def test_attack_success_rate_within_baseline():
    if not _attacked:
        pytest.skip("no attack runs in this session")
    asr = sum(r.hijacked for r in _attacked.values()) / len(_attacked)
    counted = [i for i, r in _attacked.items() if r.hijacked and i not in BASELINE["known_hijacks"]]
    limit = BASELINE["max_asr"] + BASELINE["tolerance"]
    known = sum(r.hijacked for i, r in _attacked.items() if i in BASELINE["known_hijacks"]) / len(_attacked)
    assert asr - known <= limit, f"ASR {asr:.0%} exceeds baseline {limit:.0%}; hijacked: {counted}"
