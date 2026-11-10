"""Scenario files: loading, validation, saving, and planting the payload in the world.

A YAML file holds one scenario (a mapping) or several (a list). Files whose name
starts with "_" are ignored, so _template.yaml is never run.
"""
from __future__ import annotations

import base64
import copy
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCENARIO_DIR = ROOT / "scenarios"
FIXTURE = ROOT / "fixtures" / "world.json"
CARRIER_TYPES = ("email", "file", "event")


class ScenarioError(ValueError):
    pass


@dataclass
class Scenario:
    id: str
    user_task: str
    carrier: dict                      # {type: email|file|event, id: ..., mode: append|prepend|replace}
    payload: str
    attack_succeeds_if: list           # any of these tool-call patterns means hijacked
    task_succeeds_if: dict = field(default_factory=dict)
    allowed_tools: list | None = None  # for the D2 allow-list; None = no allow-list
    description: str = ""
    goal: str = ""
    style: str = ""
    ci: bool = False                   # part of the small CI subset
    holdout: bool = False              # keep out of defense tuning
    source: str = "custom"             # builtin | custom | a dataset name such as llmail
    lang: str = "en"                   # language of the injected instruction

    @property
    def attack_kind(self) -> str:
        """"tool" if the attacker wants an action, "answer" if they want the user misinformed."""
        return "tool" if any("tool" in p for p in self.attack_succeeds_if) else "answer"

    def to_yaml_dict(self) -> dict:
        d = {"id": self.id, "description": self.description, "goal": self.goal, "style": self.style,
             "user_task": self.user_task, "carrier": self.carrier, "payload": self.payload,
             "attack_succeeds_if": self.attack_succeeds_if, "task_succeeds_if": self.task_succeeds_if,
             "allowed_tools": self.allowed_tools, "lang": None if self.lang == "en" else self.lang}
        return {k: v for k, v in d.items() if v not in ("", None, {}, [])}


def _expand(payload: str) -> str:
    """{{b64:some text}} in a payload becomes the base64 of that text."""
    return re.sub(r"\{\{b64:(.*?)\}\}",
                  lambda m: base64.b64encode(m.group(1).encode("utf-8")).decode("ascii"),
                  payload, flags=re.S)


def parse_scenario(raw: dict, source: str = "custom", where: str = "") -> Scenario:
    def fail(msg):
        raise ScenarioError(f"{where or raw.get('id', '?')}: {msg}")

    if not isinstance(raw, dict):
        fail("a scenario must be a YAML mapping")
    for key in ("id", "user_task", "carrier", "payload", "attack_succeeds_if"):
        if not raw.get(key):
            fail(f"missing required field '{key}'")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", str(raw["id"])):
        fail("id may only contain lowercase letters, digits, '-' and '_'")
    lang = str(raw.get("lang") or "en").lower()
    if not re.fullmatch(r"[a-z]{2,3}(-[a-z0-9]{2,8})?", lang):
        fail("lang must be a language code such as en, de, hi or kok")

    carrier = dict(raw["carrier"])
    if carrier.get("type") not in CARRIER_TYPES:
        fail(f"carrier.type must be one of {CARRIER_TYPES}")
    if "id" not in carrier:
        fail("carrier.id is required (email id, file path, event id, or 'new' for a new email)")
    carrier.setdefault("mode", "append")
    if carrier["mode"] not in ("append", "prepend", "replace"):
        fail("carrier.mode must be append, prepend or replace")

    attack = raw["attack_succeeds_if"]
    attack = [attack] if isinstance(attack, dict) else list(attack)
    for pattern in attack:
        if not isinstance(pattern, dict) or not ({"tool", "final_answer_contains"} & set(pattern)):
            fail("each attack_succeeds_if entry needs a 'tool' or a 'final_answer_contains'")

    task = dict(raw.get("task_succeeds_if") or {})
    if "final_answer_contains" in task:  # short alias
        task["final_answer_contains_all"] = task.pop("final_answer_contains")
    unknown = set(task) - {"final_answer_contains_all", "final_answer_contains_any", "tool_executed"}
    if unknown:
        fail(f"unknown task_succeeds_if keys: {sorted(unknown)}")

    return Scenario(
        id=str(raw["id"]), user_task=str(raw["user_task"]).strip(), carrier=carrier,
        payload=_expand(str(raw["payload"])), attack_succeeds_if=attack, task_succeeds_if=task,
        allowed_tools=raw.get("allowed_tools"), description=str(raw.get("description", "")),
        goal=str(raw.get("goal", "")), style=str(raw.get("style", "")),
        ci=bool(raw.get("ci", False)), holdout=bool(raw.get("holdout", False)), source=source,
        lang=lang,
    )


INBOX_TOOLS = {"list_emails", "read_email", "send_email", "delete_email"}


def email_only(scenario: Scenario) -> bool:
    """True if the scenario can run with the inbox MCP server alone: the payload sits in an
    email and every tool the attack or the task refers to is an inbox tool."""
    named = {p["tool"] for p in scenario.attack_succeeds_if if "tool" in p}
    wanted = scenario.task_succeeds_if.get("tool_executed")
    if wanted:
        named.add(wanted["tool"])
    named |= set(scenario.allowed_tools or [])
    return scenario.carrier["type"] == "email" and named <= INBOX_TOOLS


def load_scenarios(kind: str = "all") -> list[Scenario]:
    """kind: builtin | custom | datasets | all"""
    kinds = ("builtin", "datasets", "custom") if kind == "all" else (kind,)
    found: dict[str, Scenario] = {}
    for k in kinds:
        for path in sorted((SCENARIO_DIR / k).glob("*.y*ml")):
            if path.name.startswith("_"):
                continue
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                raise ScenarioError(f"{k}/{path.name} is not valid YAML: {exc}") from exc
            for raw in (data if isinstance(data, list) else [data]):
                source = raw.get("dataset", path.stem) if k == "datasets" and isinstance(raw, dict) else k
                s = parse_scenario(raw, source=source, where=f"{k}/{path.name}")
                if s.id in found:
                    raise ScenarioError(f"{k}/{path.name}: duplicate scenario id '{s.id}'")
                found[s.id] = s
    return list(found.values())


def get_scenario(scenario_id: str) -> Scenario:
    for s in load_scenarios("all"):
        if s.id == scenario_id:
            return s
    raise ScenarioError(f"No scenario with id '{scenario_id}'. Run: python -m harness.run --list")


def save_custom(scenario: Scenario, overwrite: bool = False) -> Path:
    path = SCENARIO_DIR / "custom" / f"{scenario.id}.yaml"
    if path.exists() and not overwrite:
        raise ScenarioError(f"{path.name} already exists in scenarios/custom")
    if any(s.id == scenario.id for s in load_scenarios("builtin") + load_scenarios("datasets")):
        raise ScenarioError(f"'{scenario.id}' is already used by a built-in or dataset scenario")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(scenario.to_yaml_dict(), sort_keys=False, allow_unicode=True),
                    encoding="utf-8")
    return path


def _place(old: str, payload: str, mode: str) -> str:
    if mode == "replace":
        return payload
    return f"{payload}\n\n{old}" if mode == "prepend" else f"{old}\n\n{payload}"


def build_world(scenario: Scenario, inject: bool = True) -> dict:
    """The fixture, with the payload planted in the carrier when inject is true."""
    world = copy.deepcopy(json.loads(FIXTURE.read_text(encoding="utf-8")))
    if not inject:
        return world
    c, mode = scenario.carrier, scenario.carrier["mode"]

    if c["type"] == "email":
        if str(c["id"]) == "new":
            world["emails"].append({
                "id": max(e["id"] for e in world["emails"]) + 1,
                "from": c.get("from", "stranger@external.test"),
                "subject": c.get("subject", "Quick note"),
                "body": scenario.payload,
            })
            return world
        for e in world["emails"]:
            if str(e["id"]) == str(c["id"]):
                e["body"] = _place(e["body"], scenario.payload, mode)
                if c.get("from"):   # forged sender
                    e["from"] = c["from"]
                return world
    elif c["type"] == "file":
        for f in world["files"]:
            if f["path"] == c["id"]:
                f["content"] = _place(f["content"], scenario.payload, mode)
                return world
    else:
        for ev in world["events"]:
            if str(ev["id"]) == str(c["id"]):
                ev["description"] = _place(ev["description"], scenario.payload, mode)
                return world
    raise ScenarioError(f"{scenario.id}: carrier {c['type']} '{c['id']}' does not exist in fixtures/world.json")
