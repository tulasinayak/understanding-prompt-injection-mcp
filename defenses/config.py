"""Which defenses are switched on for a run.

Spec strings are defense names joined with "+", e.g. "spotlight+guard".

    none         no defense
    spotlight    mark tool output as data                       (alias d1)
    sandwich     repeat the user's request after each tool result
    toolfilter   the model picks its tools before reading anything
    detect-llm   a model flags injected tool output, which is then withheld
    detect-clf   the same with a fine-tuned classifier
    summarize    naive quarantine: a tool-less model summarizes tool output
    dual         strict Dual LLM: the agent only ever sees handles
    policy       allow-list + taint rule                         (alias d2)
    allowlist    only the allow-list half of policy              (alias d2a)
    taint        only the taint half of policy                   (alias d2t)
    guard        a second model approves side-effect calls       (alias d3)
    all          spotlight+policy+guard (the layered combination used by CI)
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# canonical order used for labels
ORDER = ["spotlight", "sandwich", "toolfilter", "detect-llm", "detect-clf", "summarize", "dual",
         "allowlist", "taint", "guard"]
ALIASES = {
    "none": [], "d1": ["spotlight"], "d2": ["allowlist", "taint"], "policy": ["allowlist", "taint"],
    "d2a": ["allowlist"], "d2t": ["taint"], "d3": ["guard"],
    "all": ["spotlight", "allowlist", "taint", "guard"],
}
# the conditions compared in the study
STUDY = ["none", "spotlight", "sandwich", "toolfilter", "detect-llm", "detect-clf", "summarize",
         "dual", "policy", "guard", "spotlight+policy+guard"]


@dataclass(frozen=True)
class DefenseConfig:
    names: frozenset = frozenset()

    @classmethod
    def parse(cls, spec: "str | DefenseConfig | None") -> "DefenseConfig":
        if isinstance(spec, DefenseConfig):
            return spec
        names = set()
        for token in filter(None, re.split(r"[+,\s]+", (spec or "none").lower())):
            if token in ALIASES:
                names.update(ALIASES[token])
            elif token in ORDER:
                names.add(token)
            else:
                raise ValueError(f"Unknown defense '{token}'. Known: none, {', '.join(ORDER)}, policy, all.")
        if "dual" in names and names & {"summarize", "detect-llm", "detect-clf", "spotlight"}:
            raise ValueError("'dual' hides tool output from the agent, so it cannot be combined with "
                             "spotlight, summarize or a detector.")
        return cls(frozenset(names))

    def __getattr__(self, name: str) -> bool:
        key = name.replace("_", "-")
        if key in ORDER:
            return key in self.names
        raise AttributeError(name)

    @property
    def label(self) -> str:
        parts = [n for n in ORDER if n in self.names]
        if "allowlist" in parts and "taint" in parts:
            parts[parts.index("allowlist")] = "policy"
            parts.remove("taint")
        return "+".join(parts) or "none"
