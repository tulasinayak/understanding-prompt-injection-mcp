# External attack sets

LLMail-Inject and InjecAgent were tried and dropped: their attacks target other models and
tools and almost never transferred to this testbed (0 of 10 and 0 of 7 undefended). See
FUTURE_WORK.md for the ideas taken from them.

The scenario files in this folder are built from other people's datasets. They are not
stored in this repository; generate them locally. Every `*.yaml` file here is ignored by git.

## AgentDojo attack templates (`agentdojo_templates.yaml`)

- Source: https://github.com/ethz-spylab/agentdojo (MIT license), files
  `src/agentdojo/attacks/baseline_attacks.py` and `important_instructions_attacks.py`
- Paper: Debenedetti et al., "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection
  Attacks and Defenses for LLM Agents", 2024
- What we take: the four named attack wordings (`ignore_previous`, `injecagent`,
  `important_instructions`, `tool_knowledge`), each combined with four attacker goals written
  for this testbed's tools, giving 16 scenarios.

```bash
uv run python tools/gen_agentdojo.py
```

No download is needed for this one.

## After generating

`uv run python -m harness.run --list` shows the new scenarios with their source, and the
study sweep includes them automatically.
