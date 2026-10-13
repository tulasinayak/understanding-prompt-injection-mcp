# External attack sets

The scenario files in this folder are built from other people's datasets. They are not
stored in this repository; generate them locally. Every `*.yaml` file here is ignored by git.

## LLMail-Inject sample (`llmail_sample.yaml`)

- Source: `microsoft/llmail-inject-challenge` on Hugging Face,
  https://huggingface.co/datasets/microsoft/llmail-inject-challenge (MIT license)
- Paper: Abdelnabi et al., "LLMail-Inject: A Dataset from a Realistic Adaptive Prompt
  Injection Challenge", 2025
- What we take: emails from Phase 1, levels 1 to 3, that the challenge marked as having made
  the assistant send to the target address; at most 1500 characters, one per team.

```bash
uv run python tools/import_llmail.py
```

This fetches only the sampled rows through the Hugging Face dataset viewer API (no login
needed) with a fixed seed. The API is rate limited, so it takes a few minutes. With the
default settings it yielded 20 emails in October 2026; the dataset or API may change.

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
