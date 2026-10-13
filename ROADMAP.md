# Understanding Prompt Injection through MCP Tools: Attack and Defense

## Roadmap and research design

## Research question

Given a benign user task, how often does text inside a tool result make the agent perform an
attacker-chosen action, and how much does each defense reduce that without breaking the task?

## Threat model

The attacker controls the content of some emails, files or calendar entries. They cannot change
the system prompt, the user's message, or the tool code. Everything in the testbed is fake data
on `.test` domains; no tool touches the network.

## Metrics (all from the audit log)

| metric | meaning |
|---|---|
| ASR | share of attacked runs where the attacker's tool call was **executed** |
| attempted | share where the model **requested** it, executed or blocked. ASR < attempted means a defense caught a hijacked model |
| utility under attack | share of attacked runs where the user's task was still completed |
| benign utility | same tasks, no injection. A defense that blocks everything has ASR 0 and utility 0 |
| overhead | seconds and model calls per run |

Each rate is reported with a Wilson 95% interval.

## Conditions

`none`, `d1`, `d2`, `d3`, `all`. D2 can be split into `d2a` (allow-list only) and `d2t` (taint rule
only). Optional second axis: model (qwen3:8b, the small CI model, mistral).

## Defenses

- **D1 spotlighting** (`defenses/spotlight.py`): tool output is wrapped in tagged markers and the
  system prompt says marked text is data. Cheap; relies on the model obeying.
- **D2 tool-permission policy** (`defenses/policy.py`): deterministic. Allow-list of tools per task,
  plus a taint rule: after any untrusted read, a side-effect call is allowed only if its target
  argument appears in the user's own request.
- **D3 guard model** (`defenses/guard.py`): a second model call before each side-effect action. It
  sees the user's request and the proposed call, never the tool output.

## Known limits to write up honestly

- `target-d2-inscope-leak` gets past D2 by design: the recipient is one the user named. D2 controls
  where data goes, not what data goes there.
- The guard sees the call's arguments, which the attacker can influence (`target-d3-justification`).
- The D1 tag is derived from the run seed for reproducibility; a deployment would randomize it.
- With a small model, "attack failed" can mean "model too weak to follow it". Always read ASR next
  to benign utility, and drop a model whose benign utility is too low to interpret.
- Four built-in scenarios are marked `holdout: true`. Leave them out while tuning defenses
  (the sweep skips them unless `--include-holdout`) and run them once at the end.

## Audit trail and the EU AI Act

`audit/logger.py` writes an append-only, hash-chained JSONL record of every tool call with the
policy and guard decision (`audit/schema.md`). This corresponds in design to the record-keeping
requirement for high-risk systems (Art. 12: automatic recording of events over the system's
lifetime). Describe it as a design correspondence, not as a compliance claim.

## Compute budget on this machine (CPU only)

Full matrix: 20 scenarios x 5 conditions x 3 repeats = 300 attacked runs, plus benign runs.
Measure seconds per run first (`harness.metrics` prints it), then run the sweep overnight; it
resumes where it stopped. Repeats only differ at temperature > 0, so the sweep uses 0.7 with
seed = repeat number, while single runs and CI use temperature 0.

## Timeline

| week | outcome |
|---|---|
| 1 | Done in this repo: servers, agent, audit log, harness, defenses, tests, GUI, CI file |
| 2 | Push to GitHub, get CI green on the small model, set `tests/baseline.json` from the first runs |
| 3 | Write 10+ custom scenarios of your own; first undefended baseline table on qwen3:8b |
| 4 | Full sweep (overnight runs), per-defense ablation including d2a / d2t |
| 5 | Holdout scenarios, second model, Langfuse screenshots of one hijacked and one blocked trace |
| 6 | Write-up: results table, one figure, limitations |

## Reading list

- Greshake, Abdelnabi et al. (2023), indirect prompt injection against LLM-integrated applications
- Zhan et al. (2024), InjecAgent
- Debenedetti et al. (2024), AgentDojo
- Hines et al. (2024), spotlighting
- Abdelnabi et al. (2024), TaskTracker (detecting task drift from activations)

## SOP angle

The thesis finding was that models follow instructions over evidence. This project measures the
same failure with actions attached: instructions arriving as *data* still get followed. The
contribution is an ablation showing which mitigations help, at what utility cost, and where each
one stops working.
