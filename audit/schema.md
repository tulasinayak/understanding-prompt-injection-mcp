# Audit record schema

One JSON object per line. Every record has `ts` (UTC), `type`, `run_id`, `prev_hash`, `hash`.
`hash` is the SHA-256 of the record (without `hash`) serialized with sorted keys; `prev_hash`
is the `hash` of the line before it (64 zeros for the first line).

## `run_start`
`scenario_id`, `model`, `model_digest`, `defense`, `injected` (false = benign run),
`user_task`, `seed`, `temperature`, `repeat`, `source` (builtin, custom, agentdojo, llmail), `goal`, `attack_kind` (`tool` or `answer`).

## `tool_call` — one per tool call the model requested
| field | meaning |
|---|---|
| `step` | order within the run |
| `tool`, `args` | what the model asked for |
| `executed` | false if a defense blocked it |
| `taint_before` | had the agent already read untrusted tool output? |
| `policy` | D2 decision: `{allow, rule, reason}` or null if D2 is off |
| `guard` | D3 verdict: `{allow, reason}` or null if not consulted |
| `policy` (cont.) | `rule` is `allowlist`, `taint`, or `toolfilter` when the tool filter refused the call |
| `detector` | injection detector verdict on a read result: `{kind, flagged, score}`; flagged results are withheld from the agent |
| `quarantine` | `{mode: summarize, shown}` = the summary the agent got; `{mode: dual, shown}` = the handle it got; `{mode: dual, refused}` = a hidden value was used as a target argument |
| `result_sha256`, `result_preview` | hash and first 500 characters of what the tool returned |

`result_preview` is always what the tool really returned, even when a defense showed the agent
something else. With `dual`, `args` are logged after hidden values were filled in, i.e. as executed.

## `run_end`
`hijacked` (attacker's call was executed), `attack_attempted` (the model requested it, executed or
not), `task_ok`, `final_answer`, `duration_s`, `model_calls`, `guard_calls`, `aux_calls` (detector, summarizer, quarantined model, tool filter), `tool_filter` (tools it kept), `error`, plus the
same identifying fields as `run_start`.

All metrics are computed from these records, not from the model's prose.
