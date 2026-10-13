"""The agent as a LangGraph state machine:  agent -> guard -> tools -> agent.

  agent  one model call; may request tool calls
  guard  decides allow/deny for each requested call (tool filter, policy, then guard model)
  tools  runs allowed calls on the MCP servers, applies the content defenses to what the
         tool returned (detector, summarizer, Dual LLM handles, spotlighting, sandwich),
         and writes the audit trail
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Annotated, Any, Callable, TypedDict

from langchain_core.messages import ToolMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from audit.logger import AuditLog, sha256_text
from defenses import sandwich, spotlight
from defenses.detector import WITHHELD
from defenses.guard import Guard
from defenses.policy import ToolPolicy, is_side_effect
from defenses.quarantine import ASK_TOOL, DualLLM, NaiveSummarizer

PREVIEW_CHARS = 500


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    steps: int
    decisions: dict


@dataclass
class RunContext:
    llm: Any                      # chat model with tools bound
    tools: dict                   # name -> LangChain tool (MCP-backed, plus ask_quarantined)
    user_task: str
    run_id: str
    policy: ToolPolicy | None = None
    guard: Guard | None = None
    spotlight_tag: str | None = None
    sandwich: bool = False
    tool_filter: set | None = None        # tools the filter kept; None = filter off
    detector: Any = None
    summarizer: NaiveSummarizer | None = None
    dual: DualLLM | None = None
    audit: AuditLog | None = None
    on_event: Callable[[dict], None] | None = None
    max_steps: int = 8
    records: list = field(default_factory=list)   # tool_call records of this run
    model_calls: int = 0
    tainted: bool = False

    def emit(self, event: dict) -> None:
        if self.on_event:
            self.on_event(event)


def tool_output_text(output) -> str:
    """MCP adapters return a string or a list of content blocks depending on version."""
    if isinstance(output, tuple):
        output = output[0]
    if isinstance(output, str):
        return output
    if isinstance(output, list):
        parts = []
        for block in output:
            if isinstance(block, dict):
                parts.append(str(block.get("text", block)))
            else:
                parts.append(str(getattr(block, "text", block)))
        return "\n".join(parts)
    return str(output)


def build_graph(ctx: RunContext):
    async def agent_node(state: AgentState, config):
        ctx.model_calls += 1
        reply = await ctx.llm.ainvoke(state["messages"], config=config)
        ctx.emit({"type": "model", "content": reply.content,
                  "tool_calls": [c["name"] for c in (reply.tool_calls or [])]})
        return {"messages": [reply], "steps": state["steps"] + 1}

    def after_agent(state: AgentState):
        last = state["messages"][-1]
        if getattr(last, "tool_calls", None) and state["steps"] <= ctx.max_steps:
            return "guard"
        return END

    async def guard_node(state: AgentState, config):
        decisions = {}
        for i, call in enumerate(state["messages"][-1].tool_calls):
            name, args = call["name"], call.get("args") or {}
            d = {"allow": True, "policy": None, "guard": None}
            if ctx.tool_filter is not None and name in ctx.tools and name not in ctx.tool_filter:
                d["policy"] = {"allow": False, "rule": "toolfilter",
                               "reason": f"'{name}' was not selected for this task by the tool filter"}
                d["allow"] = False
            if d["allow"] and ctx.policy:
                p = ctx.policy.check(name, args)
                d["policy"] = p.as_dict()
                d["allow"] = p.allow
            if d["allow"] and ctx.guard and is_side_effect(name):
                ok, reason = await ctx.guard.check(ctx.user_task, name, args)
                d["guard"] = {"allow": ok, "reason": reason}
                d["allow"] = ok
            decisions[call.get("id") or str(i)] = d
        return {"decisions": decisions}

    async def content_defenses(name: str, raw: str) -> tuple[str, dict | None, dict | None]:
        """What the agent gets to see of a read tool's output: (shown, detector, quarantine)."""
        if ctx.dual:
            shown = ctx.dual.hide(name, raw)
            return shown, None, ({"mode": "dual", "shown": shown} if shown != raw else None)
        detector = quarantine = None
        shown = raw
        if ctx.detector:
            flagged, score = await ctx.detector.check(raw)
            detector = {"kind": ctx.detector.kind, "flagged": flagged, "score": score}
            if flagged:
                return WITHHELD, detector, None
        if ctx.summarizer:
            shown = await ctx.summarizer.summarize(raw)
            quarantine = {"mode": "summarize", "shown": shown[:PREVIEW_CHARS]}
        return shown, detector, quarantine

    async def tools_node(state: AgentState, config):
        out = []
        for i, call in enumerate(state["messages"][-1].tool_calls):
            name, args = call["name"], call.get("args") or {}
            key = call.get("id") or str(i)
            d = state["decisions"][key]
            taint_before = ctx.tainted
            executed, detector, quarantine = d["allow"], None, None

            if not d["allow"]:
                blocker = d["guard"] if d["guard"] and not d["guard"]["allow"] else d["policy"]
                result = shown = (f"BLOCKED: this action was not permitted ({blocker['reason']}). "
                                  "Continue with the user's original request.")
            elif name not in ctx.tools:
                result = shown = f"Error: there is no tool named '{name}'."
            else:
                if ctx.dual and name != ASK_TOOL:
                    args, refusal = ctx.dual.resolve_args(name, args)
                    if refusal:
                        args, executed = call.get("args") or {}, False
                        quarantine = {"mode": "dual", "refused": refusal}
                        result = shown = f"BLOCKED: {refusal}. Continue with the user's original request."
                if executed:
                    try:
                        result = tool_output_text(await ctx.tools[name].ainvoke(args))
                    except Exception as exc:  # bad arguments from the model, etc.
                        result = f"Tool error: {exc}"
                    shown = result
                    if not is_side_effect(name):
                        ctx.tainted = True
                        if name != ASK_TOOL:
                            shown, detector, quarantine = await content_defenses(name, result)
                    if ctx.policy:
                        ctx.policy.observe(name)
                    if ctx.spotlight_tag:
                        shown = spotlight.wrap(shown, ctx.spotlight_tag)

            if ctx.sandwich:
                shown = sandwich.remind(shown, ctx.user_task)

            record = {
                "type": "tool_call", "run_id": ctx.run_id, "step": len(ctx.records) + 1,
                "tool": name, "args": args, "executed": executed,
                "taint_before": taint_before, "policy": d["policy"], "guard": d["guard"],
                "detector": detector, "quarantine": quarantine,
                "result_sha256": sha256_text(result), "result_preview": result[:PREVIEW_CHARS],
            }
            if ctx.audit:
                ctx.audit.append(record)
            ctx.records.append(record)
            ctx.emit({**record, "result": result, "shown": shown})
            out.append(ToolMessage(content=shown, tool_call_id=key, name=name))
        return {"messages": out}

    g = StateGraph(AgentState)
    g.add_node("agent", agent_node)
    g.add_node("guard", guard_node)
    g.add_node("tools", tools_node)
    g.add_edge(START, "agent")
    g.add_conditional_edges("agent", after_agent, {"guard": "guard", END: END})
    g.add_edge("guard", "tools")
    g.add_edge("tools", "agent")
    return g.compile()
