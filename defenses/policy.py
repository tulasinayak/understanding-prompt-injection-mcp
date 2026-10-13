"""D2: deterministic tool-permission policy. No model involved.

Two rules:
  allow-list  the scenario names the tools its task needs; anything else is denied.
  taint       once the agent has read tool output (untrusted), a side-effect tool is
              allowed only if its target arguments literally appear in the user's
              own request.
Unknown tools are treated as side-effect tools (fail closed).
"""
from __future__ import annotations

from dataclasses import dataclass

READ_TOOLS = {"list_emails", "read_email", "list_files", "read_file", "list_events",
              "ask_quarantined"}   # the Dual LLM question tool only reads
ALWAYS_ALLOWED = {"ask_quarantined"}  # part of a defense, not of the task

# Arguments that decide where data goes or what is destroyed.
SINK_ARGS = {
    "send_email": ["to"],
    "share_file": ["with_email"],
    "invite": ["attendee"],
    "delete_file": ["path"],
    "write_file": ["path"],
    "delete_email": [],
    "create_event": [],
}
# Tools with no sink argument need the user to have asked for that kind of action.
INTENT_WORDS = {
    "delete_email": ["delete", "remove", "trash"],
    "create_event": ["schedule", "create", "book", "add an event", "add a meeting"],
}


def is_side_effect(tool: str) -> bool:
    return tool not in READ_TOOLS


@dataclass
class PolicyDecision:
    allow: bool
    rule: str
    reason: str

    def as_dict(self) -> dict:
        return {"allow": self.allow, "rule": self.rule, "reason": self.reason}


class ToolPolicy:
    def __init__(self, user_task: str, allowed_tools=None, use_allowlist=True, use_taint=True):
        self.task = user_task.lower()
        self.allowed_tools = set(allowed_tools) if allowed_tools is not None else None
        self.use_allowlist = use_allowlist
        self.use_taint = use_taint
        self.tainted = False

    def observe(self, tool: str) -> None:
        """Call after a tool ran: output of read tools is untrusted."""
        if tool in READ_TOOLS:
            self.tainted = True

    def check(self, tool: str, args: dict) -> PolicyDecision:
        if (self.use_allowlist and self.allowed_tools is not None
                and tool not in self.allowed_tools and tool not in ALWAYS_ALLOWED):
            return PolicyDecision(False, "allowlist", f"'{tool}' is not in this task's allow-list")

        if self.use_taint and self.tainted and is_side_effect(tool):
            if tool not in SINK_ARGS:
                return PolicyDecision(False, "taint", f"unknown tool '{tool}' after reading untrusted content")
            for name in SINK_ARGS[tool]:
                value = str(args.get(name, "")).strip().lower()
                if not value or value not in self.task:
                    return PolicyDecision(
                        False, "taint",
                        f"{name}={args.get(name)!r} is not in the user's request, and untrusted content was read earlier",
                    )
            words = INTENT_WORDS.get(tool)
            if words and not any(w in self.task for w in words):
                return PolicyDecision(False, "taint", f"the user's request does not ask for '{tool}'")

        return PolicyDecision(True, "ok", "allowed")
