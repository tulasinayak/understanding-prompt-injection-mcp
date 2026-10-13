"""Stand-in chat models so the whole pipeline can be tested without Ollama."""
from langchain_core.messages import AIMessage


def call(name: str, **args) -> dict:
    return {"name": name, "args": args, "id": f"call_{name}_{len(args)}", "type": "tool_call"}


class ScriptedModel:
    """Replays a fixed list of turns, like a model that always behaves the same way."""
    name = "scripted"

    def __init__(self, turns):
        self.turns = list(turns)
        self.seen = []          # message lists it was called with

    def bind_tools(self, tools):
        self.tool_names = [t.name for t in tools]
        return self

    async def ainvoke(self, messages, config=None, **kwargs):
        self.seen.append(list(messages))
        turn = self.turns.pop(0) if self.turns else "Done."
        if isinstance(turn, str):
            return AIMessage(content=turn)
        return AIMessage(content="", tool_calls=turn)


class FixedGuard:
    """Stand-in for a guard / detector / quarantined model. Give one reply to always
    answer the same, or a list of replies to answer in order (the last one repeats)."""

    def __init__(self, reply):
        self.replies = [reply] if isinstance(reply, str) else list(reply)
        self.seen = []

    async def ainvoke(self, messages, config=None, **kwargs):
        self.seen.append(list(messages))
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        return AIMessage(content=reply)


def agent_saw(model: ScriptedModel) -> str:
    """Everything that was ever put in front of the agent model, as one string."""
    return "\n".join(str(m.content) for call in model.seen for m in call)
