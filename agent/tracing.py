"""Optional Langfuse tracing. Off unless LANGFUSE_ENABLED=1 (see infra/langfuse.md)."""
import os


def get_callbacks() -> list:
    if os.environ.get("LANGFUSE_ENABLED") != "1":
        return []
    try:
        from langfuse.langchain import CallbackHandler
    except ImportError as exc:
        raise RuntimeError("LANGFUSE_ENABLED=1 but langfuse is not installed. "
                           "Run: uv sync --extra tracing") from exc
    return [CallbackHandler()]
