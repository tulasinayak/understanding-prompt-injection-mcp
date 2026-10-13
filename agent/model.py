"""Ollama chat model factory and small helpers around the local Ollama server."""
from __future__ import annotations

import json
import os
import urllib.request

DEFAULT_MODEL = os.environ.get("TESTBED_MODEL", "qwen3:8b")


def ollama_url() -> str:
    host = os.environ.get("OLLAMA_HOST", "127.0.0.1:11434")
    return host if host.startswith("http") else f"http://{host}"


HOSTED_PREFIX = "openai:"


def is_hosted(model: str) -> bool:
    return model.startswith(HOSTED_PREFIX)


def extra_models() -> list[str]:
    """Hosted models to offer in the GUI: TESTBED_EXTRA_MODELS="openai:model-a,openai:model-b"."""
    return [m.strip() for m in os.environ.get("TESTBED_EXTRA_MODELS", "").split(",") if m.strip()]


def make_chat_model(model: str, temperature: float = 0.0, seed: int = 42, num_predict: int = 512):
    if is_hosted(model):
        # "openai:<model id>" uses the OpenAI API (or any compatible endpoint via OPENAI_BASE_URL).
        # The key is read from the OPENAI_API_KEY environment variable, never from a file here.
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as exc:
            raise RuntimeError("Hosted models need: uv sync --extra hosted") from exc
        if not os.environ.get("OPENAI_API_KEY"):
            raise RuntimeError("Set the OPENAI_API_KEY environment variable first.")
        return ChatOpenAI(model=model[len(HOSTED_PREFIX):], temperature=temperature, seed=seed,
                          max_tokens=num_predict)

    from langchain_ollama import ChatOllama

    kwargs = dict(model=model, temperature=temperature, seed=seed, num_ctx=8192,
                  num_predict=num_predict, base_url=ollama_url())
    # Qwen3 thinks by default; switching it off keeps CPU runs short.
    if model.startswith("qwen3") and "reasoning" in ChatOllama.model_fields:
        kwargs["reasoning"] = False
    return ChatOllama(**kwargs)


def list_models() -> list[dict]:
    """Models pulled in the local Ollama; empty list if the server is not reachable."""
    try:
        with urllib.request.urlopen(f"{ollama_url()}/api/tags", timeout=3) as r:
            return json.load(r).get("models", [])
    except Exception:
        return []


def model_digest(model: str) -> str | None:
    for m in list_models():
        if m.get("name") == model or m.get("model") == model:
            return m.get("digest")
    return None
