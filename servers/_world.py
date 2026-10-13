"""Loads the fake world a server works on.

The harness writes one world file per run (fixture + planted payload) and
points TESTBED_WORLD at it, so every run starts from the same state.
"""
import json
import os
from pathlib import Path

DEFAULT_WORLD = Path(__file__).resolve().parent.parent / "fixtures" / "world.json"


def load_world() -> dict:
    path = os.environ.get("TESTBED_WORLD") or DEFAULT_WORLD
    with open(path, encoding="utf-8") as f:
        return json.load(f)
