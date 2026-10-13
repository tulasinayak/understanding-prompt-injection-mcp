"""Append-only, hash-chained JSONL audit trail.

Every record stores the hash of the record before it, so editing or removing
a line anywhere in the file breaks the chain and verify_chain() reports it.
One process should write to a given file at a time.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _digest(record_without_hash: dict) -> str:
    canonical = json.dumps(record_without_hash, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":"))
    return sha256_text(canonical)


def read_records(path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        records = read_records(self.path)
        return records[-1]["hash"] if records else GENESIS

    def append(self, record: dict) -> dict:
        body = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **record}
        body["prev_hash"] = self._last_hash()
        body["hash"] = _digest(body)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(body, ensure_ascii=False) + "\n")
        return body


def verify_chain(path) -> dict:
    """Returns {"ok", "records", "bad_line"}; bad_line is 1-based or None."""
    prev = GENESIS
    records = read_records(path)
    for i, rec in enumerate(records, start=1):
        body = {k: v for k, v in rec.items() if k != "hash"}
        if rec.get("prev_hash") != prev or rec.get("hash") != _digest(body):
            return {"ok": False, "records": len(records), "bad_line": i}
        prev = rec["hash"]
    return {"ok": True, "records": len(records), "bad_line": None}
