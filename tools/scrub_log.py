"""Remove records of scenarios no longer in scenarios/ from an audit log, and re-chain it.

    uv run python tools/scrub_log.py results/audit.jsonl

Dropped runs are those whose scenario_id is not among the current scenarios (for example the
LLMail-Inject and InjecAgent runs, which carried third-party email text). After dropping their
records the hash chain is rebuilt so the file still verifies. Writes in place after a .bak copy.
"""
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit.logger import GENESIS, _digest, read_records  # noqa: E402
from harness.scenarios import load_scenarios  # noqa: E402


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "results/audit.jsonl")
    keep_ids = {s.id for s in load_scenarios("all")}
    records = read_records(path)

    # a run's records share a run_id; drop the whole run if its scenario was removed
    drop_runs = {r["run_id"] for r in records
                 if r.get("scenario_id") and r["scenario_id"] not in keep_ids}
    kept = [r for r in records if r.get("run_id") not in drop_runs]

    prev = GENESIS
    import json
    shutil.copy(path, path.with_suffix(path.suffix + ".bak"))
    with path.open("w", encoding="utf-8") as f:
        for rec in kept:
            body = {k: v for k, v in rec.items() if k not in ("hash", "prev_hash")}
            body["prev_hash"] = prev
            body["hash"] = _digest(body)
            prev = body["hash"]
            f.write(json.dumps(body, ensure_ascii=False) + "\n")

    print(f"{path.name}: kept {len(kept)} of {len(records)} records, "
          f"dropped {len(drop_runs)} runs ({len(records) - len(kept)} records). "
          f"Backup: {path.with_suffix(path.suffix + '.bak').name}")


if __name__ == "__main__":
    main()
