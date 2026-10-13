# Optional: self-hosted Langfuse tracing

Off by default. The JSONL audit trail is the source of truth; Langfuse is for looking at
individual traces (prompts, tool calls, latencies) in a UI.

Langfuse v3 runs six containers (web, worker, Postgres, ClickHouse, Redis, MinIO) and wants
several GB of RAM. On a 16 GB machine, start it to inspect a few runs and stop it before a sweep.

## Start Langfuse

Use the compose file Langfuse maintains rather than a copy that goes stale:

```bash
git clone --depth 1 https://github.com/langfuse/langfuse.git infra/langfuse
```

```bash
docker compose -f infra/langfuse/docker-compose.yml up -d
```

Open http://localhost:3000, create a local account and a project, then copy the project's
public and secret key.

## Point the testbed at it

```bash
uv sync --extra tracing
```

PowerShell, for the current terminal:

```powershell
$env:LANGFUSE_ENABLED = "1"
$env:LANGFUSE_HOST = "http://localhost:3000"
$env:LANGFUSE_PUBLIC_KEY = "pk-lf-..."
$env:LANGFUSE_SECRET_KEY = "sk-lf-..."
```

Every `harness.run`, `harness.sweep` and GUI run started from that terminal is now traced
(`agent/tracing.py` attaches the Langfuse LangChain callback to the graph).

## Stop it

```bash
docker compose -f infra/langfuse/docker-compose.yml down
```

Status: the callback wiring is in place but has not been exercised against a running Langfuse
on this machine yet.
