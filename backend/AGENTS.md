# backend/AGENTS.md: scoped guide for `backend/src/extorq`

Read the root `AGENTS.md` first (security invariants are non-negotiable). Ownership
of each package is in `docs/team/PLAN.md` section 2; this file covers conventions
that apply to all backend code.

## Layout

| Package | Purpose | Owner |
|---|---|---|
| `contracts/` | versioned Pydantic contracts (schema 1.1), event catalog, identities | lead |
| `common/` | `config` (settings, `_FILE` secrets, startup checks), `logging` (JSON + redaction), `redaction` (`redact_text`, `sanitize_untrusted`) | A |
| `storage/` | `clickhouse.get_client(role)`, `rows` (contract -> row mapping), `migrate` | A |
| `ingest/` | HTTPS gateway (`app.py`, `processing.py`, `registry.py`, `body.py`, `server.py`); `otlp_k8s.py` is B2's normaliser | A (+B2) |
| `pipeline/` | durable SQLite spool and the ClickHouse writer | A |
| `detection/`, `correlation/` | rule engine, detector service, context builder | C2 |
| `ai/` | Jev triage, Gemini summaries, ai-worker | E |
| `api/` | analyst API | D1 |
| `cli.py` | root `extorq` CLI (lazy imports per command) | A |

## Conventions

* **Contracts only.** Cross-boundary data is a contract model; never invent a parallel
  dict format. Unknown values stay `None`. Timestamps are aware UTC.
* **ClickHouse access** only through `extorq.storage.clickhouse.get_client(role)` with
  the least-privileged role for the job (`ingest`, `detect`, `rules_ro`, `ai`, `api_ro`,
  `api_writer`, `grafana`; `admin` is for migrations only). Passwords come from
  `var/secrets/clickhouse/<user>_password` (compose: `/run/secrets/...`), never from
  environment variables or code.
* **SQL values are server-side parameters** (`{name:Type}`), never f-strings. The rare
  reviewed exception carries `# extorq: sql-reviewed <reason>` (allow-listed identifiers
  only); `tests/security` enforces this.
* **Duplicate-safe reads**: `uniqExact(event_id)`, `argMax(col, version)`, `FINAL` or the
  `v_*` views. Sorting keys are not unique.
* **Writing rows**: map models with `extorq.storage.rows` (`to_row`, `alert_to_row`, ...)
  so columns always match the migrations (`tests/unit/platform/test_platform_rows.py`
  parses the DDL and fails on drift). Schema changes are new migrations
  (`infra/clickhouse/migrations/NNNN_name.sql`, idempotent statements); applied files
  are immutable (the runner refuses changed checksums).
* **Settings** subclass `extorq.common.config.ExtorQBaseSettings` (prefix `EXTORQ_`, no
  dotenv). Secrets are `SecretStr` fields and automatically accept `<ENV_NAME>_FILE`.
  Startup checks report missing setting *names*, never values.
* **Logging** via `extorq.common.logging.configure_logging(component)` and
  `get_logger(name)`: JSON on stdout; sensitive keys and token-looking values are
  redacted by a processor, but still never log tokens, passwords, Authorization headers,
  request bodies, prompts or raw telemetry.
* **Untrusted text** (log lines, HTTP paths, user agents, k8s fields, commit messages):
  `redact_text` before persisting, `sanitize_untrusted` before displaying or embedding;
  never interpolate it into SQL, shell commands, HTML or LLM instructions.
* **External calls** have timeouts and bounded retries with jittered backoff; transient
  errors never drop accepted data (see `docs/data-flow.md`).
* **CLI**: register commands in `cli.py` with lazy imports (`load(module, attr)`), so a
  missing optional module fails only its own command with exit code 3.

## Running locally

```
make bootstrap && make up && make up-debug     # gateway 8443, ClickHouse debug proxy 18123
uv run extorq migrate --status
uv run python scripts/smoke_ingest.py          # one SYNTHETIC event round trip
make up-full                                   # + detector, ai-worker, api (8000), console, grafana
```

Dev servers bind other ports (API 8100, console 3100) so they never clash with compose.

## Tests

* `uv run pytest -q` (default markers exclude `integration`, `lab`, `live_ai`, `failure`).
* Platform: `tests/unit/platform/`, `tests/integration/platform/` (`make test-integration`),
  `tests/failure/` (`make test-failure`, agent A only: stops shared services).
* Never claim a test passed without running it; record the command and result.
