# backend/AGENTS.md: scoped guide for `backend/src/extorq`

Read the root `AGENTS.md` first (security invariants are non-negotiable). Ownership
of each package is in `docs/team/PLAN.md` section 2; this file covers conventions
that apply to all backend code.

## Layout

| Package | Purpose | Owner |
|---|---|---|
| `contracts/` | versioned Pydantic contracts (schema 2.0), event catalog, identities | lead |
| `common/` | `config` (settings, `_FILE` secrets, startup checks), `logging` (JSON + redaction), `redaction` (`redact_text`, `sanitize_untrusted`) | platform |
| `storage/` | `clickhouse.get_client(role)`, `rows` (contract -> row mapping), `migrate`, `reset` (clean-slate TRUNCATE) | platform |
| `ingest/` | HTTPS gateway (`app.py`, `processing.py`, `registry.py`, `body.py`, `server.py`); `otlp_k8s.py` is the Kubernetes telemetry team's OTLP normaliser | platform (+Kubernetes) |
| `pipeline/` | durable SQLite spool and the ClickHouse writer | platform |
| `detection/`, `correlation/` | rule engine, detector service, context builder | detection |
| `ai/` | Jev triage (the only AI provider; advisory), ai-worker | AI |
| `api/` | analyst API | UI/API |
| `cli.py` | root `extorq` CLI (lazy imports per command) | platform |

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
  replays every migration's DDL and fails on drift). A new table also goes into
  `extorq.storage.reset.DATA_TABLES` (or is protected there), otherwise
  `test_platform_reset.py` fails: a clean slate must know every table. Schema changes
  are new migrations (`infra/clickhouse/migrations/NNNN_name.sql`, idempotent
  statements); applied files are immutable (the runner refuses changed checksums).
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
make up-full                                   # + detector, ai-worker, api (8000), console, grafana (AI off)
make up-demo                                   # the same with Jev triage ON (live, budgeted calls)
make collectors-start                          # host collectors in the background (collectors-status/-stop)
make reset-data                                # read-only plan and table counts
make test-detections                           # real detection tests per asset (positives + negative controls)
make demo-check                                # read-only readiness: telemetry per asset, rules, detection tests
```

Use the [recovery runbook](../docs/recovery.md) for backup and clean-slate resets.
The reset script verifies the data bundle before truncation, clears shared queues
and re-baselines collectors with their source cursors intact. After partial
mutation it keeps writers stopped. `extorq data counts` and `extorq spool status`
are the read-only store commands.

Gateway time window: events more than 1 day in the future or older than the `events`
retention (90 days, `EXTORQ_EVENT_RETENTION_DAYS`, must equal the TTL in 0001) are
quarantined (`older_than_retention`), never acknowledged and silently expired.

Dev servers bind other ports (API 8100, console 3100) so they never clash with compose.

## Tests

* `uv run pytest -q` (default markers exclude `integration`, `lab`, `live_ai`, `failure`).
* Platform: `tests/unit/platform/`, `tests/integration/platform/` (`make test-integration`),
  `tests/failure/` (`make test-failure`, platform only: stops shared services).
* Never claim a test passed without running it; record the command and result.
