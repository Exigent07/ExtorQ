# P status: platform (schema 2.0 stage)

Owner paths (this stage): `compose.yaml`, `Makefile`, `scripts/**`,
`backend/src/extorq/{common,storage,pipeline}/**`, `backend/src/extorq/ingest/**` (except
`otlp_k8s.py`), `backend/src/extorq/cli.py`, `collectors/src/extorq_collectors/sdk/**`,
`collectors/src/extorq_collectors/cli.py`, `.github/**`, `tests/unit/platform/**`,
`tests/integration/platform/**`, `tests/failure/**`, `docs/data-model.md`, `docs/data-flow.md`,
`docs/collectors.md`, `backend/AGENTS.md`. Proposals for other owners:
`docs/team/interface-changes/P.md`.

Last update: 2026-11-22 (milestone 1: code done, docs next)

## Milestone 0: baseline
- Contracts are at schema 2.0 (lead commit 023fdb6). `extorq.storage.rows` imports the deleted
  `extorq.contracts.simulation`, so every importer (gateway, writer, SDK, other agents' tests)
  fails: `uv run pytest tests/unit/platform -q -x` -> ImportError
  `No module named 'extorq.contracts.simulation'`.

## Plan
1. Remove the simulation category: rows mapping, gateway kind handling, SDK recorder and
   `extorq-collect sim-record`, producer `simulation-runner` (bootstrap), demo_check, Makefile
   (`test-detections` targets instead of `sim-*`), CI, tests.
2. Remove Gemini runtime wiring (compose secret and variables, settings, `make up-demo`).
3. `make reset-data` (`scripts/reset_data.py --yes`): stop collectors and pipeline services,
   TRUNCATE data tables, clear the spool, reset collector baselines (keep log cursors),
   restart. Unit tests for the pure parts. Not run in this stage (VERIFY runs it).
4. `demo_check.py`: freshness/health per asset class, rule runs, newest detection-test report.
5. Docs and docstrings for schema 2.0.

## Milestone 1: schema 2.0 code (done)
- `extorq.storage.rows`: no simulation kind/columns (schema 2.0; works before and after 0008).
- Gateway: no `simulation_run` kind (quarantined as `invalid_record`), advertises `["2.0"]`;
  registry drops retired kinds from an old `producers.json` (fail closed, logged) so the
  2.0 gateway still starts before `make bootstrap` is re-run.
- SDK: `sdk/simulation.py` and `extorq-collect sim-record` deleted; status/flush no longer
  know `simulation-runner`. New `sdk/baseline.py` (re-baseline policies per collector).
- Settings: `gemini_api_key` and the dead `environment` setting removed. Compose: no Gemini
  secret/variables, no `EXTORQ_ENVIRONMENT`, api back to a read-only root filesystem.
- Bootstrap: producer `simulation-runner` removed; stale token files reported (ids only),
  never authorized, never deleted.
- New: `extorq.storage.reset` + `extorq data counts|reset --yes`; `Spool.clear()` +
  `extorq spool status|clear --yes`; `scripts/reset_data.py` (`make reset-data YES=1`).
- `demo_check.py`: telemetry per asset class, collectors (degraded = WARN), rules, ingest
  problems (quarantine/audit), detection-test reports; scenario/simulation checks removed.
- Makefile: `test-detections[-linux|-kubernetes|-github|-macos]`, `reset-data`, Jev-only
  `up-demo`; `sim-*` removed.

### Verified (milestone 1)
| Claim | Command | Result |
|---|---|---|
| platform unit suite | `uv run pytest tests/unit/platform -q` | 258 passed |
| lint/format (owned paths) | `uv run ruff check` + `ruff format --check` on owned paths | all passed, 48 files formatted |
| types | `uv run mypy` (packages) and `uv run mypy scripts/*.py` | no issues (196 + 5 files) |
| compose renders | `docker compose --profile full config --quiet` | ok |
