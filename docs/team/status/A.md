SDK READY 2026-11-21T14:42:12Z - `from extorq_collectors.sdk import Collector, CollectorContext, asset_upsert`; run `uv run extorq-collect run [--only a,b] [--once]` (configs config/collectors/*.yaml); `uv run extorq-collect sim-record --scenario <ID> --asset <asset> --status started|completed|failed|cleaned_up --run-id <id>`; details below and in docs/collectors.md
STACK READY 2026-11-21T10:36:49Z - gateway https://127.0.0.1:8443 (CA var/tls/ca.crt), producer tokens var/secrets/tokens/<producer_id>.token, ClickHouse debug proxy 127.0.0.1:18123 (profile debug; users per PLAN 4.4, passwords var/secrets/clickhouse/)

# Agent A status (Platform & Data)

Last update: 2026-11-21T15:15Z (session 2)

## Outage log (shared stack)
- 2026-11-21T15:10:56Z: compose `api` (profile full) started on 127.0.0.1:8000 for verification
  and left running (read-only API; AI providers disabled). No other service touched.
- 2026-11-21T15:08:07Z-15:08:40Z: `make up` redeploy of migrate/ingest/writer (F-19 identity
  binding, F-06 residual redaction); ClickHouse untouched.
- 2026-11-21T15:00:41Z: `make migrate` applied C3's `0005_findings_services` (view replace; no
  restarts).
- 2026-11-21T14:58:58Z-14:59:27Z: failure tests (announced 14:58Z). ClickHouse stopped for
  9.1 s (gateway kept answering 202; 100/100 buffered events delivered after restart), then
  `ingest` and `writer` restarted once each during a paced 800-record collector stream
  (800/800 delivered, 800 rows, 2 transient ConnectErrors retried by the SDK).
- 2026-11-21T14:51:52Z-14:52:07Z: `make up` redeploy of migrate/ingest/writer with the F-02/F-06
  redaction and config fixes (15 s; ClickHouse not restarted).
- 2026-11-21T14:40:33Z-14:40:40Z: `ingest` + `writer` recreated with the contract-1.1 image
  (7 s; collectors buffered and retried). ClickHouse was not touched.

## How to use the stack (for other agents)
- `make help` lists everything. Core: `make up` (clickhouse, migrate, ingest, writer);
  `make up-full` adds detector, ai-worker, api (8000), frontend (3000), grafana (3001);
  `make up-debug` = ClickHouse proxy 127.0.0.1:18123 (never during the demo, F-01);
  `make migrate` rebuilds the image (migrations are baked in) and applies new migrations;
  `make demo-check` = read-only readiness report. Do not stop/restart services you do not own.
- Gateway: `POST https://127.0.0.1:8443/v1/ingest` (IngestBatch JSON, gzip ok, schema_version
  `1.0` or `1.1`), `Authorization: Bearer <var/secrets/tokens/<producer_id>.token>`, CA
  `var/tls/ca.crt`. 403 rejects the WHOLE batch when any record is outside the producer's
  kinds/source types/assets (audited in `extorq.ingest_audit`). `NaN`/`Infinity` tokens -> 400.
  Per-record problems (validation, semantics, time, identity, storage) quarantine only that
  record (202 for the rest). Details: docs/data-flow.md.
- OTLP: `POST https://127.0.0.1:8443/v1/otlp/v1/logs` (token of `k8s-otel-extorq-lab`).
- ClickHouse from the Mac: `extorq.storage.clickhouse.get_client("<role>")` (roles admin,
  ingest, detect, rules_ro, ai, api_ro, api_writer, grafana; password files
  `var/secrets/clickhouse/<user>_password`; default 127.0.0.1:18123). DateTime64 values come
  back as naive datetimes that are UTC. Migrations applied live: 0001-0005.

### Producers (var/secrets/producers.json, `make bootstrap`)
| producer | kinds | source types | assets |
|---|---|---|---|
| macos-workstation-01 | event, asset, inventory_item, finding, scan_run, collector_health, **service, service_instance** | macos.* | macos:workstation-01 |
| linux-ssh-lab-vm-01 | same as macos | linux.* | linux:lab-vm-01 |
| k8s-inventory-extorq-lab | same as macos | k8s.api_inventory, k8s.events, k8s.posture | k8s:extorq-lab* (incl. nodes `k8s:extorq-lab/node/<n>`) |
| k8s-otel-extorq-lab | event | k8s.audit, k8s.container_log | k8s:extorq-lab* |
| github-collector | 1.0 telemetry kinds | github.* | github:* |
| scanner-runner | asset, finding, scan_run, collector_health | scanner.* | lab assets |
| simulation-runner | simulation_run | extorq.simulation | lab assets |
| extorq-selftest (A-IC-1) | collector_health | extorq.pipeline | macos:workstation-01 |

Service-model rules enforced by the gateway (B1, B2, B3): `Service.service_id` must equal
`identity.service_id(asset_id, service_kind, service_key)` and `ServiceInstance.instance_id`
must equal `identity.instance_id(service_id, instance_kind, instance_key)`, else the record is
quarantined (`identity_mismatch`, F-19). A `service_instance` WITHOUT `asset_id` is quarantined
(`asset_unattributable`, A-IC-2): set the host/node asset. `Service.telemetry_sources` is not
checked against the producer. Gap events may use your own source types.

### Collector SDK (B1, B2, B3, C1, C3) - full guide: docs/collectors.md
```python
from extorq_collectors.sdk import Collector, CollectorContext, asset_upsert

class LinuxSSHCollector(Collector):
    collector_type = "linux_ssh"
    source_types = ("linux.journald", "linux.auditd")   # all must be allowed for the producer
    def collect(self, ctx: CollectorContext) -> None:
        cursor = ctx.checkpoints.get("journal.cursor")
        added, changed, removed = ctx.diff_snapshot("units", {key: item_dict, ...})
        asset = asset_upsert(ctx, asset_type="linux_host", name="lab-vm-01", attributes={...})
        ctx.emit([*events, *([asset] if asset else [])], {"journal.cursor": new_cursor})
```
- `emit` validates ALL records first, then commits outbox + checkpoints + staged snapshots in one
  transaction; Service/ServiceInstance models are accepted. Snapshots advance only with an emit
  (discarded after a failed cycle).
- `uv run extorq-collect run|status|flush [--requeue-dead]`; state `var/collectors/<id>/state.db`.
- Delivery at least once; 401 and systemic 400/404/405/415/422 stay buffered (A-IC-3); 403
  bisects so only unauthorized records are dead-lettered.
- sim-record: exit 0 delivered, 75 buffered locally (delivered by next sim-record/flush), 2 invalid.
  Incident 14:38Z: run c7cbc976ecaf (VM-001) hit the old 1.0 gateway (422, dead-lettered); A fixed
  the policy, requeued and delivered both records (`simulation_runs` shows it completed).

### Notes for other agents
- C2: `extorq.storage.rows.alert_to_row(alert)` maps the full `alerts` contract incl.
  `service_ids` (shared helper; your store already writes service_ids).
- D1/D2: compose `api` runs on 127.0.0.1:8000 (since 15:10Z; healthz 200, viewer GET 200, no
  token 401, viewer POST 403). `make up-full` includes `frontend` now that frontend/Dockerfile
  exists. Console secrets: host layout kept; compose maps `var/secrets/api_service_token`,
  `analyst_password`, `viewer_password`, `frontend_session_secret` to
  `/run/secrets/{api_service_token,console_analyst_password,console_viewer_password,
  console_session_secret}` (43+ chars each). Docker Desktop bind-mounted secrets are readable
  by non-root uids (ingest uid 10001 reads its 0600 secrets).
  Collector `sdk-heartbeat-example` (`collector_type = heartbeat`) is the SDK self-test.
- E: E-IC-1 done (`EXTORQ_JEV_ENABLED`/`EXTORQ_GEMINI_ENABLED` default false, `EXTORQ_AI_DOTENV=""`).
  `api`/`ai-worker` run with `read_only: false` because compose cannot materialise
  `environment:`-sourced secrets in a read-only rootfs (verified error); verified key states:
  ai-worker jev_key=configured/gemini_key=missing, api jev_key=missing/gemini_key=configured.
  Also fixed: `<NAME>_FILE` now populates aliased settings (`JEV_API_KEY_FILE`,
  `GEMINI_API_KEY_FILE`) in `extorq.common.config.Settings`.
- F: F-02, F-03, F-04, F-05 resolved; F-06 incl. residual forms (`--requirepass`, `redis-cli -a`,
  `curl -u user:pass`, `PGPASSWORD=`/`MYSQL_PWD=`-style env assignments) resolved; F-19 gateway
  part implemented (your 2 xfail tests now XPASS: drop the markers). known-limitations P7
  (Makefile/CI) and S7/F-06 are now addressed (your doc).
- B1, C3: repo-wide `uv run mypy` reports 44 errors in `collectors/.../linux/discovery.py` and
  `scanners/src/extorq_scanners/*` (CI `mypy` job fails until fixed).

## Done
- Session 1: bootstrap, extorq.common, ClickHouse config + RBAC 0002 + migration runner, rows,
  gateway, spool, writer, compose (core/full/debug), backend image, root CLI.
- Session 2:
  - Schema 1.1: rows for services, service_instances, event service/container columns, finding
    service_id, alert service_ids (`alert_to_row`); gateway strict JSON (NaN/Infinity -> 400),
    per-record exception quarantine, F-19 identity binding, service kinds in time checks,
    redaction and authorization, status reports 1.1; producers.json with service kinds +
    extorq-selftest; config `_FILE` alias fix.
  - Collector SDK finished: package API, runner fixes (no snapshot leakage via health, sanitised
    health details, read-only status), asset_upsert, heartbeat example, CLI run/status/flush/
    sim-record, dead-letter requeue, systemic-4xx policy.
  - F findings F-02/03/04/05/06/19 (A parts) fixed.
  - Compose: E-IC-1 flags; api/ai-worker writable rootfs fix; validated core/full/debug.
  - Makefile (all targets incl. delegations), CI workflow (`.github/workflows/ci.yml`), `.dockerignore`.
  - Tests: unit (`tests/unit/platform`, 139), integration (`tests/integration/platform`, 26),
    failure (`tests/failure`, 2). Scripts: `scripts/demo_check.py`.
  - Docs: docs/data-model.md, docs/data-flow.md, docs/collectors.md, backend/AGENTS.md,
    docs/team/interface-changes/A.md (A-IC-1..3).

## Verified (commands and observed results)
| Claim | Command | Result |
|---|---|---|
| rows map every RecordKind (+alerts, quarantine, audit) exactly onto the 0001+0004 DDL | `uv run pytest tests/unit/platform/test_platform_rows.py -q` | passed (part of 139) |
| platform unit suite (common, rows, gateway, writer/spool, SDK, bootstrap, migrate, CLI) | `uv run pytest tests/unit/platform -q` | 139 passed |
| lint/format/types on my paths | `uv run ruff check <A paths>`; `uv run ruff format <A paths>`; `uv run mypy <A modules>` | all checks passed; no issues in 31 source files |
| whole default suite (all teams) | `uv run pytest -q --ignore=tests/rules` | 1531 passed, 5 skipped (before the F-19 change); security suite after: 293 passed + 2 xpassed (F-19) |
| live integration (round trip, dedup/replay counts, 401/403 audit, RBAC matrix, default user, profiles, F-19 on the deployed gateway) | `uv run pytest -q -m integration tests/integration/platform` | 26 passed |
| durability under failure | `uv run pytest -q -m failure tests/failure -s` | 2 passed: ClickHouse outage 9.1 s, 100/100 delivered; 800/800 across ingest+writer restarts, 800 rows |
| SDK end to end on the live gateway | `make sdk-selftest` | exit 0; `collector_health` row for sdk-heartbeat-example (producer extorq-selftest) |
| HTTPS ingest -> ClickHouse | `uv run python scripts/smoke_ingest.py` | HTTP 202 accepted=1; read back as extorq_api_ro (0.17-0.68 s) |
| `make up` works (build, migrate one-shot, --wait) | `make up` | migrate exited 0, ingest/writer healthy in 15 s |
| migration 0005 applied | `make migrate` | `0005_findings_services` applied; grafana role reads `v_findings_current.service_id` |
| bootstrap idempotent, 0600/0700, registry = PLAN + service kinds | `uv run python scripts/bootstrap.py`; unit tests | 2nd run created=0 rotated=0; token hashes verified |
| compose valid | `docker compose config --quiet`; `docker compose --profile full --profile debug config --quiet` | both valid |
| compose api works | `docker compose --profile full up -d --no-deps api` + probes | healthy; /api/v1/health 200; /api/v1/services 200 (80 services); no token 401; viewer POST 403 |
| ai-worker/api key isolation | `startup_report()` inside both containers | ai-worker: jev configured, gemini missing; api: jev missing, gemini configured; both disabled |
| CI workflow passes F's checks; scanner commands work | `uv run pytest tests/security/test_security_ci.py`; local `docker run` of the CI gitleaks (4 commits scanned, no leaks) and trivy commands (uv.lock, pnpm-lock: 0 fixable HIGH/CRITICAL) | 4 passed; exit 0 / exit 0 |
| demo readiness report | `make demo-check` | core platform ready (migrations 0001-0005, collectors, pipeline, rules, alerts, services, simulations listed) |

## Not verified
- CI on GitHub itself (no push; actions pinned to SHAs resolved with `gh api`).
- `make up-full` as a whole (detector/grafana are started by their owners; frontend image not
  built by A; compose `ai-worker` loop not started to avoid interfering with E's host run).
- `make rotate` + `make rotate-apply` on the live stack (rotation logic unit-tested only).

## Blockers
- none

## Next
- Keep the stack healthy; rebuild/recreate ingest/writer on request (e.g. B2 normaliser updates).
- Lead: ratify A-IC-1 (extorq-selftest producer) and decide A-IC-2 (instances without asset_id).
