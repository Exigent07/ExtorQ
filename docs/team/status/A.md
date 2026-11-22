SDK READY 2026-11-21T14:42:12Z - `from extorq_collectors.sdk import Collector, CollectorContext, asset_upsert`; run `uv run extorq-collect run [--only a,b] [--once]` (configs config/collectors/*.yaml); `uv run extorq-collect sim-record --scenario <ID> --asset <asset> --status started|completed|failed|cleaned_up --run-id <id>`; details below and in docs/collectors.md
STACK READY 2026-11-21T10:36:49Z - gateway https://127.0.0.1:8443 (CA var/tls/ca.crt), producer tokens var/secrets/tokens/<producer_id>.token, ClickHouse debug proxy 127.0.0.1:18123 (profile debug; users per PLAN 4.4, passwords var/secrets/clickhouse/)

# Agent A status (Platform & Data)

## Session 3 (2026-11-22 IST = 2026-11-21 UTC): final fixes and demo readiness - DONE
Last update: 2026-11-21T20:39Z. All seven lead tasks done and verified (table below).

### Live state left behind (for the lead and other agents)
- Compose: clickhouse, migrate (one-shot, exit 0), ingest, writer, detector, ai-worker, api,
  frontend, grafana all up via `make up-full` (20:35Z, exit 0 in 49 s, `--wait` healthy);
  clickhouse-debug still up (other agents use it; stop it before the demo, F-01).
- AI flags OFF in the running containers (ai-worker reports `disabled`, api
  `EXTORQ_GEMINI_ENABLED=false`). `make up-demo` turns both on; NOT started by A (no AI budget).
- Background host collectors RUNNING: `make collectors-status` -> runner pid 59404 (another
  agent restarted it at 20:31:18Z with `make collectors-stop/start`; fine), all four `ok`,
  outbox 0, dead 0. Stop with `make collectors-stop`; never run a second `extorq-collect run`
  for these ids in parallel (the start script refuses to).
- Kubernetes inventory token: ~18 h left at 20:37Z (expires ~2026-11-22T14:50Z, before the
  demo). B2 must re-mint (`infra/kind/kind.sh token`) and then
  `make collectors-stop collectors-start`; `make demo-check` warns below 24 h.

### Done
1. Gateway: events with `event_time < now - retention` are quarantined as
   `older_than_retention: event_time is older than the events retention (90 days); ...`
   (`Limits.retention`, setting `EXTORQ_EVENT_RETENTION_DAYS`, default 90 = `events` TTL; a unit
   test parses the TTL from 0001 and fails on drift). Future check kept
   (`time: event_time_in_future`); other kinds unchanged (own TTL columns, future check only).
   `/v1/status` reports `limits.max_future_seconds` and `limits.event_retention_days`.
2. Redaction (B2-IC-2): key-based rules never rewrite `true/false/null/None`; after a quoted
   key (JSON/dict) never numbers or arrays; quoted values matched escape-aware (`"ab\"cd"`
   used to leak `cd`); numeric `"authorization": 123` no longer eats the closing `}`. Literal
   exemption also for `FOO_TOKEN=false`. Free-text numbers stay candidates (`password=123456`).
3. SDK: string-only config secret check with key context, error names the setting path only
   (C1 3.1); fixed a pre-existing leak (loader embedded pydantic `str(exc)` = `input_value`, i.e.
   the refused secret, in CLI errors); `ctx.mark_degraded(reason)` -> `degraded` + reasons in
   `last_error`/`details.degraded_reasons`, `last_success_at` still advances (B3-IC-2, C1 3.3);
   `ctx.committed_snapshot(name)` read-only copy (B3-IC-3). See interface-changes/A.md A-IC-4.
4. Grafana (D1-IC-1): `var/secrets/grafana_secret_key` from `make bootstrap`;
   `GF_SECURITY_SECRET_KEY__FILE`; grafana on a fresh `grafana-data` volume (old one held only
   provisioned state and data keys under Grafana's public default key; backed up to a temporary
   volume during the switch, removed after verification).
5. Runtime: `scripts/collectors_ctl.py` + `make collectors-start|stop|status` (nohup + own
   session, pidfile `var/run/collectors.pid`, log `var/log/collectors.log` 0600, idempotent
   start, refuses duplicate runners, never signals a recycled pid, zombies count as dead);
   `make up-full` = every service incl. frontend + ai-worker with `--wait` (AI off);
   `make up-demo` = same with both AI flags true; ingest (B2-IC-1), detector (C2-IC-2), api,
   frontend rebuilt/recreated; `scripts/demo_check.py` rewritten (see below).
6. Ruff: no findings in A's files. Others (`uv run ruff check . --exclude frontend`):
   14 in `lab/apps/lab-portal/app.py` (B1: E501 x3, UP032 x2, UP041 x3, RUF100 x5, S101);
   `ruff format --check` (now also formats Markdown code blocks): `docs/correlation.md` (C2),
   `docs/team/interface-changes/B1.md` (B1), `docs/team/interface-changes/F.md` (F),
   `infra/vm/lib/render_cloud_init.py` (B1), `lab/apps/lab-portal/app.py` (B1).
7. Docs: `docs/data-model.md` (contract 1.1 summary, 0005/0006, view-freezing note, retention
   alignment, migration table), `docs/data-flow.md` (retention quarantine, JSON-safe redaction,
   degraded status, guarantees table, demo-check), `docs/collectors.md` (config check, degraded
   hint, committed snapshots, background runner, ruff-formatted example), `backend/AGENTS.md`.

### Verified (session 3; commands and observed results)
| Claim | Command | Result |
|---|---|---|
| A unit suite | `uv run pytest tests/unit/platform -q` | 194 passed (new: retention x5, JSON-safe redaction incl. a seeded 400-document property test, SDK x14, controller x11, compose/bootstrap secret consistency) |
| security suite | `uv run pytest tests/security -q` | 296 passed, 32 deselected (gitleaks scan clean after building a synthetic test password at runtime) |
| whole default suite | `uv run pytest -q` (20:38Z) | 1909 passed, 5 skipped, 0 failed (an earlier run had 2 failures in E's `ai/projection` and C1's `github/workflow` while they were mid-edit) |
| live gateway (deployed code) | `uv run pytest -q -m integration tests/integration/platform` | 29 passed (new: 91-day event quarantined `older_than_retention` in `ingest_quarantine` and absent from `events`, 89-day event stored; `"automount_sa_token": false` survives in stored attributes; status reports the window) |
| lint / types | `uv run ruff check` + `ruff format --check` on A paths; `uv run mypy` | all checks passed; mypy: no issues in 195 source files (repo-wide) |
| B2-IC-1 | `docker exec extorq-ingest-1 python -c "...sha256(inspect.getsource(otlp_k8s))[:16]"` vs `shasum -a 256 backend/src/extorq/ingest/otlp_k8s.py` | `abc31d0c08efff94` == `abc31d0c08efff94` (after the 20:21Z recreate and again after `make up-full`) |
| B2-IC-2 live | ClickHouse: events with `attributes.request_summary` in the last 30 min | 2 of 2 valid JSON |
| no real traffic quarantined by the changes | `ingest_quarantine` last hour, grouped by producer/reason | only A's 2 synthetic integration probes |
| bootstrap idempotent | `python3 scripts/bootstrap.py` | created=1 (grafana_secret_key, 0600, 43 chars) kept=5; tokens/registry/TLS kept |
| Grafana with the new key | recreate + scratch probe (admin password read from file, never printed) | healthy in 7 s; 0 `level=error` lines; datasource "Data source is working"; query returns rows; 5 provisioned dashboards |
| background collectors | `make collectors-start`; ClickHouse `v_collector_latest` | all four `ok`, last_success 14-21 s; `collectors-start` twice -> "already running"; `make collectors-stop` -> stopped in ~1 s (SIGTERM handled, `collectors_stop_requested` logged) |
| `make up-full` | `make up-full` (20:35Z) | exit 0 in 48.6 s; migrate `already_applied` 0001-0006, `passwords_synced` 7; every service healthy/running |
| `make up-demo` renders AI on | `EXTORQ_JEV_ENABLED=true EXTORQ_GEMINI_ENABLED=true docker compose --profile full config` (and `make -n up-demo`) | both flags `"true"`; default rendering both `"false"` (not started) |
| detector on C2's code, rule runs flow | `docker logs extorq-detector-1`; demo-check rules section | late-data catch-up ran, 0 alerts duplicated; every rule ran <= 26 s before the check, 0 failed in 24 h, no missing sources |
| readiness | `uv run python scripts/demo_check.py` (20:37Z) | exit 0 `DEMO READY`; warnings: debug proxy running, k8s token ~18 h; scenarios VM-001 76fec91ab730 (23/23 evidence stored), VM-002 5ac7d8f5a069 (3/3), K8S-001 cfbff55664cf (1/1), K8S-002 afc76864b420 (2/2), GH-001 e70639259d30 (1/1), 0 synthetic |
| readiness without the debug proxy | `EXTORQ_CLICKHOUSE_PORT=1 uv run python scripts/demo_check.py` | queries ran inside the api container as api_ro; exit 0 |

### Not verified (session 3)
- `make up-demo` with AI actually ON (no live AI budget for A): only the rendered config.
- Failure-injection suite (`make test-failure`) not re-run: it stops shared services, and the
  pipeline code (spool/writer/sender) did not change this session.
- Collector behaviour across a k8s token expiry (B2 re-mints before the demo).
- B3/C1 adoption of `mark_degraded` / `committed_snapshot` (their code; A-IC-4 describes it).

## Session 2 history
Last update: 2026-11-21T15:15Z (session 2)

## Outage log (shared stack)
- 2026-11-21T20:35Z: `make up-full` end-to-end verification (rebuilds backend/frontend/grafana images from
  the current tree, re-runs `migrate`, recreates changed services; seconds per service).
- 2026-11-21T20:26Z: backend image rebuilt with C2's current detection code (rules validate: 9 valid, 0
  problems; `tests/unit/detection` + `tests/unit/correlation` 75 passed) and `detector` recreated
  (C2-IC-2). C2 may recreate it again when its session-3 work lands (last writer wins).
- 2026-11-21T20:26Z: `api` recreated on the 20:21Z backend image (D's tree at that time; `tests/unit/api`
  green), `ai-worker` started (AI flags OFF: reports `disabled`, no provider calls), `frontend`
  started from a fresh `frontend/Dockerfile` build (image a1ad98a6fa52). Seconds of API outage.
- 2026-11-21T20:23Z: `grafana` recreated with `GF_SECURITY_SECRET_KEY__FILE` (D1-IC-1) on a FRESH
  `grafana-data` volume (the old one only held provisioned state: 5 provisioned dashboards,
  1 read-only provisioned datasource, admin user, 0 annotations; its data keys were encrypted
  under Grafana's public default key). ~1 min Grafana outage.
- 2026-11-21T20:20Z (session 3): building extorq/backend:0.1.0 from the current tree, then recreating
  `ingest` + `writer` (seconds; collectors buffer and retry). `detector` NOT recreated while
  `uv run extorq rules validate` fails on C2's in-progress VM-002 (missing fixture): C2 recreates
  it when ready (or A does once rules validate). `api` follows after its unit tests pass.
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
  back as naive datetimes that are UTC. Migrations applied live: 0001-0006.

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
  Continuous: `make collectors-start|stop|status` (one background runner, session 3).
- Session 3: `ctx.mark_degraded(reason)` (partial success -> `degraded`) and
  `ctx.committed_snapshot(name)` (read-only copy of the last commit); config secret check
  looks at string settings only (A-IC-4).
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
