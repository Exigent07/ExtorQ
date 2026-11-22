# ExtorQ Team Plan — Architecture Baseline, Ownership and Interfaces

Status: **authoritative** for the build. Owner: team lead. Changes to anything in
§3–§6 follow the interface-change protocol (§8). Demo: **Mon 2026-11-23**.

Priority order when trade-offs are needed:
**real telemetry → reliable storage → five working detections → security posture →
demonstrable UI → correlation → AI enrichment → polish.** The system must work with
Jev and Gemini completely unavailable.

---

## 1. Pipeline

```
collectors / scanners ──TLS+token──▶ ingest gateway ──▶ SQLite spool (durable, WAL)
   (host-native, OTel in kind)        (validate, authz,      │
                                       redact, dedup,         ▼
                                       quarantine)        writer ──batched──▶ ClickHouse
                                                                               │
          detector (versioned SQL rules) ◀──────────────────────────────────────┤
              │ alerts + evidence + rule_runs                                  │
              ▼                                                                 │
          correlation → InvestigationContext (hashed)  ─────────────────────────┤
              │                                                                 │
          ai-worker (Jev triage, advisory) ── ai_assessments ───────────────────┤
              │                                                                 │
          api (read API, Gemini on demand) ◀─── frontend (Next.js)   grafana ◀──┘
```

## 2. Team and ownership

Only the owner edits a path. Need a change elsewhere? Write it in your
`docs/team/interface-changes/<you>.md` and report it; the lead integrates.

| Agent | Scope | Owns (write access) |
|---|---|---|
| **Lead** | contracts, schema baseline, integration, final verification | `backend/src/extorq/contracts/**`, `infra/clickhouse/migrations/0001_core_tables.sql`, `pyproject.toml` (all), `uv.lock`, `docs/team/PLAN.md`, `docs/team/TASKBOARD.md`, `CLAUDE.md` |
| **A – Platform & Data** | compose, ClickHouse config/RBAC/migrations runner, ingest gateway, spool, writer, collector SDK, bootstrap/secrets/TLS, Makefile, CI | `compose.yaml`, `infra/compose/**`, `infra/clickhouse/**` (except 0001 and 0003), `infra/tls/**`, `backend/src/extorq/{common,storage,pipeline}/**`, `backend/src/extorq/ingest/**` (except `otlp_k8s.py`), `backend/src/extorq/cli.py`, `backend/Dockerfile`, `collectors/src/extorq_collectors/sdk/**`, `collectors/src/extorq_collectors/cli.py`, `scripts/**`, `Makefile`, `.github/**`, `.env.example`, `.dockerignore`, `tests/unit/platform/**`, `tests/integration/platform/**`, `tests/failure/**`, `docs/data-model.md`, `docs/data-flow.md`, `docs/collectors.md`, `backend/AGENTS.md` |
| **B1 – Linux VM telemetry** | Ubuntu VM (QEMU/HVF, cloud-init), SSH dispatch boundary, nginx, lab web app, auditd, Linux SSH collector, VM/HTTP simulations | `infra/vm/**`, `lab/apps/lab-portal/**`, `collectors/src/extorq_collectors/linux/**`, `config/collectors/linux.yaml`, `simulations/{vm,http}/**`, `tests/unit/linux/**`, `tests/fixtures/linux/**`, `docs/telemetry/linux.md`, `collectors/AGENTS.md` |
| **B2 – Kubernetes telemetry** | Kind cluster with API audit logging, PSA namespaces, OTel Collector DaemonSet, lab workloads, OTLP→event normaliser, K8s inventory/posture collector, K8s simulations | `infra/kind/**`, `backend/src/extorq/ingest/otlp_k8s.py`, `collectors/src/extorq_collectors/kubernetes/**`, `config/collectors/kubernetes.yaml`, `simulations/k8s/**`, `tests/unit/kubernetes/**`, `tests/fixtures/kubernetes/**`, `docs/telemetry/kubernetes.md`, `infra/kind/AGENTS.md` |
| **B3 – macOS telemetry** | native macOS collector (unified log, launchd, posture, inventory), MAC-001 simulation | `collectors/src/extorq_collectors/macos/**`, `config/collectors/macos.yaml`, `simulations/macos/**`, `tests/unit/macos/**`, `tests/fixtures/macos/**`, `docs/telemetry/macos.md` |
| **C1 – GitHub security** | GitHub API collector + workflow analyzer, repo posture, lab repo content, GH-001 simulation | `collectors/src/extorq_collectors/github/**`, `config/collectors/github.yaml`, `lab/github-repo/**`, `simulations/github/**`, `tests/unit/github/**`, `tests/fixtures/github/**`, `docs/telemetry/github.md` |
| **C2 – Detection & correlation** | rule format/registry/loader/validator, detection engine + detector service, alert identity/dedup, rule test harness, rules, correlation + context builder, scenario verification tooling | `rules/**`, `backend/src/extorq/{detection,correlation}/**`, `simulations/lib/**`, `simulations/README.md`, `tests/unit/{detection,correlation}/**`, `tests/rules/**`, `docs/{detection-engine,detection-catalog,correlation,attack-scenarios}.md`, `rules/AGENTS.md` |
| **C3 – Scanners & findings** | Trivy/Gitleaks/Semgrep integration, Linux package SBOM scanning, findings lifecycle view | `scanners/**`, `config/scanners.yaml`, `infra/clickhouse/migrations/0003_findings_views.sql`, `tests/unit/scanners/**`, `tests/fixtures/scanners/**`, `docs/telemetry/scanners.md` |
| **D1 – API & Grafana** | analyst API (FastAPI), OpenAPI contract, Grafana provisioning/dashboards | `backend/src/extorq/api/**`, `infra/grafana/**`, `docs/api/**`, `tests/unit/api/**`, `tests/integration/api/**` |
| **D2 – Security console** | Next.js + TypeScript + shadcn/ui console | `frontend/**` |
| **E – AI engineering** | Jev triage provider, Gemini summary provider, budgets/flags, sanitisation, evidence validation, ai-worker, evaluation dataset/harness | `backend/src/extorq/ai/**`, `tests/unit/ai/**`, `tests/ai/**`, `eval/**`, `docs/ai-integrations.md` |
| **F – Security assurance, QA, docs** | threat model, privilege audit, independent review, docs set, ADRs, final QA | `README.md`, `AGENTS.md`, `docs/{architecture,threat-model,security,testing,operations,deployment,known-limitations,demo-runbook,telemetry-sources}.md`, `docs/adr/**`, `tests/security/**` |

Shared lab-app log contract: B1 owns the lab web app and its JSON log schema
(`docs/team/interface-changes/B1.md`); B2 packages the same source as a container
image; A's gateway (via B2's `otlp_k8s.py`) and B1's Linux collector both parse it.

## 3. Shared contracts (lead-owned; read before coding)

* Pydantic models: `backend/src/extorq/contracts/` (schema **1.0**). Every
  cross-boundary record is one of these. Never define a parallel format.
* Event catalog: `contracts/catalog.py`. The gateway quarantines unknown event
  types, category mismatches and disallowed source types.
* Identities: `contracts/identity.py` (`event_id`, `finding_id`, `alert_id`,
  `context_id`, `assessment_id`, `scope_hash`, `canonical_json`, `input_hash`).
* ClickHouse schema: `infra/clickhouse/migrations/0001_core_tables.sql`
  (validated on ClickHouse 26.8.42). Column names there are the contract for
  rule SQL, API queries and Grafana panels.

Invariants:
1. Unknown stays unknown (`None`/NULL). Never invent telemetry fields.
2. Timestamps are aware UTC; naive ones are rejected.
3. Queries are duplicate-safe (`uniqExact(event_id)`, `argMax`, `FINAL`).
4. Alerts are written only by the detector. AI writes only `ai_assessments`.
5. Logs, commit messages, HTTP paths, k8s object fields are attacker-controlled.
6. Secrets never appear in logs, events, fixtures, docs, AI requests or agent messages.

## 4. Runtime topology

### 4.1 Compose services (A owns `compose.yaml`)

| Service | Image | Networks | Published (127.0.0.1 only) | Purpose |
|---|---|---|---|---|
| clickhouse | `clickhouse/clickhouse-server:26.8.42.13` | data | — | storage |
| clickhouse-debug | socat proxy, **profile `debug`** | data, edge | 18123 → clickhouse:8123 | tests/debug only |
| migrate | backend image, one-shot `extorq migrate` | data | — | schema + RBAC |
| ingest | backend image `extorq gateway` | edge | **8443** (HTTPS) | ingestion gateway |
| writer | backend image `extorq writer` | data | — | spool → ClickHouse |
| detector | backend image `extorq detector` | data | — | rules + correlation |
| ai-worker | backend image `extorq ai-worker` | data, edge | — | Jev triage |
| api | backend image `extorq api` | data, edge | 8000 | analyst API |
| frontend | `frontend/Dockerfile` (Next standalone) | edge | **3000** | console |
| grafana | `infra/grafana/Dockerfile` (plugin baked in) | data, edge | **3001** | analytics |

`data` is `internal: true` (no egress). `ingest` and `writer` share the named
volume `spool` (SQLite WAL). Dev servers during development: frontend **3100**,
API **8100** (never bind the compose ports from dev servers).

### 4.2 Lab assets and ports

| Asset | asset_id | Access from Mac |
|---|---|---|
| macOS host | `macos:workstation-01` | native |
| Ubuntu 24.04 VM (QEMU+HVF, user-mode net) | `linux:lab-vm-01` | SSH `127.0.0.1:2222`, HTTP `127.0.0.1:8088`; VM reaches Mac loopback as `10.0.2.2` |
| Kind cluster `extorq-lab` | `k8s:extorq-lab` | kubeconfig context `kind-extorq-lab`; demo app NodePort → `127.0.0.1:8089`; pods reach gateway at `https://host.docker.internal:8443` (verify; fallback documented) |
| GitHub repo | `github:<owner>/extorq-lab` (lower-case) | API via token |

Do not touch the pre-existing `motorq-security` kind cluster.

### 4.3 Producers, tokens and authorization (A implements, others consume)

`var/secrets/producers.json` (generated by `make bootstrap`, never committed):
`{producer_id, token_sha256, allowed_kinds[], allowed_source_types[], allowed_asset_patterns[]}`.
Each collector reads its token from `var/secrets/tokens/<producer_id>.token` (0600).

| producer_id | kinds | source types | assets |
|---|---|---|---|
| `macos-workstation-01` | event, asset, inventory_item, finding, scan_run, collector_health | `macos.*` | `macos:workstation-01` |
| `linux-ssh-lab-vm-01` | same | `linux.*` | `linux:lab-vm-01` |
| `k8s-inventory-extorq-lab` | same | `k8s.api_inventory`, `k8s.events`, `k8s.posture` | `k8s:extorq-lab*` |
| `k8s-otel-extorq-lab` | event (via OTLP endpoint) | `k8s.audit`, `k8s.container_log` | `k8s:extorq-lab*` |
| `github-collector` | same as macos | `github.*` | `github:*` |
| `scanner-runner` | asset, finding, scan_run, collector_health | `scanner.*` | any configured lab asset |
| `simulation-runner` | simulation_run | `extorq.simulation` | any configured lab asset |

### 4.4 ClickHouse identities (A implements in `infra/clickhouse/migrations/0002_rbac.sql`+runner)

Admin `extorq_admin` (migrations only). Service users with least privilege,
`HOST IP` restricted to private ranges, settings profiles + quotas:

* `extorq_ingest` – INSERT only: events, assets, inventory_items, scan_runs, finding_observations, collector_health, pipeline_health, ingest_quarantine, ingest_audit, simulation_runs.
* `extorq_detect` – SELECT telemetry/alert tables; INSERT alerts, alert_evidence, rule_runs, detection_rules, investigation_contexts, context_relationships, pipeline_health.
* `extorq_rules_ro` – SELECT events, assets, inventory_items, finding_observations, scan_runs, simulation_runs; `readonly=1`. Executes rule SQL only.
* `extorq_ai` – SELECT alerts, investigation_contexts, context_relationships, ai_assessments; INSERT ai_assessments, pipeline_health. **No write on alerts.**
* `extorq_api_ro` – SELECT all `extorq.*`; `readonly=2`, max_execution_time, result limits.
* `extorq_api_writer` – INSERT analyst_state, analyst_actions, ai_assessments, investigation_contexts, context_relationships. **No write on alerts.**
* `extorq_grafana` – SELECT on analytics tables; on `events` every column except `raw`, `payload`; `readonly=2`, quota.

The `default` user must have no network access. Passwords: `var/secrets/clickhouse/<user>_password`.

### 4.5 Secrets and configuration

* `.env` (user-owned, never modified/printed/committed): `JEV_API_KEY`, `GEMINI_API_KEY`.
  Compose passes them as file secrets (`secrets: …: environment: …`) only to
  `ai-worker`/`api`. Code maps `JEV_API_KEY` → `TypeSafeClient(api_key=…)`
  (the SDK's own env var is `TYPESAFE_API_KEY`).
* Generated secrets: `var/secrets/**` and `var/tls/**` by `make bootstrap` (0600).
* Settings: `extorq.common.config.Settings` (pydantic-settings, prefix `EXTORQ_`,
  every secret also accepts `<NAME>_FILE`). Startup checks report *missing* config
  by name, never values.
* Collector config (no secrets): `config/collectors/<collector>.yaml`.

## 5. Module interfaces (cross-team)

```python
# A — extorq.common
config.get_settings() -> Settings
logging.configure_logging(component: str) -> None; logging.get_logger(name) -> BoundLogger
redaction.redact_text(text: str) -> tuple[str, int]          # (redacted, count)
redaction.sanitize_untrusted(text: str, limit: int) -> str     # strip controls, truncate
# A — extorq.storage
clickhouse.get_client(role: Literal["admin","ingest","detect","rules_ro","ai","api_ro","api_writer"])
rows.TABLE_BY_KIND: dict[RecordKind, str]
rows.to_row(kind, model, *, producer_id, batch_id, ingested_at) -> dict
# A — collector SDK: extorq_collectors.sdk
class Collector(ABC): collector_type; source_types; def collect(self, ctx) -> None
class CollectorContext: collector_id, asset_id, producer_id, config, state (KV),
    checkpoints.get(key)/…, emit(records: list[IngestRecord], checkpoints: dict[str,str])  # atomic outbox+checkpoint
class GatewayClient(base_url, token, ca_file).send(batch) -> IngestResult
# runner: `extorq-collect run [--only a,b] [--once]`; collectors are configured in
# config/collectors/*.yaml with `module: package.module:ClassName`.
# `extorq-collect sim-record --scenario VM-001 --asset linux:lab-vm-01 --status started --run-id <id>`
# C2 — detection / correlation
detection.registry.load_rules(root="rules") -> list[LoadedRule]
detection.engine.DetectionEngine.run_once(now: datetime | None) -> list[RuleRun]
detection.service.main(once: bool = False) -> None                # compose `detector`
correlation.builder.ContextBuilder(read_client).build(alert_id) -> InvestigationContext
correlation.store.save_context(write_client, ctx); load_latest_context(read_client, alert_id)
# E — AI
ai.jev.JevTriageProvider.assess(ctx) -> AIAssessment
ai.gemini.GeminiSummaryProvider.summarize(ctx, requested_by) -> AIAssessment
ai.service.AIService.request_summary(alert_id, requested_by) -> AIAssessment   # used by API
ai.worker.main() -> None                                                       # compose `ai-worker`
ai.store.save_assessment(write_client, a); list_assessments(read_client, alert_id)
# D — API
api.app.create_app() -> FastAPI          # `extorq api`
```

Root CLI `extorq` (A) uses **lazy imports** of the entry points above:
`migrate | gateway | writer | detector [--once] | ai-worker | api | rules validate|test |
context build <alert_id> | ai triage|summary <alert_id> | ai eval`.

### 5.1 Ingestion HTTP (A)

* `POST /v1/ingest` — `IngestBatch` JSON (gzip ok). 202 `IngestResult`. 401 bad/missing
  token, 403 producer/kind/source/asset not authorized (logged to `ingest_audit`),
  413 > 4 MiB / > 1000 records, 415 content type, 422 envelope invalid, 503 spool
  full (`Retry-After`). Per-record failures → quarantine, batch continues. Events with
  `event_time` > now+1d or older than 400d → quarantine.
* `POST /v1/otlp/v1/logs` — OTLP/HTTP **JSON** logs from the kind OTel collector
  (bearer token). Normalises k8s audit lines and container logs into SecurityEvents.
* `GET /healthz` (no auth, no detail) · `GET /v1/status` (auth; spool depth, counters).

### 5.2 Analyst API (D) — base `/api/v1`, `Authorization: Bearer <api service token>`,
`X-ExtorQ-User`, `X-ExtorQ-Role` (`analyst`|`viewer`), mutations require `analyst`:
`GET overview · GET assets · GET assets/{id} · GET findings · GET rules · GET rules/{id} ·
GET alerts · GET alerts/{id} · GET alerts/{id}/context · GET alerts/{id}/assessments ·
POST alerts/{id}/summary · POST alerts/{id}/state · GET events · GET events/{id} ·
GET health · GET timeseries/{alerts|events}`.

### 5.3 Event semantics (from the catalog) used by mandatory rules

| Rule | Inputs | Grouping / identity |
|---|---|---|
| VM-001 failed SSH auth | `auth.ssh.{login_failed,invalid_user,preauth_closed,max_auth_exceeded}` (`linux.journald`) | (asset, src_ip); window 5 min; ≥5 distinct (src_ip,src_port) connections; bucket identity |
| VM-002 systemd persistence | `persistence.systemd.unit_{created,modified,enabled}` (`linux.inventory`) + optional `file.audit.watch` key `extorq_systemd` (`linux.auditd`) | (asset, unit path, sha256); unit not in allowlist; high confidence when both sources agree |
| K8S-001 privileged pod denied | `k8s.api.request` verb=create resource=pods code=403 with privileged/host* in `attributes.request_summary` or `attributes.pod_security_violation` | audit_id |
| K8S-002 risky RBAC | `k8s.api.request` create/update/patch on (cluster)rolebindings/(cluster)roles, success, risky roleRef/subjects/rules **and/or** `k8s.resource.{created,updated}` with `attributes.risk_flags` | (cluster, kind/ns/name, risk signature); high confidence when audit + state agree |
| GH-001 workflow permissions | `github.workflow.modified` with `write_all_added` or sensitive `added_write_scopes` or dangerous `triggers_added` | (repo, commit, workflow path) |

Simulation marker: any actor/object name containing `extorq-sim-<run_id>` sets
`event.simulation` (telemetry stays genuine; rules do **not** filter it out).

## 6. Conventions

* Python 3.12, `uv run …`; ruff (`make lint`), mypy (`make typecheck`), pytest.
* Structured JSON logs via `extorq.common.logging`; never log tokens, passwords,
  API keys, Authorization headers, prompt bodies or raw secrets.
* Every external call has a timeout and bounded retries with backoff + jitter.
* SQL: ClickHouse server-side parameters (`{name:Type}`) only; never f-string values.
* Subprocess: argument lists, never `shell=True`; validate every argument.
* Tests: unit tests next to your area under `tests/`; markers `integration`, `lab`,
  `live_ai`, `failure`. Never claim a test passed unless you ran it.
* Docs describe implemented behaviour only; label anything planned as **planned**.

## 7. Shared-infrastructure rules (avoid stepping on each other)

* Only **A** (and the lead) may run `docker compose down`, restart ClickHouse, or
  run failure-injection tests against the shared stack. Others may `up -d <service>`
  only for services they own.
* B1 owns the VM lifecycle; B2 owns the `extorq-lab` cluster lifecycle.
* Throwaway containers for your own tests must use unique names prefixed with your
  agent id (e.g. `extorq-c2-rules-ch`) and be removed afterwards.
* No paid-API loops: Jev/Gemini live calls only via budgeted code paths, ≤ 20 live
  calls per agent per phase, never in unit tests.
* GitHub: no pushes or repo creation without the lead's explicit go-ahead
  (outward-facing). Read-only API calls are fine.

## 8. Interface-change protocol

1. Write the proposal in `docs/team/interface-changes/<agent>.md` (what, why,
   affected agents). 2. Do not edit lead-owned files. 3. Report it in your final
   structured output. The lead merges contract/schema changes and announces them.

## 9. Status reporting

Each agent keeps `docs/team/status/<agent>.md` current: done, verified (with the
exact commands run and their results), not verified, blockers, next steps.
The lead maintains `docs/team/TASKBOARD.md`.

---

## 10. Amendment (2026-11-21): node-wise, service-aware monitoring

Hosts and Kubernetes nodes run many services; ExtorQ models them explicitly instead
of one undifferentiated telemetry stream. Contract schema **1.1** (additive; 1.0
records stay valid). Lead-owned artefacts (already merged and applied):

* `backend/src/extorq/contracts/service.py` — `Service`, `ServiceInstance`,
  `ServiceEndpoint`, `ServiceRef`, enums `ServiceKind` (host_service, application,
  k8s_workload, k8s_service), `ServiceCategory`, `AdapterSupport`
  (implemented / planned / none), `MonitoringStatus` (monitored / degraded /
  unmonitored), `DiscoveryEvidence`, `PortAttribution` (confirmed / inferred / unknown).
* `SecurityEvent.service: ServiceRef | None`, `KubernetesInfo.container_id`,
  `PostureFinding.service_id`, `DetectionAlert.service_ids`,
  `InvestigationContext.services` / `related_assets`, `EventSummary.service_*`,
  new `RelationshipBasis` values (same_service, same_service_instance,
  cross_service_same_asset, cross_asset), `AssetType.KUBERNETES_NODE`
  (asset id `k8s:<cluster>/node/<name>`), record kinds `service`, `service_instance`.
* Identities: `identity.service_id(asset_id, service_kind, service_key)`,
  `identity.instance_id(service_id, instance_kind, instance_key)`.
* Catalog: `service.discovered`, `service.removed`, `service.exposure.changed`,
  `http.server.error`, `audit.config.changed`, `account.user.created/deleted`,
  source type `linux.apache`; `extorq.collector.gap_detected` may now be emitted
  under each collector's own source types; `system.log.notable` also from `linux.auditd`.
* Migration `0004_services.sql` (applied live): tables `services`,
  `service_instances`, views `v_services`, `v_service_instances_current`; columns
  `events.{service_id, service_name, service_instance_id, adapter_id, k8s_container_id}`,
  `finding_observations.service_id`, `alerts.service_ids`; grants.
* Collector-side interface `collectors/src/extorq_collectors/services/`
  (`ServiceCandidate`, `ServiceAdapter`, `AdapterContext`, registry with
  implemented-over-planned precedence, `classify_coverage`, `build_service`,
  `exposure_of`, `service_ref`) and **planned** adapters: ftp (vsftpd/ProFTPD),
  postgresql, mysql, dns, redis. Also `ContractModel` now rejects NaN/Infinity.

### 10.1 Rules of the service model
1. A service exists only with discovery evidence. A process is never assumed to be a
   network service; a port is attributed to a service only with explicit
   `PortAttribution` (confirmed requires an observed socket owner).
2. Coverage is explicit and visible: discovered → supported (adapter implemented) →
   actively monitored (enabled + fresh). Unsupported/planned/unmonitored services are
   shown, never hidden.
3. Kubernetes: nodes are assets; workloads and logical Kubernetes Services are
   distinct `ServiceKind`s; Pods/containers are `ServiceInstance`s. A Kubernetes
   Service is never confused with a host OS service.
4. Adapters collect only what their source supports and declare `never_collects`
   (no FTP file contents, credentials, HTTP Authorization headers, DB query text).
5. Correlation across services/hosts preserves identities, timestamps, network
   context and confidence; temporal proximity alone is never causation.

### 10.2 Ownership and work per agent
| Agent | Amendment work |
|---|---|
| A | rows mapping for `service`/`service_instance` + new event/finding/alert columns; producers registry allows the new kinds for host + k8s inventory producers; gateway accepts 1.1, rejects NaN/Infinity tokens; console wiring from `docs/team/interface-changes/D2.md`; SDK support for service records |
| B1 | owns the shared `collectors/src/extorq_collectors/services/**` package from now on (extend, don't break the interface); Linux discovery (systemd units, processes, listening sockets, nginx/sshd/app config refs); **implemented** adapters in `extorq_collectors/linux/adapters/`: ssh, nginx (access + error log), apache (access/error parsers; tested on documented formats, marked not deployed in the lab), webapp-json (lab-portal), systemd (lifecycle + persistence); events carry `ServiceRef`; Service/ServiceInstance records; `service.*` events |
| B3 | macOS discovery (launchd jobs, processes, listeners) through the shared interface; ssh adapter binding for macOS unified-log sshd where Remote Login is enabled (else the service is reported not running/unmonitored) |
| B2 | Kubernetes hierarchy: node assets, workload + Kubernetes Service services, Pod/container instances, container-log enrichment (pod uid, container id, namespace, node, workload) and `ServiceRef` on events in `otlp_k8s.py` |
| C2 | service-aware correlation (relationship bases, cross-service on one asset, cross-asset only with identity evidence), `alerts.service_ids`, rule **CORR-002** (ordered sequence HTTP probing → SSH auth failures → unexpected systemd change on one host, e.g. ClickHouse `windowFunnel`, confidence never implies causation) |
| C3 | migration `0005_findings_services.sql` (CREATE OR REPLACE VIEW `v_findings_current` adding `service_id`), service attribution of findings where evidence allows (e.g. package → owning service, inferred) |
| D1 | `GET /api/v1/assets/{id}/services`, `GET /api/v1/services`, `GET /api/v1/services/{service_id}` (instances, endpoints, telemetry coverage, events, findings, alerts); regenerate OpenAPI |
| D2 | drill-down Asset → Services/Workloads → Telemetry → Findings → Alerts → Investigation; unsupported/unmonitored services shown transparently |
| E | include service summaries in the AI allow-list projection (names, kinds, coverage only) |
| F | architecture/data-model/threat-model/AGENTS.md updates for the service model and adapter data minimisation |

## 11. Lead decisions (2026-11-22, after build session 2)

* **Event age vs retention:** events older than the `events` TTL (90 days) are quarantined
  at the gateway with reason `older_than_retention` (previously accepted up to 400 days and
  then silently expired). Owner: A.
* **Producers:** `extorq-selftest` (collector_health only, source `extorq.pipeline`, asset
  `macos:workstation-01`) is part of the registry for the SDK heartbeat self-test (A-IC-1).
* **Analyst API (§5.2 additions):** `GET /api/v1/assets/{asset_id}/services`,
  `GET /api/v1/services`, `GET /api/v1/services/{service_id}`; `service_id` filters on
  events/findings/alerts (D1-IC-2).
* **Catalog:** `macos.unified_log` may emit `auth.ssh.{login_failed, invalid_user,
  preauth_closed, max_auth_exceeded, login_succeeded}` (B3-IC-1). `container_id` canonical
  form is the bare 64-hex id (B2-IC-3).
* **Migration 0006** refreshes `v_alerts` (views freeze `SELECT *` column lists at CREATE).
* **GitHub lab:** `Exigent07/extorq-lab` created PRIVATE by the lead with the user's explicit
  approval; the collector uses the gh CLI token fallback (approved; broader than read-only,
  flagged in health/docs). No other GitHub writes are authorised.
* **Data minimisation:** raw captures from the user's personal Mac (launchd/process/app
  inventories) are not committed; macOS fixtures are reduced to minimal representative
  samples before entering git history (owner B3).

## 12. User decisions (2026-11-22) and the detection-test matrix

**Decisions (binding):**
1. **No simulation category.** Contract schema **2.0** removed `SimulationTag`/`event.simulation`,
   `SimulationRun` and the `simulation_run` record kind, `alerts.simulation_run_ids`,
   `InvestigationContext.simulation_run_ids`, the `simulation_run` relationship basis and the
   `extorq.simulation` source type. Migration `0008_remove_simulation.sql` drops the storage.
   Detection tests are **real activity** on the monitored assets, verified by the test runner by
   asset + rule + time window. No `extorq-sim-*` markers, badges, filters or categories anywhere.
2. **Jev only.** Gemini is removed everywhere (contracts: `AIProvider.GEMINI`, `AITask.SUMMARY`,
   summary/validation models; code, API endpoint, UI panel, compose secret, settings, docs).
3. **No "lab" labels in the product UI** (environment pill, "Security console · Lab", breadcrumb
   roots, environment badges). Real resource names (hostnames, cluster and repository names) stay.
4. **Clean-slate verification:** the database is cleared and every asset is re-verified with the
   matrix below; results go to `docs/testing.md` with exact commands and outcomes.
5. New catalog types: `github.secret.exposed` (redacted match only), `software.installed`,
   `software.removed` (macOS).

**Detection-test matrix** (`detection_tests/`, runner `uv run python -m detection_tests run
--asset <linux|kubernetes|github|macos|all>`, `make test-detections`). Every positive test has a
negative control that must NOT raise the same rule, and every test cleans up after itself.
Artefact names are realistic but identifiable for cleanup (prefix `extorq-test-`), never "sim".

| Asset | Rule | Positive (real activity) | Negative control (must not alert that rule) |
|---|---|---|---|
| Linux | VM-001 SSH auth failure burst | ≥8 SSH connections from the Mac with commonly guessed users (root, admin, oracle, test, ubuntu) and a throwaway key | 3 successful key logins by the admin user |
| Linux | VM-002 systemd persistence | as admin+sudo: create `/etc/systemd/system/extorq-test-*.service` (ExecStart=/bin/true), daemon-reload, enable; cleanup | restart an existing unit (state change only) |
| Linux | **VM-003** local account created | `sudo useradd -M -s /usr/sbin/nologin extorq-test-*`; cleanup `userdel` | create/delete a temp file in /tmp |
| Linux | **VM-004** cron persistence | `sudo tee /etc/cron.d/extorq-test-*` (harmless `true` job); cleanup | `crontab -l` / read-only cron listing |
| Linux | HTTP-001 web probing | ≥12 probe-like paths (/.env, /.git/config, /wp-login.php, /phpmyadmin/, /server-status, /admin ...) | 20 normal 2xx requests |
| Linux | APP-001 web login failures | 6 failed POST /login on the VM web app | 1 failed + 1 successful login |
| Linux | CORR-002 multi-stage | HTTP-001 → VM-001 → VM-002 tests in order within 30 min | VM-001 test alone |
| Kubernetes | K8S-001 privileged pod denied | privileged pod into `extorq-restricted` → 403 | compliant pod in `extorq-restricted` (admitted), deleted |
| Kubernetes | K8S-002 risky RBAC | ClusterRoleBinding of a test SA to `cluster-admin`; cleanup | RoleBinding of a test SA to built-in `view` in one namespace |
| Kubernetes | **K8S-003** interactive exec into pod | `kubectl exec` into the web app pod running `id` | `kubectl logs` of the same pod |
| Kubernetes | **K8S-004** cluster-wide secret enumeration | `kubectl get secrets -A` by a human identity | `kubectl get configmap <one>` in one namespace |
| Kubernetes | **K8S-005** privileged/host-namespace pod admitted | privileged or hostPath pod created (201) in a namespace without PSA enforcement; cleanup | unprivileged pod in the same namespace |
| Kubernetes | APP-001 (cluster web app) | 6 failed logins via NodePort 127.0.0.1:8089 | successful login |
| GitHub | GH-001 workflow permission escalation | CI workflow → `permissions: write-all`; revert | change that reduces permissions |
| GitHub | **GH-002** privileged trigger + untrusted checkout | add `pull_request_target` workflow checking out the PR head; revert | `pull_request` workflow with checkout |
| GitHub | **GH-003** unpinned third-party action | add a third-party action pinned by tag (e.g. `docker/setup-buildx-action@v3`); revert | same action pinned to a full 40-hex SHA |
| GitHub | **GH-004** script injection via untrusted context | `run:` interpolating `${{ github.event.issue.title }}`; revert | value passed via `env:` and quoted shell variable |
| GitHub | **GH-005** credential committed | commit a FAKE credential-shaped string (generated, never real); revert | commit a high-entropy non-credential (e.g. SHA-256 checksum line) |
| macOS | MAC-001 new launch item | `~/Library/LaunchAgents/com.extorq.test.*.plist` (/usr/bin/true, not loaded); cleanup | create/delete a .txt file there |
| macOS | **MAC-002** launch item runs a shell/interpreter or user-writable path | plist with `["/bin/sh","-c","/tmp/extorq-test-*"]` (never loaded); cleanup | plist pointing to /usr/bin/true (MAC-001 only) |
| macOS | **MAC-003** listener exposed on all interfaces by a non-allowlisted process | minimal accept-and-close TCP listener on 0.0.0.0:<high port> for ≤3 cycles | same listener on 127.0.0.1 |
| macOS | **MAC-004** sudo authentication failure burst | `sudo -k`, then 3× wrong password via `sudo -S -v` (no privilege obtained) | a single failed attempt |
| macOS | **MAC-005** unsigned application installed | minimal unsigned bundle `/Applications/ExtorQ Test.app` (never executed); cleanup | copy of a signed Apple app bundle; cleanup |

GitHub tests push only to the private disposable repository `Exigent07/extorq-lab` (user-approved
for detection testing) and revert each change. macOS tests never use sudo successfully, never load
launch items and never change security settings.
