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
| **A – Platform & Data** | compose, ClickHouse config/RBAC/migrations runner, ingest gateway, spool, writer, collector SDK, bootstrap/secrets/TLS, Makefile, CI | `compose.yaml`, `infra/compose/**`, `infra/clickhouse/**` (except 0001), `infra/tls/**`, `backend/src/extorq/{common,storage,ingest,pipeline}/**`, `backend/src/extorq/cli.py`, `backend/Dockerfile`, `collectors/src/extorq_collectors/sdk/**`, `collectors/src/extorq_collectors/cli.py`, `scripts/**`, `Makefile`, `.github/**`, `.env.example`, `.dockerignore`, `tests/unit/platform/**`, `tests/integration/platform/**`, `tests/failure/**`, `docs/data-model.md`, `docs/data-flow.md`, `docs/collectors.md`, `backend/AGENTS.md` |
| **B1 – Linux & macOS telemetry** | Ubuntu VM (QEMU/HVF, cloud-init), SSH dispatch boundary, nginx + lab web app, auditd, Linux collector, macOS collector, VM/HTTP simulations | `infra/vm/**`, `collectors/src/extorq_collectors/{linux,macos}/**`, `config/collectors/{linux,macos}.yaml`, `simulations/{vm,http}/**`, `tests/unit/linux/**`, `tests/unit/macos/**`, `tests/fixtures/{linux,macos}/**`, `docs/telemetry/{linux,macos}.md`, `collectors/AGENTS.md` |
| **B2 – Kubernetes telemetry** | Kind cluster with API audit logging, PSA namespaces, OTel Collector DaemonSet, lab workloads, K8s inventory/posture collector, K8s simulations | `infra/kind/**`, `collectors/src/extorq_collectors/kubernetes/**`, `config/collectors/kubernetes.yaml`, `simulations/k8s/**`, `tests/unit/kubernetes/**`, `tests/fixtures/kubernetes/**`, `docs/telemetry/kubernetes.md`, `infra/kind/AGENTS.md` |
| **C1 – GitHub & scanners** | GitHub API collector + workflow analyzer, repo posture, Trivy/Gitleaks/Semgrep integration, findings lifecycle view, lab repo content, GH simulation | `collectors/src/extorq_collectors/github/**`, `config/collectors/github.yaml`, `scanners/**`, `config/scanners.yaml`, `infra/clickhouse/migrations/0003_findings_views.sql`, `lab/github-repo/**`, `simulations/github/**`, `tests/unit/{github,scanners}/**`, `tests/fixtures/{github,scanners}/**`, `docs/telemetry/{github,scanners}.md` |
| **C2 – Detection & correlation** | rule format/registry/loader/validator, detection engine + detector service, alert identity/dedup, rule tests harness, rules, correlation + context builder, simulation verification | `rules/**`, `backend/src/extorq/{detection,correlation}/**`, `simulations/lib/**`, `simulations/README.md`, `tests/unit/{detection,correlation}/**`, `tests/rules/**`, `docs/{detection-engine,detection-catalog,correlation,attack-scenarios}.md`, `rules/AGENTS.md` |
| **D – Analyst experience** | analyst API (FastAPI), Next.js + shadcn console, Grafana provisioning/dashboards | `backend/src/extorq/api/**`, `frontend/**`, `infra/grafana/**`, `tests/unit/api/**`, `tests/integration/api/**`, `frontend/AGENTS.md` |
| **E – AI engineering** | Jev triage provider, Gemini summary provider, budgets/flags, sanitisation, evidence validation, ai-worker, evaluation dataset/harness | `backend/src/extorq/ai/**`, `tests/unit/ai/**`, `tests/ai/**`, `eval/**`, `docs/ai-integrations.md` |
| **F – Security assurance, QA, docs** | threat model, privilege audit, independent review, docs set, ADRs, final QA | `README.md`, `AGENTS.md`, `docs/{architecture,threat-model,security,testing,operations,deployment,known-limitations,demo-runbook,telemetry-sources}.md`, `docs/adr/**`, `tests/security/**` |

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
