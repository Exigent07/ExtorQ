# AGENTS.md: ExtorQ Engineering Guide (canonical)

This is the canonical guide for AI agents and human engineers working on
ExtorQ. `CLAUDE.md` only imports this file; do not duplicate instructions
there. Build-time ownership, interfaces and the interface-change protocol are in
[`docs/team/PLAN.md`](docs/team/PLAN.md). Component guides sit next to the
code they describe and add detail without overriding the security invariants
below: [`backend/AGENTS.md`](backend/AGENTS.md) (present); `collectors/AGENTS.md`,
`rules/AGENTS.md`, `frontend/AGENTS.md` and `infra/kind/AGENTS.md` are owned by
B1, C2, D2 and B2 and were not present at the last update.

Documentation rule: describe only what exists; label anything else
**planned**.

## 1. What ExtorQ is

A security telemetry, detection, correlation and investigation platform (a
small SIEM) for a lab on one Apple Silicon Mac. It monitors four asset classes:
the **macOS host**, an **Ubuntu 24.04 VM** (QEMU/HVF), a **kind Kubernetes
cluster** (`extorq-lab`: control plane and workloads) and a **GitHub lab
repository**. Since contract schema 1.1 every host and node is further broken
down into **services** (host services, applications, Kubernetes workloads,
Kubernetes Service objects) and **service instances** (processes, containers,
Pods).

Core principle: **deterministic collection and detection establish the
evidence; AI assists interpretation and is never authoritative.**

Pipeline: collection and scanning -> authenticated ingestion gateway -> durable
SQLite spool -> writer -> ClickHouse -> versioned SQL detections -> correlation
and InvestigationContext -> optional AI enrichment (Jev triage, Gemini summary)
-> analyst API, console and Grafana. Full description:
[`docs/architecture.md`](docs/architecture.md).

### Goals
* Real telemetry from all four asset classes, attributed to services where the
  evidence allows.
* Reliable, restart-safe storage (durable spool, at-least-once delivery,
  duplicate-safe queries).
* Five working detections driven by genuine scenario telemetry: VM-001,
  VM-002, K8S-001, K8S-002, GH-001 (PLAN 5.3).
* Security posture findings tied to real scan runs.
* Evidence-traceable alerts and investigations with explicit confidence.
* Honest health, coverage and staleness signals; unmonitored services are shown.
* A polished analyst console.

### Non-goals
EDR-grade process or network telemetry; autonomous response or remediation;
AI-generated detections or AI authority over alerts; multi-tenant SaaS;
exactly-once delivery; claiming GitHub organisation audit-log or other
enterprise-only features without access; complete protocol coverage for every
service (additional adapters stay modular and planned).

## 2. Repository layout and responsibilities

| Path | Contents | Owner (PLAN 2) |
|---|---|---|
| `backend/src/extorq/contracts/` | versioned Pydantic contracts, event catalog, identities: the single source of truth | lead |
| `backend/src/extorq/{common,storage,pipeline,ingest}/` | config, logging, redaction; ClickHouse access and migrations runner; spool and writer; ingest gateway (`ingest/otlp_k8s.py`: B2) | A |
| `backend/src/extorq/{detection,correlation}/` | rule engine, SQL guard, alert identity, context builder | C2 |
| `backend/src/extorq/ai/` | Jev triage, Gemini summaries, sanitisation, budgets, worker | E |
| `backend/src/extorq/api/` | analyst API | D1 |
| `collectors/src/extorq_collectors/sdk/` | collector SDK: outbox, checkpoints, sender, runner | A |
| `collectors/src/extorq_collectors/services/` | shared service-discovery interface, adapter registry, planned adapters | B1 (from the lead) |
| `collectors/src/extorq_collectors/{linux,macos,kubernetes,github}/` | platform collectors and service adapters | B1, B3, B2, C1 |
| `scanners/` | Trivy, Gitleaks, Semgrep integration (`extorq-scan`) | C3 |
| `rules/` | detection rules (YAML metadata + SQL) and their JSONL fixtures | C2 |
| `simulations/` | safe, reversible attack scenarios for lab assets | B1, B2, B3, C1, C2 |
| `infra/clickhouse/` | server config, users, migrations (`0001`, `0004`: lead; `0002`: A; `0003`: C3) | as noted |
| `infra/vm/`, `infra/kind/`, `infra/grafana/` | Ubuntu VM, kind cluster, Grafana | B1, B2, D1 |
| `frontend/` | Next.js + shadcn/ui security console | D2 |
| `lab/` | monitored lab targets (lab portal app, lab GitHub repository content): deliberately attackable, not ExtorQ code | B1, C1 |
| `tests/` | unit, integration, failure, security, rules and AI tests | per area |
| `docs/` | architecture, threat model, security, runbooks, ADRs, telemetry docs | F and per area |
| `var/` | **local runtime state and secrets: gitignored, never commit, never print** | generated |

## 3. Security invariants (non-negotiable)

1. **Never print, log, commit or transmit secrets.** `.env` (user-owned) holds
   `JEV_API_KEY` and `GEMINI_API_KEY`: never overwrite, rename, delete, read,
   cat or echo it. Generated secrets live in `var/secrets/`, TLS material in
   `var/tls/`, VM keys in `var/vm/`, kubeconfigs in `var/kube/` (files 0600,
   directories 0700). Pass secrets by file path (`*_FILE` settings, compose
   file secrets). Startup checks name missing settings, never values. Tokens,
   passwords, Authorization headers and API keys are redacted from logs,
   errors, fixtures, docs, screenshots and AI prompts.
2. **All telemetry is untrusted input.** Log lines, commit messages, HTTP
   paths, user agents, user names, process names, unit descriptions,
   Kubernetes object fields and workflow YAML may be attacker-controlled.
   Validate, bound and sanitise; never render as HTML; never let it become
   instructions to an LLM; never interpolate it into SQL or shell commands.
3. **Least privilege everywhere.** One ClickHouse user per service (PLAN 4.4);
   read-only identities for analysts, rules and Grafana; collectors read-only;
   no secrets RBAC in Kubernetes; the VM collector key can only run a fixed
   allow-list of read-only dispatcher commands.
4. **Authoritative data is deterministic.** Only the detector writes alerts.
   AI writes only `ai_assessments` and cannot change severity, suppress,
   delete or remediate anything. Analyst actions live in `analyst_state` and
   `analyst_actions`.
5. **No exposure.** Services bind to `127.0.0.1` or internal Docker networks.
   ClickHouse is never exposed beyond the loopback debug proxy. No
   unauthenticated access to telemetry. Browser code never sees database or API
   credentials.
6. **Unknown stays unknown.** Never invent telemetry fields, fabricate metrics,
   detections, coverage or test results. Demonstrations use real scenario
   telemetry; synthetic fixtures are labelled synthetic.
7. **Collect only what a source supports and what is needed.** Service
   adapters declare `never_collects` and keep it: no FTP file contents,
   application credentials, HTTP Authorization headers or cookies, or database
   query text. Services carry configuration paths, never contents.
8. **No dangerous capabilities.** Never disable SIP or other host security
   controls, never build persistence or "unstoppable" agents, never run attacks
   outside lab assets.

## 4. Data contracts

* All cross-boundary records are contract models from
  `backend/src/extorq/contracts/` (schema **1.1**; 1.0 records stay valid):
  `SecurityEvent`, `Asset`, `InventoryItem`, `PostureFinding`, `ScanRun`,
  `CollectorHealth`, `SimulationRun`, `Service`, `ServiceInstance`, plus
  alerts, contexts and AI assessments. Models forbid extra fields, require
  aware UTC timestamps and reject NaN/Infinity.
* Event types, their categories and allowed source types are fixed in
  `contracts/catalog.py`; the gateway quarantines anything else.
* Identities are deterministic (`contracts/identity.py`). Breaking identity
  changes add a new namespace version (`*.v2`); never edit an existing one.
* ClickHouse column names in `infra/clickhouse/migrations/` are the contract for
  rule SQL, API queries and dashboards. Latest-state tables are
  `ReplacingMergeTree`: read them through the `v_*` views or with
  `FINAL`/`argMax`, count `uniqExact(event_id)`.
* Contract, catalog, schema and dependency changes go through
  `docs/team/interface-changes/<agent>.md` and the lead (PLAN 8).

## 5. Trust boundaries (summary)

Full model: [`docs/threat-model.md`](docs/threat-model.md); identities and
ports: [`docs/security.md`](docs/security.md).

| Boundary | Control |
|---|---|
| Producers -> gateway | TLS with the local CA, per-producer bearer token (digest compared against all producers), per-record authorisation of kind, asset and source type |
| Host loopback -> services | `127.0.0.1` publishing only; every service authenticates (lab assets can reach host loopback: T18) |
| `edge` -> `data` network | `data` is internal (no egress); ClickHouse is on `data` only |
| Mac -> VM | SSH key bound to a forced read-only dispatcher (`restrict,command=`, `ForceCommand`) |
| Mac -> kind | separate admin kubeconfig under `var/kube`; read-only inventory RBAC; scoped OTel token |
| Browser -> console | signed HttpOnly `SameSite=Strict` session, CSP nonce, server-side API token |
| Backend -> AI providers | flags, daily caps, allow-list projection, sanitiser, advisory-only storage |
| Telemetry content -> everything | treated as attacker-controlled everywhere |

## 6. Development conventions and coding standards

* Python 3.12 via `uv` (`uv run ...`); ruff (`uv run ruff check`,
  `uv run ruff format`) and mypy (`uv run mypy`). Type every function.
* Structured JSON logging through `extorq.common.logging`; never log tokens,
  passwords, API keys, Authorization headers, prompt bodies or raw secrets.
* Every network call has a timeout and bounded retries with jittered backoff.
* Subprocesses: argument lists, never `shell=True`; validate every argument.
* SQL: ClickHouse server-side parameters (`{name:Type}`), SQLite `?`
  placeholders; never f-string or concatenate values. DDL that cannot be
  parameterised uses allow-listed identifiers and validated values and carries
  `# extorq: sql-reviewed <reason>` on the call line.
* YAML with safe loaders only; no `eval`/`exec`/`pickle` on input; TLS
  verification is never disabled.
* Frontend: render telemetry as text (`UntrustedText`); no
  `dangerouslySetInnerHTML` (banned by ESLint), no secrets in `NEXT_PUBLIC_*`,
  API calls only from server code.
* Unknown values stay `None`/`NULL`; never guess versions, owners or causes.
* Tests sit under `tests/<area>/`; pytest markers `integration`, `lab`,
  `live_ai`, `failure` are excluded by default. Never claim a test passed
  without running it; record exact commands and results in your status file.
* Throwaway containers are named `extorq-<agent>-<purpose>` and removed after use.

## 7. How to extend ExtorQ

### 7.1 Add a collector
1. Implement `extorq_collectors.sdk.Collector` (`collector_type`,
   `source_types`, `collect(ctx)`; optional `setup`/`close`). Read checkpoints
   from `ctx`, build contract records, and call
   `ctx.emit(records, checkpoints)`, which commits records, checkpoints and
   snapshots in one transaction (`collectors/src/extorq_collectors/sdk/base.py`).
   Use `ctx.diff_snapshot()` for inventories. Raise on failure; the runner
   reports it in `CollectorHealth`.
2. Use only catalog event types and source types; set unknown fields to `None`;
   emit `extorq.collector.gap_detected` when the source lost data.
3. Add `config/collectors/<name>.yaml` (`collector_id`, `producer_id`,
   `asset_id`, `module: package.module:ClassName`, `interval_seconds`,
   `settings`). Never put secrets in it (the loader rejects secret-looking
   values); tokens come from `var/secrets/tokens/<producer_id>.token`.
4. Ask A (interface-changes) for a producer entry: allowed kinds, source types
   and asset patterns (`scripts/bootstrap.py` `PRODUCERS`).
5. Write parser tests from real, scrubbed fixtures; label synthetic fixtures.
6. Run it: `uv run extorq-collect run --only <collector_id> --once`, then
   `uv run extorq-collect status`.
7. Document the source in `docs/telemetry/<platform>.md` and the index
   `docs/telemetry-sources.md`.

### 7.2 Add a service adapter
The shared interface is `collectors/src/extorq_collectors/services/`
(design: [architecture section 5](docs/architecture.md#5-service-model-schema-11),
[ADR 0010](docs/adr/0010-service-model-and-adapter-registry.md)).

1. Discovery produces `ServiceCandidate` objects with at least one
   `DiscoveryEvidence`. Never assume a process is a network service
   (`is_network_service=None` unless a listener is observed), and attribute a
   port only with `PortAttribution`: `confirmed` needs an observed socket owner,
   `inferred` comes from configuration or a well-known port, otherwise
   `unknown`.
2. Subclass `ServiceAdapter` in the platform package (for example
   `extorq_collectors/linux/adapters/`) and decorate it with `@register`.
   Declare `adapter_id`, `support = AdapterSupport.IMPLEMENTED`, `category`,
   matching evidence (`products`, `unit_patterns`, `executables`;
   `well_known_ports` never identify a product), `source_types`,
   `description`, `collects` and `never_collects`.
3. Implement `accepts(raw)` and `parse(raw, ctx)`; return `SecurityEvent`s that
   carry `ctx.service` (a `ServiceRef`) only when the record is genuinely
   attributable to that service. Verify the sender where the source allows it
   (journald `_SYSTEMD_UNIT`, `_EXE`, UID).
4. Keep every `never_collects` promise: strip query strings, never keep
   Authorization headers, cookies, bodies, credentials, file contents or query
   text; truncate and sanitise all strings.
5. Use `classify_coverage()` for `adapter_support`/`monitoring_status`; report
   `monitored` only when the adapter's source for that service is enabled and
   fresh. Unsupported and unmonitored services stay visible with their
   `coverage_note`.
6. New event types or source types need a catalog change through the lead.
7. Add parser tests (positive, negative, hostile input) and run
   `uv run pytest tests/security/test_security_service_adapters.py -q`.
8. Update `docs/architecture.md` section 5.5 (adapter table) and the platform
   telemetry doc.

Implemented versus planned: an adapter is **implemented** only when it parses
real telemetry and has tests. **Planned** adapters (`services/planned.py`: FTP
vsftpd/ProFTPD/Pure-FTPd, PostgreSQL, MySQL/MariaDB, DNS, Redis) recognise a
service so it is shown as "planned adapter: unmonitored", accept nothing and
emit nothing. To implement one, subclass it with `support = IMPLEMENTED`,
register it (an implemented registration replaces the planned one with the same
id) and follow the steps above.

### 7.3 Add a detection rule
1. Create `rules/<platform>/<ID>.yaml` (metadata: `rule_id`, `version`,
   `title`, `severity`, `requires` source and event types, `schedule`, `dedup`,
   `group_by`, `params`, `false_positives`, `blind_spots`, `query`,
   `summary_template`, `tests`) and `<ID>.sql` (one `SELECT`/`WITH` over
   allow-listed tables, window bounds `{window_start:DateTime64(3, 'UTC')}` /
   `{window_end:DateTime64(3, 'UTC')}`, declared parameters only).
2. Add positive and negative JSONL fixtures under `rules/<platform>/tests/<ID>/`.
3. Validate and test: `uv run extorq rules validate` and
   `uv run extorq rules test` (ephemeral ClickHouse, needs Docker).
4. Document false positives and blind spots honestly; never filter out
   simulation telemetry.

### 7.4 Add a scanner
Follow `scanners/src/extorq_scanners/` (C3): run the tool in a pinned image by
digest via `docker.py`, normalise its JSON in `normalize/<tool>.py` into
`PostureFinding`s tied to a `ScanRun` with a `scope_hash`, sanitise and redact
all text (Gitleaks output is redacted), and never resolve findings from a
failed or partial scan. Configure targets in `config/scanners.yaml`.

### 7.5 Add a console view
Inside `frontend/` (D2): add a route under `src/app/(console)/`, call
`requireSession()` first, fetch through the server-only client in
`src/lib/server/api.ts`, validate responses with the zod schemas in
`src/lib/api/schemas.ts`, render telemetry with `UntrustedText`, and show
loading, empty, error, stale and unmonitored states explicitly. Never fetch the
API from client components.

## 8. Running and testing

The `Makefile` is the entry point (`make help`); each target wraps a command
that can also be run directly:

| Task | Make target | Direct command |
|---|---|---|
| Secrets, CA, producer registry | `make bootstrap` | `python3 scripts/bootstrap.py && uv sync` |
| Core / full stack | `make up` / `make up-full` | `docker compose up -d` / `docker compose --profile full up -d` |
| Debug ClickHouse proxy (never in demos) | `make up-debug` | `docker compose --profile debug up -d clickhouse-debug` |
| Ubuntu VM | `make vm-up` / `vm-status` / `vm-down` | `infra/vm/vm.sh up` / `status` / `down` |
| kind cluster | `make kind-up` / `kind-status` / `kind-down` | `infra/kind/kind.sh up` / `status` / `down` |
| Collectors | `make collectors`, `collectors-once`, `collectors-status`, `collectors-flush` | `uv run extorq-collect run [--only ids] [--once]` |
| Scanners | `make scan` | `uv run extorq-scan run all` |
| Simulations | `make sim-<scenario>`, `make sim-cleanup SCENARIO=... RUN_ID=...` | `simulations/**.sh` |
| Rules | | `uv run extorq rules validate`, `uv run extorq rules test` |
| Unit tests | `make test` | `uv run pytest -q` (excludes integration/lab/live_ai/failure) |
| Security tests | `make test-security` | `uv run pytest tests/security -q` |
| Live RBAC probe | | `uv run pytest tests/security/test_security_clickhouse_rbac_live.py -m integration -q` |
| Lint and types | `make lint`, `make typecheck` | `uv run ruff check`, `uv run mypy` |
| Demo readiness | `make demo-check` (script being added by A) | `uv run python scripts/demo_check.py` |

CI (`.github/workflows/ci.yml`) runs lint, type checks, unit and security
tests, the frontend build, gitleaks and Trivy on every push and pull request.

Details: [`docs/deployment.md`](docs/deployment.md),
[`docs/operations.md`](docs/operations.md), [`docs/testing.md`](docs/testing.md).

## 9. Debugging common failures

| Symptom | Check |
|---|---|
| Collector reports `buffered` / exit 75 | gateway reachable? `curl --cacert var/tls/ca.crt https://127.0.0.1:8443/healthz`; `uv run extorq-collect status`; records stay in the outbox until acknowledged |
| Gateway `401` | token file `var/secrets/tokens/<producer_id>.token` matches `producers.json` (re-run bootstrap; never print the token) |
| Gateway `403` | record kind, source type or asset not allowed for that producer; see `extorq.ingest_audit` |
| Records missing but `202` returned | quarantined: query `extorq.ingest_quarantine` (reason, redacted excerpt); writer dead letters in its health |
| Nothing reaches ClickHouse | `docker compose ps` (writer healthy?), `GET /v1/status` with a token for spool depth |
| Linux collector fails | `infra/vm/vm.sh status`; host-key and authentication errors are never retried; exit 77 means the dispatcher denied the command |
| Kubernetes telemetry missing | `infra/kind/kind.sh status` and `netcheck` (pods to gateway over TLS) |
| Rule produces nothing | `extorq.rule_runs` (status, `missing_sources`, sanitised error); `uv run extorq rules test --only <ID>` |
| AI output missing | providers are off unless `EXTORQ_JEV_ENABLED` / `EXTORQ_GEMINI_ENABLED` and a key are set; daily caps; detection never waits for AI |
| Service shown unmonitored | read its `coverage_note`: no adapter, planned adapter, disabled, failing source, no or stale telemetry |

## 10. Actions requiring explicit human authorisation

Pushing to any remote; creating or modifying GitHub repositories or settings;
deleting volumes or databases with collected data (`docker compose down -v`);
running `docker compose down` or restarting shared services you do not own;
touching clusters or VMs not created by ExtorQ (for example `motorq-security`);
disabling security controls; raising AI usage limits or making live AI calls
outside a granted budget; sending data to any new third-party service; reading
or printing `.env` or anything under `var/secrets`.

## 11. Keeping docs and architecture in sync

Any change to a contract, table, port, privilege, rule, adapter or trust
boundary updates the matching document in the same change:
`docs/architecture.md`, `docs/threat-model.md`, `docs/security.md`,
`docs/telemetry-sources.md` and `docs/telemetry/*.md`,
`docs/known-limitations.md`, `docs/detection-catalog.md` (C2) and the ADRs in
`docs/adr/`. Status of the build: `docs/team/status/<agent>.md`.
