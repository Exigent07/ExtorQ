# ExtorQ Analyst API

Read API over ExtorQ's ClickHouse store plus two audited analyst mutations. Package
`backend/src/extorq/api` (owner: D1). Machine-readable contract: [`openapi.json`](openapi.json)
(generated from the code; the console's TypeScript types are generated from it).

* Served by `extorq api` (compose service `api`, `127.0.0.1:8000`, profile `full`).
* Development server: `uv run python -m extorq.api --port 8100` (loopback; port 8000 is
  refused so a dev server never collides with compose).
* Regenerate the contract after any schema change:
  `uv run python -m extorq.api.openapi_export docs/api/openapi.json`
  (`tests/unit/api/test_api_openapi.py` fails while the file is stale).

## Trust model and authentication

The browser never calls this API. The console's Next.js server holds the API service
token and forwards the signed-in user:

| Header | Meaning |
|---|---|
| `Authorization: Bearer <token>` | API service token, compared in constant time (SHA-256 digests + `hmac.compare_digest`) with the file named by `EXTORQ_API_SERVICE_TOKEN_FILE` (default `var/secrets/api_service_token`). Tokens shorter than 32 characters are treated as not configured. |
| `X-ExtorQ-User` | Console user name, `^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$` |
| `X-ExtorQ-Role` | `analyst` (may mutate) or `viewer` (read-only) |

| Situation | Status |
|---|---|
| Token not configured on the server | 503 (fail closed; retried every 5 s, so bootstrap can create it later) |
| Missing/invalid token or user header | 401 |
| Missing/unknown role | 403 |
| Viewer calling a mutation | 403 |

Consequence (documented in the threat model, finding F-12): any holder of the service token
can assert any user and role, so the token lives only in the console container.
`GET /healthz` is the only unauthenticated route (liveness, no detail).

Every response carries `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, a `default-src 'none'` CSP and `X-Request-Id`. Request bodies are
capped (`EXTORQ_API_MAX_BODY_BYTES`, default 64 KiB, enforced while streaming). Error bodies
are `{"detail": ..., "request_id": ...}`; database errors, SQL and stack traces are never
returned (ClickHouse failures become 503 and are logged server-side with the request id).
Validation errors never echo the submitted values.

## Storage identities and SQL

* Reads: `extorq_api_ro` (`readonly=2`, execution-time and result-row caps, quota).
* Writes: `extorq_api_writer`, only `analyst_state`, `analyst_actions` and, when an analyst
  builds a missing investigation context on demand, `investigation_contexts` /
  `context_relationships` (through C2's `correlation.store`). The API never writes alerts.
* Every statement is a static literal in `repository.py`; values travel only as ClickHouse
  server-side parameters (`{name:Type}`); optional filters use
  `(empty({p:String}) OR col = {p:String})`. Queries are duplicate-safe (`FINAL` views,
  `uniqExact`, `argMax`, `LIMIT 1 BY event_id`). `events.raw` is never read; `payload` only
  by `GET /events/{id}`. Enforced by `tests/unit/api/test_api_repository_sql.py`.

## Endpoints (base `/api/v1`)

All list endpoints are bounded (`limit` 1-200, `offset` <= 10000; events up to 500) and
return `page` = `{limit, offset, returned, has_more, next_offset, total}`. Time ranges are
`since` (inclusive) / `until` (exclusive), ISO-8601 **with** a timezone (naive values -> 400).

| Method + path | Purpose | Filters / notes |
|---|---|---|
| `GET /overview` | Asset coverage per asset class (incl. stale/missing), open alerts by severity, open findings (lifecycle view or explicit `lifecycle_available=false` fallback), alerts over 24 h, collection health summary, recent high/critical alerts, **service coverage** | — |
| `GET /assets` | Assets with collector coverage, last event, open alerts | `asset_type`, `environment` |
| `GET /assets/{asset_id}` | Asset record, collectors (staleness), inventory summary, event counts per source type, findings, recent alerts, **`services_summary`**, **`child_assets`** (e.g. Kubernetes nodes of a cluster) | `since`/`until` for event counts (default 24 h, max 90 d) |
| `GET /assets/{asset_id}/services` | Services of one asset + coverage summary | `kind`, `category`, `adapter_support`, `monitoring_status`, `coverage`, `include_removed` |
| `GET /services` | Service inventory across assets | `asset_id` + the filters above |
| `GET /services/{service_id}` | Service detail: endpoints (exposure + attribution), instances, telemetry per source, authentication activity, recent events, findings, alerts | `since`/`until` (default 24 h, max 31 d) |
| `GET /findings` | Posture findings | `asset_id`, `severity`, `scanner`, `category`, `state` (lifecycle only, else 400), `service_id` |
| `GET /rules`, `GET /rules/{rule_id}` | Rules with latest run, staleness, alert counts; detail with versions and recent runs | `severity`, `status`, `enabled`; `runs_limit`, `run_status` |
| `GET /alerts` | Alerts with analyst state | `asset_id`, `rule_id`, `severity`, `status`, `open_only`, `simulation_run_id`, `service_id`, `sort`; default 30 d, max 400 d |
| `GET /alerts/{alert_id}` | Alert, analyst state, rule brief, asset, evidence resolved through `alert_evidence` (trigger first) with **unresolved evidence ids listed explicitly**, analyst actions | evidence capped at 500 (`evidence_capped`) |
| `GET /alerts/{alert_id}/context` | Latest InvestigationContext (C2); built on demand when missing. Only analysts persist an on-demand build (audited); viewers get an ephemeral build | 503 with a clear message when correlation is not installed |
| `GET /alerts/{alert_id}/assessments` | AI assessments (advisory), via E's store or a direct query | invalid stored rows are counted, not shown |
| `POST /alerts/{alert_id}/summary` | Gemini summary via E's `AIService` (analyst only, per-user rate limit, one in flight per alert) | 503 when AI is unavailable or disabled; 409/429 |
| `POST /alerts/{alert_id}/state` | Analyst workflow state (analyst only) | body `{status, assignee?, note?, expected_updated_at?}`; 409 on concurrent change |
| `GET /events` | Bounded event search (default 24 h, max 31 d) | `asset_id`, `event_type`, `event_type_prefix`, `source_type`, `category`, `outcome`, `actor`, `src_ip`, `simulation_run_id`, `service_id` |
| `GET /events/{event_id}` | Stored SecurityEvent (schema 1.0/1.1), ingest metadata, alerts citing it | — |
| `GET /health` | Collectors (stale = now - last_success_at > 3 x interval, or never succeeded), pipeline (`v_pipeline_latest`), rule health, AI provider health (recent `ai_assessments` statuses + configured/enabled flags, presence only), ingestion boundary (quarantine, audit decisions) | — |
| `GET /timeseries/alerts`, `GET /timeseries/events` | Distinct alerts/events per bucket (sparse: missing buckets mean "no stored rows") | `bucket_seconds` (60..86400), `group_by`, filters |

**Mutations are audited first.** `POST /alerts/{id}/state` and `POST /alerts/{id}/summary`
write an `analyst_actions` row (actor, role, action, details) *before* acting; if the audit
write fails nothing changes (503). A failed state write is itself audited.

**Asset ids in paths** contain `:` and often `/` (`github:owner/repo`,
`k8s:<cluster>/node/<name>`). Send them percent-encoded as one segment:
`/api/v1/assets/github%3Aowner%2Frepo` and `/api/v1/assets/github%3Aowner%2Frepo/services`.
The services sub-route matches only a *literal* `/services` suffix in the raw path, so an
asset whose id ends in `/services` is never confused with the sub-resource.

## Service coverage (schema 1.1)

Hierarchy: **Asset -> Service -> ServiceInstance -> telemetry (events), findings, alerts**.
`service_kind` keeps host OS services (`host_service`), applications, Kubernetes workloads
(`k8s_workload`) and logical Kubernetes Services (`k8s_service`) apart; Pods and containers
are instances; Kubernetes nodes are assets (`kubernetes_node`, listed in the cluster's
`child_assets`).

Each service reports `adapter_support` (implemented / planned / none) and the collector's
`monitoring_status` at discovery time. The API derives `coverage_state` **at request time**:

| adapter_support | reported status | coverage_state |
|---|---|---|
| none | any | `unsupported` |
| planned | any | `planned` (extension point, no telemetry) |
| implemented | unmonitored | `unmonitored` (adapter not enabled/configured) |
| implemented | degraded | `degraded` |
| implemented | monitored | `monitored`, **or `degraded`** when the discovery record is older than `EXTORQ_API_SERVICE_STALE_SECONDS` (default 3600) or every collector reporting one of the service's declared telemetry sources is stale |

Nothing is ever upgraded; `coverage_reasons` explains each downgrade or qualification.
Collectors match a service when they report the source type for the service's asset or an
ancestor asset (`k8s:<cluster>` covers `k8s:<cluster>/node/<name>`). A source with no
collector health at all is shown as `collection: "no_collector_health"` in the service
detail but does not invent staleness. Unsupported, planned and unmonitored services are
always listed; `include_removed=true` adds tombstoned services.

Per-service views only contain what the adapters attributed (`events.service_id`,
`finding_observations.service_id`, `alerts.service_ids`): an empty list means "nothing
attributed", not "nothing happened". Finding attribution uses the latest non-null
`service_id` among a finding's observations (works before and after C3's 0005 view change).

## Data honesty rules

* Values come from stored telemetry; unknown values are `null`.
* Empty sources yield empty lists plus explicit flags/notes (`reported=false`,
  `lifecycle_available=false`, `no_collector_reports`, `notes`), never zeros that look
  measured. Time series are sparse.
* Every string from telemetry, rules, AI output or analysts is **untrusted**: clients render
  it as text only (never HTML/Markdown, never into URLs, commands or queries).

## Configuration (`EXTORQ_API_*`)

| Variable | Default | Purpose |
|---|---|---|
| `SERVICE_TOKEN_FILE` | `var/secrets/api_service_token` | service token file (preferred) |
| `ENABLE_DOCS` | `false` | serve `/api/v1/openapi.json` and `/api/v1/docs` |
| `MAX_BODY_BYTES` | 65536 | request body cap |
| `PIPELINE_STALE_SECONDS` | 300 | pipeline report staleness |
| `SUMMARY_REQUESTS_PER_MINUTE` | 6 | per-user AI summary limit |
| `AI_HEALTH_WINDOW_HOURS` | 24 | AI health statistics window |
| `SERVICE_STALE_SECONDS` | 3600 | service/instance record staleness |

ClickHouse connection settings and password files are owned by the platform
(`extorq.storage.clickhouse.get_client`, `EXTORQ_CLICKHOUSE_*`).

## Tests

| Command | What it proves |
|---|---|
| `uv run pytest tests/unit/api -q` | routes, auth/roles, derivations, coverage, routing, OpenAPI freshness, static SQL safety (fake repository, no infrastructure) |
| `uv run pytest tests/integration/api/test_api_sql_clickhouse.py -m integration -q` | every SQL statement on a throwaway ClickHouse 26.8 with the real migrations 0001-0004 and the real 0002 roles/profiles; synthetic rows only; container removed afterwards |
| `uv run pytest tests/integration/api/test_api_live.py -m integration -q` | read-only checks against the live stack (requires `STACK READY`): every endpoint on real telemetry, consistency with direct SQL |
