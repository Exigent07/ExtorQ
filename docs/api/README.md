# ExtorQ Analyst API

Read API over ExtorQ's ClickHouse store plus one audited analyst mutation (the workflow state
of an alert). Package `backend/src/extorq/api` (owner: D1). Machine-readable contract:
[`openapi.json`](openapi.json) (generated from the code; the console's TypeScript types are
generated from it). Contract schema **2.0**: there is no simulation category (no simulation
fields, filters or tags; detection tests are real activity verified by asset, rule and time
window) and Jev is the only AI provider (the on-demand Gemini summary endpoint was removed).
The API never calls an AI provider: it only reads the advisory Jev assessments the ai-worker
stores.

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
When the `extorq_api_ro` ClickHouse quota (6000 queries per minute since migration 0007;
1200 in 0002) is exhausted the API answers **429** with `Retry-After: 30` instead (also
`GET /health`, which no longer reports "storage unreachable" for a quota error): it is load,
not an outage, and clients must not retry at once (the console retries only 502/503/504).
Each request reads collector health once (one evaluator per request) and aggregate responses
are cached briefly (see [Response cache](#response-cache)) to keep the query count low.
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
| `GET /overview` | Asset coverage per asset class (incl. stale/missing, `assets_retired`), open alerts by severity, open findings (lifecycle view or explicit `lifecycle_available=false` fallback), alerts over 24 h, collection health summary (`collectors_retired`), recent high/critical alerts, **service coverage**, **`lifecycle`** (thresholds, counts, `retired_asset_ids`) | `include_retired` (default false: retired assets left out of every rollup except open alerts) |
| `GET /assets` | Assets with collector coverage (own + ancestor collectors, `collectors_inherited`; self-tests never count), last event, open alerts, **`lifecycle_state`**, `last_observed_at`, `lifecycle_reason`; `retired_excluded` counts what the default left out | `asset_type`, `environment`, `include_retired` |
| `GET /assets/{asset_id}` | Asset record (with lifecycle; also for retired assets), telemetry collectors covering it (staleness and `lifecycle_state`; a node lists its cluster's collectors, each with its own `asset_id`; self-tests are not listed), inventory summary, event counts per source type, findings, recent alerts, **`services_summary`**, **`child_assets`** (e.g. Kubernetes nodes of a cluster) | `since`/`until` for event counts (default 24 h, max 90 d) |
| `GET /assets/{asset_id}/services` | Services of one asset + coverage summary; **`hosted`**: services of an ancestor asset with instances on this asset (a node's Pods/containers grouped by cluster workload; not counted in `summary`) | `kind`, `category`, `adapter_support`, `monitoring_status`, `coverage`, `include_removed` (filters apply to `items`) |
| `GET /services` | Service inventory across assets | `asset_id` + the filters above |
| `GET /services/{service_id}` | Service detail: endpoints (exposure + attribution), instances, telemetry per source, authentication activity, recent events, findings, alerts | `since`/`until` (default 24 h, max 31 d) |
| `GET /findings` | Posture findings | `asset_id`, `severity`, `scanner`, `category`, `state` (lifecycle only, else 400), `service_id` |
| `GET /rules`, `GET /rules/{rule_id}` | Rules with latest run, staleness, alert counts; detail with versions and recent runs | `severity`, `status`, `enabled`; `runs_limit`, `run_status` |
| `GET /alerts` | Alerts with analyst state | `asset_id`, `rule_id`, `severity`, `status`, `open_only`, `service_id`, `sort`; default 30 d, max 400 d |
| `GET /alerts/{alert_id}` | Alert, analyst state, rule brief for the alert's exact rule version if available, asset, evidence resolved through `alert_evidence` (trigger first), analyst actions | Evidence is capped at 500 (`evidence_capped`). `unresolved_evidence_ids` lists missing event references. `expired_evidence_ids` identifies the subset whose known event time is outside retention. |
| `GET /alerts/{alert_id}/context` | Latest InvestigationContext (C2); built on demand when missing **or unreadable** (a stored context that no longer validates, for example one written before the schema 2.0 reset, is logged and rebuilt, never shown). Only analysts persist an on-demand build (audited); viewers get an ephemeral build | 503 with a clear message when correlation is not installed; 500 `stored investigation context failed its integrity check` when a stored body does not match its input hash (never rebuilt over) |
| `GET /alerts/{alert_id}/assessments` | Advisory Jev triage assessments (written by the ai-worker), newest first, via the AI module's store or a direct `ai_assessments` query | rows that fail contract 2.0 validation (for example of a removed provider) are counted in `invalid_records`, never shown |
| `POST /alerts/{alert_id}/state` | Analyst workflow state (analyst only) | body `{status, assignee?, note?, expected_updated_at?}`; 409 on concurrent change |
| `GET /events` | Bounded event search (default 24 h, max 31 d) | `asset_id`, `event_type`, `event_type_prefix`, `source_type`, `category`, `outcome`, `actor`, `src_ip`, `service_id` |
| `GET /events/{event_id}` | Stored SecurityEvent (contract schema 2.0), ingest metadata, alerts citing it | a stored payload that fails 2.0 validation (an event written before the schema 2.0 reset) is a 500 `stored event failed contract validation`, never a guessed event |
| `GET /health` | Collectors (stale = now - last_success_at > 3 x interval, or never succeeded; `lifecycle_state`, `self_test`), pipeline (`v_pipeline_latest`), rule health, Jev triage health (recent `ai_assessments` statuses; **`runtime_status`** / `runtime_reported_at` = the ai-worker's own state from its newest fresh `pipeline_health` report, `disabled` when Jev is off or has no key there, `null` when it is not reporting; `configured` / `enabled` = the API process's view, presence only, never the key; another provider is listed only if stored rows name it), ingestion boundary (quarantine, audit decisions); `collectors_retired` + a note when retired collectors are not listed | `include_retired` (default false) |
| `GET /timeseries/alerts`, `GET /timeseries/events` | Distinct alerts/events per bucket (sparse: missing buckets mean "no stored rows") | `bucket_seconds` (60..86400), `group_by`, filters |

**Mutations are audited first.** `POST /alerts/{id}/state` (and the persistence of an
investigation context an analyst built on demand) writes an `analyst_actions` row (actor,
role, action, details) *before* acting; if the audit write fails nothing changes (503). A
failed state write is itself audited. Audited actions: `alert_state_changed`,
`alert_state_change_failed`, `context_built`.

**Asset ids in paths** contain `:` and often `/` (`github:owner/repo`,
`k8s:<cluster>/node/<name>`). Send them percent-encoded as one segment:
`/api/v1/assets/github%3Aowner%2Frepo` and `/api/v1/assets/github%3Aowner%2Frepo/services`.
The services sub-route matches only a *literal* `/services` suffix in the raw path, so an
asset whose id ends in `/services` is never confused with the sub-resource.

## Service coverage

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
ancestor asset (`k8s:<cluster>` covers `k8s:<cluster>/node/<name>`). The same ancestor rule
gives an asset's own coverage (`coverage_status`, `collectors_total`, overview classes): a
Kubernetes node is covered by its cluster's collectors (`collectors_inherited` says how many
report for an ancestor) instead of being reported "missing".

**Ownership (F-19).** Service ids can be computed by anyone, so the API never lets rows of
another asset appear under a service:

* A service row counts only when its stored `service_id` equals the identity computed from
  its natural key (`service_id(asset_id, kind, key)`); a mismatching row is never shown (the
  detail answers with the newest genuine row or 404; listings count it in `invalid_records`).
  The gateway quarantines such rows since session 2; the API re-checks.
* `GET /services/{id}` (instances, telemetry per source, authentication activity, recent
  events) and `GET /events?service_id=` only include rows whose `asset_id` is the service's
  own asset or a descendant of it (a cluster's nodes). An event or instance from another
  asset that names the service is left out.
* `hosted` (on `GET /assets/{id}/services`) lists an instance only under a service whose asset
  is a strict ancestor of the requested asset and whose identity matches.

Alerts are written by the detector only and are not filtered this way; findings follow
`v_findings_current.service_id`. A source with no
collector health at all is shown as `collection: "no_collector_health"` in the service
detail but does not invent staleness. Unsupported, planned and unmonitored services are
always listed; `include_removed=true` adds tombstoned services.

Every view that reports service coverage (`GET /assets/{id}` `services_summary`,
`GET /assets/{id}/services`, `GET /services`, `GET /services/{id}`, `GET /overview`
`service_coverage`) evaluates it with the same function against **all** collector health
reports, so a service (for example on a Kubernetes node, covered by the cluster's
collectors) has the same `coverage_state` in every view at the same instant.
Kubernetes workloads with a configured log adapter use node-scoped OTel health for
the nodes hosting their running Pods. Every known hosting node must report fresh
delivery for the required log source for effective coverage to be monitored.

Per-service views only contain what the adapters attributed (`events.service_id`,
`v_findings_current.service_id`, `alerts.service_ids`): an empty list means "nothing
attributed", not "nothing happened". A finding's `service_id` is the attribution of its
**latest** observation (`v_findings_current.service_id`, C3 migration 0005): a later scan
that re-attributes the finding wins, and a later scan without attribution evidence clears
an older link (it is never carried forward). `GET /findings` (items and the `service_id`
filter), `GET /assets/{id}` and `GET /services/{id}` all apply this one rule; without the
lifecycle view the observation fallback reproduces it.

## Asset and collector lifecycle

`GET /health` exposes OTel delivery in `collectors[].details.delivery_state`
with node and source attribution. An OTel report expires after three missed
scrape intervals. `last_success_at` is the latest corroborated native timestamp
and `lag_seconds` is its age when acknowledged by the gateway. Queue fields
`queue_requests` and `queue_capacity_requests` use requests as their unit.
See [Kubernetes delivery health](../telemetry/kubernetes.md#31-delivery-health).

Every asset carries `lifecycle_state` (`active` | `stale` | `retired`), `last_observed_at`
(the newer of the asset record's `last_seen` and its newest event) and `lifecycle_reason`
(API-derived text for `stale`/`retired`). It is evaluated at request time by one function
(`extorq.api.lifecycle.Estate`) for every view, so an asset has the same state everywhere.

* A collector is **reporting** while its latest health report is no older than the
  retirement window (`EXTORQ_API_ASSET_RETIRE_SECONDS`, default 86400 s) or 3 x its interval
  when that is longer (a daily scanner stays configured for 72 h). The collector runner
  reports health every cycle for every enabled collector, failed cycles included; a collector
  removed from or disabled in `config/collectors` (or a one-off test run) stops reporting.
  The API cannot read the host's collector configuration (it runs in a container without
  it), so "no reporting collector" is the observable form of "no enabled collector
  configured".
* **Self-tests** (collector type `heartbeat`, or only `extorq.*` pipeline sources: the SDK
  heartbeat `sdk-heartbeat-example`, A-IC-1) collect no telemetry of their asset. They never
  count toward an asset's coverage (`collectors_total`, `coverage_status`, the asset
  detail's `collectors`) and never keep an asset configured; `CollectorStatus.self_test`
  marks them in `GET /health`.
* An asset is **retired** when no telemetry collector covering it (its own or an ancestor's)
  is reporting **and** it was not observed within the retirement window. Example: C1's
  mechanics-test repositories (`github:octocat/hello-world`, `github:actions/...`) and their
  owner accounts, last seen 2026-11-21 14:47 UTC, whose one-off collector
  `github-mechanics-test` last reported 15:01:41 UTC: retired from 2026-11-22 15:01:41 UTC.
* Otherwise an asset is **stale** when not observed for longer than
  `EXTORQ_API_ASSET_STALE_SECONDS` (default 3600 s) or 3 x the shortest interval of its
  reporting collectors when that is longer; else **active**. A Kubernetes node is covered by
  its cluster's collector, so it can become stale but never retired while that reports.
* A collector is **retired** when it reports for a retired asset or is a self-test that
  stopped reporting; otherwise `stale` (its `stale` flag) or `active`.

Nothing is deleted. By default the asset list, the overview's asset coverage, findings KPI,
collection health and service coverage, and the health collector list leave retired assets
and collectors out, and say how many they left out (`retired_excluded`, `assets_retired`,
`collectors_retired`, `lifecycle.retired_asset_ids`, a health note). `include_retired=true`
includes them again; `GET /assets/{id}` always answers for a retired asset. **Open alerts are
never filtered by lifecycle**: silencing an asset's collectors must not hide its detections.

Limitations: a collector that disappears from configuration while another collector still
reports for the same asset stays `stale` (not retired) until its health rows expire (30-day
TTL); a node removed from a cluster stays `stale` while the cluster collector reports.

## Response cache

Aggregate GET responses are computed once and reused for `EXTORQ_API_CACHE_TTL_SECONDS`
(default 15 s, 0 disables): `GET /overview`, `GET /health`, `GET /assets`,
`GET /assets/{id}`, `GET /assets/{id}/services`, `GET /services`, `GET /services/{id}`,
`GET /rules`, `GET /rules/{id}`. Keys are the route plus its validated parameters (the
responses do not depend on the caller's role; authentication still runs on every request).
Concurrent misses of one key compute once; errors are never cached; the cache holds at most
`EXTORQ_API_CACHE_MAX_ENTRIES` responses. A successful `POST /alerts/{id}/state` clears it,
and a computation that started before such a mutation is not stored. Responses say `X-ExtorQ-Cache: hit|miss|off` and, on hits,
`X-ExtorQ-Cache-Age: <seconds>`; `generated_at` (overview, health) is the computation time.
Alert, event, finding, context, assessment and time-series reads are never cached.

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
| `AI_HEALTH_WINDOW_HOURS` | 24 | window of the Jev status counts in `GET /health` |
| `SERVICE_STALE_SECONDS` | 3600 | service/instance record staleness |
| `ASSET_STALE_SECONDS` | 3600 | asset lifecycle `stale` threshold (or 3 x the shortest reporting interval) |
| `ASSET_RETIRE_SECONDS` | 86400 | retirement window (no reporting collector and not observed) |
| `CACHE_TTL_SECONDS` | 15 | aggregate response cache TTL (0 disables) |
| `CACHE_MAX_ENTRIES` | 128 | cached responses kept at most |

ClickHouse connection settings and password files are owned by the platform
(`extorq.storage.clickhouse.get_client`, `EXTORQ_CLICKHOUSE_*`).

## Tests

| Command | What it proves |
|---|---|
| `uv run pytest tests/unit/api -q` | routes, auth/roles, derivations, coverage, lifecycle, response cache, routing, OpenAPI freshness, static SQL safety (fake repository, no infrastructure) |
| `uv run pytest tests/integration/api/test_api_sql_clickhouse.py -m integration -q` | Executes every SQL statement on an isolated ClickHouse 26.8 instance with the current migrations, the real 0002 roles and profiles, and synthetic rows. Removes the container afterwards. |
| `uv run pytest tests/integration/api/test_api_lifecycle_clickhouse.py -m integration -q` | lifecycle SQL inputs and endpoints on real rows (a synthetic repository retired 3 days ago), cache hit on real SQL, and migration 0007 (quota 1200 -> 6000, other limits unchanged, idempotent) on a throwaway ClickHouse |
| `uv run pytest tests/integration/api/test_api_live.py -m integration -q` | read-only checks against the live stack (requires `STACK READY`): every endpoint on real telemetry, consistency with direct SQL |
