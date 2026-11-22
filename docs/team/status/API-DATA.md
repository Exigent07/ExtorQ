# API-DATA status (acting for D1 API and A platform)

Last updated: 2026-11-22 07:33 UTC (M0-M5 done; compose api runs this code)

Owns for this task: `backend/src/extorq/api/**`, `tests/unit/api/**`, `tests/integration/api/**`,
`docs/api/**`, new `infra/clickhouse/migrations/0007_api_quota.sql`; may rebuild/recreate the
compose `api` service (announced in `docs/team/status/D1.md`). Does not touch `frontend/`.

## Plan
- [x] M0 read AGENTS.md, frontend/AGENTS.md, PLAN.md, D1/UI-1/UI-2 status; baseline
      `uv run pytest tests/unit/api -q` = 221 passed; live data inspected (read-only, paced)
- [x] M1 asset lifecycle (`lifecycle_state` active/stale/retired), retired assets excluded from
      coverage, KPIs and degraded rollups by default (`include_retired=true` shows them):
      `backend/src/extorq/api/lifecycle.py` (pure rules), routes assets/overview/health,
      unit tests `tests/unit/api/test_api_lifecycle.py` (16)
- [x] M2 short-TTL in-process cache for aggregate endpoints + fewer queries per page:
      `backend/src/extorq/api/cache.py`, routes overview/health/assets/asset detail/asset
      services/services/service detail/rules (list+detail); invalidated by analyst mutations;
      `GET /assets` 5 -> 4 queries (no separate count); `/health` answers 429 (not "storage
      unreachable") when the quota is exhausted; unit tests `test_api_cache.py` (20)
- [x] M3 migration `0007_api_quota.sql` (extorq_api_ro quota 6000 queries / 60 s), `make migrate`
      (applied 06:55:02 UTC, done before any API code change so the rebuilt shared image
      carried only the new migration file; regression test on a throwaway ClickHouse: M4)
- [x] M4 OpenAPI regenerated (additive only), `docs/api/README.md` (lifecycle, cache, quota),
      `docs/data-model.md` migrations table (0007), handoff to UI-4 below
- [x] M5 compose `api` rebuilt + recreated (07:14:51, again 07:24:37 for the `hosted`
      follow-up); /api/v1/health + investigation contexts of all five mandatory rules verified;
      two paced smoke runs without any 429/503

## For UI-4 (and UI-2): API fields (all additive; `docs/api/openapi.json` regenerated)
Run `pnpm gen:api` to pick them up; nothing was removed or retyped, so the contract check keeps
passing without it. Live on the compose API (127.0.0.1:8000) since 2026-11-22 07:14 UTC.
- `AssetListItem` / `AssetRecord`: `lifecycle_state` (`active` | `stale` | `retired`),
  `last_observed_at` (newer of `last_seen` and the newest event; ISO UTC or null),
  `lifecycle_reason` (API-derived text for stale/retired, null when active; plain text).
- `GET /assets?include_retired=true` (default false: retired assets are LEFT OUT);
  `AssetListResponse.retired_excluded` = how many the default left out (say so in the UI).
  `GET /assets/{id}` answers for retired assets too.
- `GET /overview?include_retired=true`; `AssetClassCoverage.assets_retired` (retired assets of
  the class, excluded from every other count and from `status` by default);
  `CollectionHealthSummary.collectors_retired`; new required `OverviewResponse.lifecycle` =
  `{stale_after_seconds, retire_after_seconds, active, stale, retired, retired_asset_ids,
  include_retired}`. Open alerts are NEVER filtered by lifecycle.
- `GET /health?include_retired=true`; `HealthResponse.collectors_retired` + a note when retired
  collectors are not listed; every `CollectorStatus` has `lifecycle_state` and `self_test`
  (SDK heartbeat: never counted as asset coverage; the asset detail no longer lists it).
- Caching: overview/health/assets/asset detail/asset services/services/service detail/rules are
  served from a 15 s in-process cache (`X-ExtorQ-Cache: hit|miss|off`, `X-ExtorQ-Cache-Age`);
  `generated_at` is the computation time. Analyst state changes and AI summaries clear it.
- What the console will see live: the macOS tile no longer counts the stopped
  `sdk-heartbeat-example` (macOS `ok`, collectors 1/1). The mechanics-test GitHub assets
  (`github:octocat/hello-world`, `github:octocat`, `github:actions`,
  `github:actions/hello-world-javascript-action`) are `stale` now and become `retired` at
  2026-11-22 15:01:41 UTC (24 h after their collector's last report); from then on the GitHub
  repository tile shows 1/1 `ok` with `assets_retired: 2` (both test repositories), the
  accounts class 1 asset (`github:exigent07`, no collector of its own) with `assets_retired: 2`,
  and collection health 11/11 with `collectors_retired: 2` (mechanics test + heartbeat).
  Until then they still count (honest transitional state). Suggested UI: a muted "Retired"
  badge + "N retired hidden" line with a link/toggle to `include_retired=true`; a "Stale"
  badge from `lifecycle_state` (reason in a tooltip, it is API text, not telemetry).

## Live observations (M0, read-only queries as extorq_api_ro via the debug proxy)
- Assets not configured for collection: `github:octocat/hello-world`, `github:octocat`,
  `github:actions`, `github:actions/hello-world-javascript-action` (C1's mechanics test,
  last seen 2026-11-21 14:47 UTC). Their only collector `github-mechanics-test` last reported
  2026-11-21 15:01:41 UTC and is in no `config/collectors/*.yaml`.
- `sdk-heartbeat-example` (SDK self-test, A-IC-1: "treat as self-test") on
  `macos:workstation-01` last reported 2026-11-21 15:09 UTC; it is what makes the macOS tile
  "Degraded: 1 of 2 collectors stale".
- No alert and no service belongs to those assets; 4 open findings do.

## Verified
| Claim | Command | Result |
|---|---|---|
| `ALTER QUOTA ... FOR INTERVAL` replaces EVERY limit of the interval (a partial ALTER would have removed the errors/result/read/execution-time limits) | throwaway `extorq-apidata-quota-probe` (clickhouse-server 26.8.42.13): CREATE QUOTA as in 0002, `ALTER QUOTA ... MAX queries = 6000` only, read `system.quota_limits` | partial ALTER: errors/result_rows/read_rows/execution_time became NULL (unlimited); full ALTER twice: 6000/300/50000000/5000000000/600, KEYED BY user_name and TO extorq_api_ro kept; IF EXISTS on a missing quota is a no-op; container removed |
| 0007 applied live | `make migrate` (06:54:56-06:55:02 UTC) | `migration_applied 0007_api_quota`, already applied 0001-0006, exit 0; no service recreated |
| Live quota after 0007 | `SELECT ... FROM system.quota_usage` as extorq_api_ro (debug proxy) | max_queries 6000, max_errors 300, max_result_rows 50000000, max_read_rows 5000000000, max_execution_time 600 |
| API unit tests (36 new: lifecycle 16, cache 20) | `uv run pytest tests/unit/api -q` | 257 passed (baseline 221) |
| New SQL + endpoints + 0007 on a throwaway ClickHouse 26.8 (own container `extorq-d1-apisql-*`, removed) | `uv run pytest tests/integration/api/test_api_lifecycle_clickhouse.py -m integration -q` | 5 passed (asset_last_events asset_type, finding exclusion, retired repo left out of list/overview/health, retired detail 200, cache hit, 0007 1200->6000 with other limits unchanged and idempotent) |
| Existing SQL + Grafana SQL unchanged | `uv run pytest tests/integration/api/test_api_sql_clickhouse.py tests/integration/api/test_grafana_sql_clickhouse.py -m integration -q` | 77 passed |
| Lint/format/types | `uv run ruff check` + `ruff format --check` (api, tests/unit/api, tests/integration/api); `uv run mypy backend/src/extorq/api` + new test files | clean; no issues |
| New code in-process vs the LIVE store (paced 1 s, viewer, read-only), default 24 h window | scratch probe (`create_app` + `ClickHouseRepository`, random token file) | macOS class `ok` (heartbeat no longer coverage); mechanics-test assets `stale` (16 h, retire at 15:01:41 UTC); collection 13 total / 2 stale / 0 retired; second overview `X-ExtorQ-Cache: hit` |
| Same with `asset_retire_seconds=43200` (what the 24 h default gives after 15:01:41 UTC) | same probe | 4 retired (`github:actions`, `github:actions/hello-world-javascript-action`, `github:octocat`, `github:octocat/hello-world`); GitHub repository class `ok` 1/1 + `assets_retired` 2; accounts class 1 + 2 retired; collectors 11/11 ok, 2 retired (mechanics, heartbeat) + health note; findings KPI 3611 (4 of retired repos left out); open alerts 14 (unchanged) |
| Query fan-out of a console-like sequence (12 page loads: shell asset list + overview, 2 asset pages with services, rules, health, overview, twice) | scratch `fanout.py` in-process vs the live store, query-counting client | 191 ClickHouse queries with the cache off (~16 per page), 65 with the 15 s cache (~5.4 per page) |
| Whole default suite | `uv run pytest -q` | 1982 passed, 5 skipped, 1 failed: `tests/security/test_security_secret_scan.py::test_no_secrets_in_git_history` flags `tests/unit/ai/test_ai_sanitize.py:75` in COMMIT e243768 (git history, E's file; unrelated to this work, nothing committed here). A first run also saw a transient failure of `test_security_frontend_static.py` while UI agents were editing `frontend/`; it passed (26/26) on rerun |
| Repo-wide lint/format/types | `uv run ruff check` + `ruff format --check` over backend/src collectors/src scanners/src tests scripts eval; `uv run mypy` | all checks passed; 327 files formatted; no issues in 197 source files |
| Live API tests incl. new lifecycle consistency test | `uv run pytest tests/integration/api/test_api_live.py -m integration -q` (paced 0.8 s) | 7 passed (114 s) |
| Compose `api` runs the current tree | `docker compose --profile full build api` + `up -d --no-deps api`; sha256 of every `.py` in the container vs `backend/src/extorq` | identical (97 files incl. `api/cache.py`, `api/lifecycle.py` and 16 `ai/` modules); healthy; startup log `cache_ttl_seconds 15.0`, `asset_retire_seconds 86400` |
| `/api/v1/health` and investigation contexts on the compose API | scratch `compose_check.py` (token read from `var/secrets/api_service_token` by path, never printed; viewer; paced 1 s) | health 200, storage reachable; VM-001, VM-002, K8S-001, K8S-002, GH-001: alert detail 200, context 200 `stored` (107/253/150/198/8 timeline entries), assessments 200 via `ai.store` |
| No 429/503 during paced smoke runs | `node scripts/smoke.mjs --base http://127.0.0.1:3000` (pace 1500 ms; compose console -> compose api) at 07:16:27-07:17:57 and 07:25:23-07:26:53, quota polled every 5 s (`system.quota_usage`), api logs scanned | 102 passed / 3 failed both times; the 3 failures are new-UI markers missing from YESTERDAY's console image on 3000 (overview tiles, shell groups, "Show all" walls; UI agents' work), not API errors; no page showed an API error state (the only one is the expected refusal of an invalid alert id); no `storage_quota_exceeded`/`storage_error`/`unhandled_error` in the api log; peak 296 then 222 queries per minute of 6000, 0 errors |
| New console (UI agents' `pnpm dev` on 3100 -> compose api) works with the new API | `node scripts/smoke.mjs --base http://127.0.0.1:3100` (paced 1500 ms) 07:28:11-07:29:43 | 103 passed, 2 failed: both "CSP allows unsafe-eval", inherent to `next dev` (not a production build); every page/data check passed, no API error state; api log: 0 warnings/errors since the 07:24:37 recreate; quota 306/6000 in that minute, 0 errors |
| Final code: throwaway-ClickHouse suites | `uv run pytest tests/integration/api/test_api_sql_clickhouse.py tests/integration/api/test_grafana_sql_clickhouse.py tests/integration/api/test_api_lifecycle_clickhouse.py -m integration -q` | 82 passed; no container left |
| Final code: live API tests | `uv run pytest tests/integration/api/test_api_live.py -m integration -q` | 7 passed (114.6 s) |
| `hosted` follow-up | `uv run pytest tests/unit/api -q` (new `test_hosted_is_not_queried_for_assets_without_ancestors`) | 258 passed |
| OpenAPI additive only | `uv run python -m extorq.api.openapi_export docs/api/openapi.json`; diff | +193/-4 lines; the 4 removed lines are 2 summaries, the description and a re-ordered `required` entry (`service_coverage` still required) |

## Not verified
- The retired state on the compose API with the default 24 h window: the mechanics-test assets
  cross it at 2026-11-22 15:01:41 UTC (after this session). Verified the same code path live
  in-process with a 12 h window (table above) and on a throwaway ClickHouse.
- Analyst mutations (state change, AI summary) clearing the cache on the LIVE stack: not
  exercised (shared demo data, paid AI); unit-tested (`test_api_cache.py`).
- A production build of the new console against the new API: UI agents own it; their dev
  server passed every data check of the smoke test.
- Grafana (infra/grafana, outside this task's ownership) still shows the stopped
  `github-mechanics-test` and `sdk-heartbeat-example` collectors as STALE in its collector
  panels (it reads ClickHouse directly, not the API).

## Blockers
- None.
