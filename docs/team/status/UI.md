# Agent UI status (API, console, Grafana; schema 2.0 stage)

Owner paths: `frontend/**`, `backend/src/extorq/api/**`, `infra/grafana/**`, `docs/api/**`,
`tests/unit/api/**`, `tests/integration/api/**`. Stage: schema 2.0 clean-up (user decisions
2026-11-22, PLAN section 12: no simulation category, Jev only, no "lab" labels in the UI).
No commits, no compose rebuilds, no database clearing and no live detection tests in this stage.

## Milestone log (2026-11-22)

- M0 (start): read AGENTS.md, PLAN.md section 12, contracts 2.0 (`023fdb6`), migration 0008.
  Baseline: `uv run pytest tests/unit/api -q -p no:cacheprovider -x` -> fails in
  `api_fakes.py` (`AIProvider.GEMINI` removed in schema 2.0).

- M1 API (22:15 local): simulation fields/filters (`simulation_run_ids`, `simulation_run_id`,
  `scenario_id`, `SIM_RUN_PATTERN`), `POST /alerts/{id}/summary`, `SummaryGate`,
  `summary_requests_per_minute` and Gemini health/configuration removed; Jev configuration from
  contract enums; `docs/api/openapi.json` regenerated (24 insertions, 579 deletions). Tests:
  fakes are Jev-only; new tests for removed endpoint, ignored `simulation_run_id`, legacy
  provider rows counted invalid, store failure fallback, and an OpenAPI check that no
  simulation/summary/Gemini text remains. The ClickHouse harness now applies 0007 + 0008.
  `uv run pytest tests/unit/api -q` -> 255 passed; `-m integration` SQL + lifecycle on a
  throwaway ClickHouse with 0008 applied -> 24 passed; Grafana unit + SQL -> 119 passed.

- M2 Console (22:50 local): removed `SimulationBadge`/`SimulationTag`, the `sim` facet (URL,
  model, table column, facet options), the "simulation-tagged" KPI, simulation fields in event
  and evidence sheets and the `simulation_run` relationship label; the Gemini card,
  `summary-request.tsx`, `requestSummaryAction`, `requestSummary`, `permissions.requestSummary`,
  `EXTORQ_SUMMARY_TIMEOUT_MS`, `SUMMARY_OUTCOME`/`refusalDetail`, `statementChips`,
  `summaryUnavailableReason`, `providerTime`, `EvidenceChip` and the dead `aiSummary`; the LAB
  pill (`EnvironmentPill`), "Security console · Lab", "lab" copy on login/overview, the asset
  "Environment" fact and the environment in the investigation header. AI tab is Jev only; health
  card "AI triage". zod schemas and the contract check follow the regenerated OpenAPI types.
  `pnpm lint` 0 warnings; `pnpm typecheck` ok; `pnpm test` 194/194; `pnpm build` ok;
  `tests/security/test_security_frontend_static.py` 26 passed; no secrets in `.next/static`.
  Smoke script: Jev-only markers, `EXTORQ_SMOKE_RULES`, and a removed-copy check on every page.
  AGENTS.md / DESIGN.md updated; the screenshot README is marked outdated (retake after VERIFY).

## Plan
1. API: drop `simulation_run_ids` / `simulation_run_id` / `scenario_id` (schemas, SQL, filters),
   `POST /alerts/{id}/summary` + `SummaryGate` + summary settings, Gemini provider health;
   regenerate `docs/api/openapi.json`; update `docs/api/README.md`; tests.
2. Console: remove Simulation badges/facets/filters/labels, the Gemini card and button, the
   LAB pill and "lab" copy, environment badges; `pnpm gen:api`, lint, typecheck, test, build;
   update `scripts/smoke.mjs`, `AGENTS.md`, `DESIGN.md`.
3. Grafana: no dropped columns; panel titles/descriptions/units/thresholds; validate JSON.

## Independent release verification (2026-11-23 IST)

The working tree was based on `023fdb63b6023143302a0733883c9749743835c3` and included
uncommitted releases in progress. The alert API now withholds a rule brief when its exact
version is unavailable. The console separates expired and otherwise unavailable evidence and
shows node- and source-specific Kubernetes delivery state and reported metrics. Grafana keeps
OpenTelemetry exporter requests separate from SDK collector records. The disposable SQL harness
applies the current numbered migrations, including the evidence event-time migration. The
console smoke script checks real asset links for the cluster filter and scopes retired-copy
checks to product controls so historical provenance can remain visible.

| Command | Result |
|---|---|
| `npm run lint && npm run typecheck && npm test` in `frontend/` | ESLint and TypeScript passed. All 199 frontend tests passed. |
| `npm run build -- --webpack` in `frontend/` | Production compile and standalone build passed using Webpack |
| `npm run build` in `frontend/` | Turbopack could not bind its worker socket in the restricted session (`EPERM`) |
| `node --check frontend/scripts/smoke.mjs` | Passed |
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q --tb=short -p no:cacheprovider tests/unit/api tests/security/test_security_frontend_static.py` | 375 passed |
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python infra/grafana/generate_dashboards.py --check` | Dashboards current |
| `docker compose --env-file /dev/null --profile full config --quiet` | Compose configuration parsed successfully |
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -r s -p no:cacheprovider -m integration tests/integration/api/test_api_sql_clickhouse.py tests/integration/api/test_grafana_sql_clickhouse.py` | 92 skipped because the Docker API socket returned permission denied |

The restricted session also denied a generic loopback bind and could not reach the console or
Grafana over loopback. Authenticated browser views, Grafana datasource queries and the
revision of any running images remain unverified. Run the smoke script against a freshly
built isolated release using the controlled-test alert IDs and both role credentials. Run the
Grafana live suite and capture desktop and mobile views from that deployment.
