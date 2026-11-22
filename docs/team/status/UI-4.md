# UI-4 status: Assets, asset detail, service detail (console page stage)

Last updated: 2026-11-22 07:12 UTC (M1 done, M2 overview tab done; findings/events tabs written)

## Scope (owned paths only)
`frontend/src/app/(console)/assets/**`, `frontend/src/app/(console)/services/**`,
`frontend/src/components/views/assets/**`, `frontend/src/components/views/services/**`.
Shared shell/components/tokens (`src/components/console`, `src/components/ui`, `src/lib/**`,
`scripts/**`) are read-only for me; requests for them go in "Requests" below.

External importers of my folders (their exports must stay stable):
- `src/app/(console)/health/page.tsx` imports `CollectorTable` (`views/assets/collector-table`).
- `src/components/views/investigation/context-sections.tsx` imports `ServiceCoverageDot`
  (`views/services/service-badges`).

## Plan / milestones
- [x] M0 read AGENTS.md, frontend/AGENTS.md, PLAN.md, DESIGN.md, UI-1 status, screenshots; survey
      the live API data (paced, read-only, viewer role, token passed by file)
- [x] M1 Assets page: asset cards grouped by class (icon, name, type, health dot, collectors x/y,
      last event, open alerts, findings severity mini-bar, service coverage mini-bar); owner accounts
      as a context card (account > repositories); details capped at 16 assets per view (quota)
- [x] M2 Asset detail: header card + LinkTabs; Overview (KPIs, telemetry sources with freshness
      meters, events by source, inventory, recent alerts, attributes, service coverage, nodes)
- [ ] M3 Services / Workloads tab: DataTable (kind, category, coverage badge + reason, ports with
      exposure + attribution, instances), Kubernetes levels (cluster > nodes > workloads >
      Kubernetes Services > Pods/containers), node: workloads running on it; one quiet stale
      indicator per section
- [ ] M4 Findings + Events tabs: DataTables with facets, DetailSheet for rows (raw excerpt on demand
      through the existing server action)
- [ ] M5 Service detail: header + tabs (telemetry sources with freshness, instances, endpoints,
      findings, alerts linking to investigations, events)
- [ ] M6 screenshots read and iterated; lint / typecheck / test / build / smoke

## Data facts found (2026-11-22 ~06:47 UTC, live compose API)
- 10 assets: macOS host (degraded: `sdk-heartbeat-example` collector stale), Linux VM (ok),
  kind cluster (ok), its node (ok, 4 collectors inherited), 3 GitHub repositories
  (`exigent07/extorq-lab` ok; `octocat/hello-world` stale and `actions/hello-world-javascript-action`
  without collector, both last reported 2026-11-21 14:47 by the test collector
  `github-mechanics-test`), 3 GitHub accounts (no collector; overview marks the class `expected=false`).
- The API has **no retired/decommissioned marker** for assets (OpenAPI `AssetListItem` has none;
  `attributes.archived` is false for all repositories). So no asset is shown as retired.
- All 24 Kubernetes instances report `stale=true` (observed 2026-11-21 14:55Z; D1-IC-8, K-DATA fixing).

## Verified
(none yet)

## Not verified
(none yet)

## Requests for shared files
(none yet)

## Blockers
- None.
