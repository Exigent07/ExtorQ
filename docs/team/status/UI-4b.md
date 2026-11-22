# UI-4b status: finish UI-4's scope (Assets, asset detail, service detail)

Last updated: 2026-11-22 11:35 UTC (M0-M6 done; final checks green)

## Scope (owned paths only)
`frontend/src/app/(console)/assets/**`, `frontend/src/app/(console)/services/**`,
`frontend/src/components/views/assets/**`, `frontend/src/components/views/services/**`.
Shared shell/components/tokens (`src/components/console`, `src/components/ui`, `src/lib/**`,
`scripts/**`) were read-only for me; requests are listed below. No git commit.

External importers of my folders: none (grep over `src/`, 11:00 UTC). UI-4's notes about
`CollectorTable` (Health) and `ServiceCoverageDot` (Investigation) are out of date: Health uses
`views/health/collectors-table.tsx`, Investigation no longer imports `ServiceCoverageDot`.

## Starting point (b375fbe, 2026-11-22 10:47 UTC)
UI-4 had finished M1 (Assets page) and M2 (asset overview tab) and left unverified first versions
of the services tab, Kubernetes levels, node page, findings/events tables and the service page.
UI-5 added lifecycle (`src/lib/lifecycle.ts`, `LifecycleBadge`, `?retired=1`).
Baseline: `pnpm typecheck` exit 0, `pnpm lint` exit 0, `pnpm test` 159 passed.

## Milestones
- [x] M0 (10:52 UTC) context read; `pnpm gen:api` (no diff: lifecycle already typed); dev server
      3100 -> compose API 8000; first screenshots of every owned route (21 PNGs read). Gaps found:
      no retired section; duplicate "Stale" marks (lifecycle pill + health dot); ports cells
      wrapping to 3-4 lines; coverage note inline instead of on hover; workloads' telemetry column
      all dashes; events tables with all-empty Actor/Source IP columns and no event-type facet;
      "Instances 4" not saying 2 Pods + 2 containers; no events time range; node findings/events
      empty states not pointing to the cluster.
- [x] M3 Services / Workloads tab: `coverage-cell.tsx` (dot + word; hover card with the state's
      meaning, the API's reasons and the collector note via UntrustedText), `ports-cell.tsx` (most
      exposed endpoint on two nowrap lines + "+N"; hover card lists every endpoint with exposure,
      owner attribution meaning and basis; "Owner unknown" in the brighter tone, never shown as an
      owner; IPv6 in brackets), Kind column only when rows mix kinds, "Telemetry" column (sources,
      last time only when reported), key line hidden when it repeats the name, finding-style facets
      only where rows differ. Kubernetes levels: cluster > nodes > workloads > Kubernetes Services >
      Pods and containers (tile links to the node's workloads), 2 columns on phones. Node page:
      workloads with their Pods/containers on the node; one quiet stale notice per section (no
      per-row badges). `EndpointLine` and the unused `ServiceCoverageDot` removed (no importers).
- [x] M4 Findings + Events tabs: events 24 h / 7 d / 30 d ToggleGroup (`range-toggle.tsx`,
      navigates; the server reads the API window; 30 d kept inside the API's 31-day maximum),
      event-type facet, quiet outcome dot, all-empty optional columns hidden at first
      (`emptyOptionalColumns`), "capped" notice; findings facets only where rows differ; a node's
      empty findings/events tabs link to the cluster's (Kubernetes scans and events are stored
      under `k8s:extorq-lab`, checked in `config/scanners.yaml`). DetailSheets for finding and
      event rows (existing) verified by clicking.
- [x] M5 Service detail: header card (instances figure says what it counts: "2 Pods · 2
      containers" via `instanceBreakdown`; discovered-via and adapter id one-line with hover cards)
      + tabs: telemetry sources with freshness meters, instances, ports and exposure, findings,
      alerts linking to investigations, events, attributes (verified for ssh, coredns, lab-portal
      workload, kube-dns Kubernetes Service).
- [x] Retired assets: `retired-assets.tsx`, a collapsed muted section at the end of the Assets
      page (count in its header, in the subtitle "N retired (listed apart)" and in the notice;
      rows link to the retired asset pages with the API's reason; ErrorState inside if the
      `include_retired` read fails; `?retired=1`, the Overview's link, opens it). One status per
      asset card / owner-account row / asset header (`assetStatus`: lifecycle when stale or
      retired, else health); lifecycle notice with the API reason under a stale/retired asset's
      header; subtitle says "N stale" for lifecycle-stale assets and "N with stale collectors"
      for collector verdicts; owner accounts are a top-aligned context panel (no blank band).
- [x] M6 screenshots read and iterated (rounds r0-r4 + final); lint / typecheck / test / build /
      smoke green.

## Verified
| Claim | Command (in `frontend/` unless noted) | Result |
|---|---|---|
| Types + OpenAPI contract | `pnpm gen:api` (no diff) then `pnpm typecheck` | exit 0 |
| Lint (0 warnings) | `pnpm lint` | exit 0 |
| Unit tests | `pnpm test` | 175 passed, 0 failed (baseline 159; +12 `views/services/model.test.ts`, +4 assets model) |
| Production build | `pnpm build` (Node 20.11.1, Tailwind 4.3.3) | exit 0, 10 routes + proxy (final build 11:29 UTC) |
| End to end, production build over the compose API | `next start --port 3101` (`EXTORQ_API_BASE_URL=http://127.0.0.1:8000`, secrets by file) + `EXTORQ_SMOKE_ANALYST_PASSWORD_FILE=../var/secrets/analyst_password EXTORQ_SMOKE_VIEWER_PASSWORD_FILE=../var/secrets/viewer_password node scripts/smoke.mjs --base http://127.0.0.1:3101` (paced 1500 ms) | run 1 11:12:54-11:14:24 UTC 105/0; run 2 11:24:07-11:25:37 105/0; run 3 on the final build 11:29:51-11:31:21 UTC: 105 passed, 0 failed, exit 0 (every asset class x 4 tabs, workload, Kubernetes Service, host service, node -> workload link) |
| No XSS sinks / browser credentials | repo root: `uv run pytest tests/security/test_security_frontend_static.py -q` | 26 passed |
| No secrets or server config in the client bundle | `grep -rIl` over `.next/static` for EXTORQ_API_TOKEN, EXTORQ_SESSION_SECRET, EXTORQ_ANALYST_PASSWORD_FILE, NEXT_PUBLIC, clickhouse, Bearer, api_service_token, frontend_session_secret | 0 files each |
| No console errors, CSP violations or exceptions (production build) | scratch copy of `scripts/screenshots.mjs` with CDP `Log`/`Runtime` capture: Assets `?retired=1`, macOS services, Linux events 7 d, node workloads, coredns service, event sheet opened, range toggle clicked, ports hover card | "no console errors, warnings or exceptions" on every page |
| Facets, sheets, hover cards work | same tool with clicks/hover: event-type facet (ssh events -> 16 of 50), finding sheet, event sheet, coverage and ports hover cards | screenshots read |
| Retired section renders as specified | SYNTHETIC: scratch proxy on 127.0.0.1:8199 forwarding to the API and marking the 4 mechanics-test assets retired as the API will at 15:01:41 UTC; second `next start` on 3102 | collapsed + `?retired=1` + retired repo page read: subtitle "5 of 5 monitored assets healthy · 1 GitHub owner account · 4 retired (listed apart)", GitHub class Healthy 1 of 1, section count 4 with reasons; proxy and 3102 stopped |
| Screenshots | `node --experimental-websocket scripts/screenshots.mjs --base http://127.0.0.1:3101 ...` (paced) | final set read (1440 px): Assets; macOS / Linux VM / kind cluster / Kubernetes node / GitHub repo x overview, services, findings, events; ssh (host service) + ports tab; coredns (Kubernetes workload) instances; kube-dns (Kubernetes Service) ports. Also 390 px phone checks (Assets, cluster services, ssh), no horizontal overflow |

Screenshot files (scratchpad, not committed):
`/private/tmp/claude-501/-Users-exigent-Development-ExtorQ/5613ba9c-4f02-44a4-90cb-7e9748b9b4aa/scratchpad/shots/final/*.png`
(25 PNGs) and `.../shots/synthetic-final/synthetic-*.png` (3, synthetic retired state).

## Not verified
- The real retired state on the live API (the mechanics-test assets retire at 2026-11-22
  15:01:41 UTC, after this session): only with the synthetic proxy above. The page reads the
  same API fields (`retired_excluded`, `include_retired=true`, `lifecycle_state`).
- Hover cards on keyboard focus: Radix HoverCard opens on focus (source checked), but the
  headless capture only showed mouse hover.
- Browsers other than headless Chrome; screen readers (semantics reviewed in code only).
- The compose console (port 3000) still runs an older image; redeploying it is A's / the lead's.

## Requests for shared files (not changed by me)
- `frontend/docs/screenshots/04-kind-node-workloads.png` (UI-5 / lead) still shows the old yellow
  "Stale" Pod badges; replace it with `.../shots/final/41-node-workloads.png` or a recapture.
- `src/components/views/overview/asset-coverage.tsx`: link "Show retired" to
  `/assets?retired=1#retired-assets` so the page also scrolls to the opened section.
- `src/components/console/data-table.tsx` `FacetFilter`: a wider popover (or a class prop) so long
  option labels such as event types (`auth.ssh.login_succeeded`) do not truncate at `w-56`.
- `scripts/screenshots.mjs`: `--hover`, `--clicks` and console-error capture (working version in
  the scratch copy `.../scratchpad/shots.mjs`) would let page agents verify hover cards, sheets
  and CSP without a proxy.

## Blockers
- None.
