# UI-2 status: Detections + System health pages (frontend)

Last updated: 2026-11-22 07:45 UTC (stage complete; no commits made)

Owns: `src/app/(console)/detections/**`, `src/app/(console)/health/**`,
`src/components/views/detections/**`, `src/components/views/health/**` (frontend/).
Shared shell/components/tokens (`src/components/console`, `src/components/ui`, `src/lib`) were used
as they are; change requests are listed below instead of edits to shared files.

## Done
- [x] M0 read AGENTS.md, frontend/AGENTS.md, PLAN.md, DESIGN.md, UI-1 handoff, the smoke markers
      of /detections and /health, the baseline screenshot 05-detections.png
- [x] M1 Detections: KPI row (alerts in range by severity; open by workflow state and age of the
      oldest open alert; assets with alerts; rule health bar), shadcn Tabs Alerts | Rules (URL
      `tab=rules`, both panels server-rendered, inactive one hidden), alert table (view-local
      TanStack table in the shared DataTable's look: severity pill, rule id + title linking to the
      investigation, one-line summary with hover card, simulation badge, asset + linked services,
      evidence chip + confidence, last/first seen with UTC tooltips, analyst status; faceted
      filters severity/rule/asset/status/simulation with live counts mirrored in the URL;
      time-range ToggleGroup on `range`; row click to /investigations/<id>), evidence drawer
      (shadcn Sheet: what fired, alert facts, cited events loaded on open through the read-only
      `loadEvidenceAction`), rules table (shared DataTable: severity, status + version, last run
      dot + relative time + duration + schedule, runs/failures 24 h, quiet sources as muted badges,
      open/total alerts that switch to the filtered Alerts tab in place, ATT&CK ids as badges)
- [x] M2 System health: storage pill in the title row, KPI row (collectors healthy/total with split
      bar, ingestion spool depth + oldest age, quarantined + gateway rejections, rule failures 24 h,
      AI providers enabled/total, advisory), collectors DataTable (status dot + stale pill + last
      error in a HoverCard, collector, asset, source types (+N in a hover card), last success with
      a freshness bar against 3 intervals, lag, buffered; facets status/asset/type; problems first),
      ingestion pipeline table, rule execution table with a run-total footer, quarantine and
      rejections with a bar list, AI providers (advisory: flag, key presence, last call status,
      last success, outcome counts), API notes
- [x] M3 loading skeletons at real layout; unit tests (23) for both view models
- [x] M4 screenshots read and iterated (4 rounds: column priorities by container width, drawer
      width/overflow, phone layouts, KPI balance, 13 px data text, focus on drawer open)
- [x] M5 lint / typecheck / test / build / smoke / security checks green (below)

## Files (all inside UI-2's scope)
- `src/app/(console)/detections/page.tsx`, `loading.tsx`, `data.ts` (route-local server-only
  loader through `apiRequest`: up to 200 alerts per request, severity/status as arrays)
- `src/components/views/detections/`: `model.ts` (+ `model.test.ts`), `workspace.tsx` (state
  provider mirrored in the URL, tabs, range toggle), `alerts-table.tsx`, `facet-filter.tsx`,
  `evidence-sheet.tsx`, `rules-table.tsx`, `kpi-row.tsx`, `time-hint.tsx`.
  Removed (replaced, no other importer): `alert-filters.tsx`, `alert-history.tsx`,
  `evidence-drilldown.tsx`.
- `src/app/(console)/health/page.tsx`, `loading.tsx`; `src/components/views/health/`: `model.ts`
  (+ `model.test.ts`), `kpi-row.tsx`, `collectors-table.tsx`, `health-sections.tsx` (rewritten).

## Behaviour notes for reviewers
- One API read for the whole alert range (limit 200; today 24 alerts in 7 days), so facets and
  counts work on complete data and change the URL in place (history.replaceState, no server
  round trip). If the API holds more than one page, the page says so (Notice), facet changes then
  navigate so the API filters, and Older/Newer links page through. Totals never present the loaded
  count as the total (lower bound "200+" if the API gave no total).
- URL filters stay compatible with every existing link (`?rule=VM-001&range=30d` from the palette,
  `?severity=high`, `?asset=...`); new: repeated values, `sim=yes|no`, `tab=rules`, all validated
  against the same allow-lists (`views/detections/model.ts`).
- Link prefetches in production render only up to `loading.tsx` boundaries: measured 0 extra API
  reads from them (API log during a browser run: alerts x2, rules x1, assets x1, alerts/{id} x1).

## Verified (commands run in `frontend/` unless noted; results observed)
| Claim | Command | Result |
|---|---|---|
| Lint clean (whole project) | `pnpm lint` | exit 0 |
| Types + OpenAPI contract check (whole project) | `pnpm typecheck` | exit 0 |
| Unit tests (whole project; 23 new in `views/{detections,health}/model.test.ts`) | `pnpm test` | 132 passed, 0 failed |
| Production build (Node 20.11.1, Tailwind 4.3.3) | `pnpm build` | exit 0 (final build 07:42 UTC, after the last code change; lint/typecheck/test re-run just before it: exit 0, 132 passed) |
| End to end on the production build | `next start` on 127.0.0.1:3101 (`EXTORQ_API_BASE_URL=http://127.0.0.1:8000`, secrets by file) + `EXTORQ_SMOKE_ANALYST_PASSWORD_FILE=../var/secrets/analyst_password EXTORQ_SMOKE_VIEWER_PASSWORD_FILE=../var/secrets/viewer_password node scripts/smoke.mjs --base http://127.0.0.1:3101` | final build: 105 passed, 0 failed, exit 0 (07:44 UTC; also 105/105 on the previous build) (all detections filters incl. "rule filter keeps only VM-001 rows", "asset filter keeps cluster rows", rules table, health markers, investigations of the 5 mandatory rules found through the new table, viewer read-only, forged viewer state change refused) |
| Browser interactions, no console errors / CSP violations (production) | headless Chrome over CDP with real mouse events (scratch `interact.mjs`) | facet High -> `?severity=high` 11 rows, +Medium 22 rows, no page fetch; Rules tab -> `tab=rules`; rule link -> Alerts filtered to that rule in place; 30 d -> new data; evidence drawer 576 px, scrollWidth 575 (no overflow), server action POST; Escape closes it (focus back on the chip); row click -> /investigations/<id>; "no console errors, exceptions or CSP violations" |
| Viewer role on both pages | scratch marker check signed in as viewer | 7/7 pages PASS (same data, no mutating controls exist on these pages) |
| Design inspector (app rules) on the production build, 1440/768/390 | `node ~/.claude/skills/design-taste-frontend/scripts/inspect.mjs --app <url>` (Node 26) through a loopback cookie-adding proxy | Detections: 0 FAIL, 0 WARN; Health: 0 FAIL, 0 WARN (fixed on the way: 74%/54% text under 13 px -> summaries, collector ids, asset ids, AI values at 13 px; KPI and rule-card blank bands; 768 px overflow of the alert's second line) |
| No XSS sinks / browser credentials (F's checks) | repo root: `uv run pytest tests/security/test_security_frontend_static.py tests/security/test_security_containers.py -q` | 49 passed, 1 warning (pre-existing compose hardening note, owner A) |
| No secrets or server config in the client bundle | `grep -rIl` over `.next/static` for EXTORQ_API_TOKEN, EXTORQ_SESSION_SECRET, EXTORQ_ANALYST_PASSWORD_FILE, NEXT_PUBLIC, clickhouse, Bearer, api_service_token, frontend_session_secret, 127.0.0.1:8000, /api/v1/ | 0 files each |
| Screenshots inspected | `scripts/screenshots.mjs` (1440 first screen + full, rules tab, evidence drawer, 1024, 390) and the inspector's 1440/768/390 renders | all read; final set in the session scratchpad (not copied into `frontend/docs/screenshots`, which UI-1 owns) |

## Not verified
- The compose console on port 3000 still runs the old image (redeploy owned by A).
- A real capped range (> 200 alerts): only unit-tested (`alertFigures`, `apiFilters`) and reviewed;
  the lab has 24 alerts.
- Error states rendered against a failing API (code paths use the shared ErrorState; not forced).
- Browsers other than headless Chrome; screen readers (semantics reviewed in code only).

## Shared-component change requests (not edited; view-local workaround in place)
1. `DetailSheet` (console/detail-sheet.tsx): `size` never widens the sheet: SheetContent's
   `data-[side=right]:sm:max-w-sm` out-specifies `sm:max-w-2xl`/`sm:max-w-xl` (and
   `data-[side=right]:w-3/4` beats `w-full` on phones). Use the same variant chain
   (`data-[side=right]:sm:max-w-xl`, `data-[side=right]:w-full`) so tailwind-merge replaces them.
2. `DetailSheet`: the Radix ScrollArea viewport wraps children in `display: table`, so no-wrap
   content (UntrustedText `oneLine`, `flex-none` timestamps) widens the body past the sheet and
   clips it. Add `[&_[data-radix-scroll-area-viewport]>div]:block!` to its ScrollArea. Also: Radix
   auto-focuses the first focusable element on open; when that is a `Hint`, its tooltip opens and
   swallows the first Escape: focus the content instead (`onOpenAutoFocus`). Workaround with all
   three fixes: the drawer in `views/detections/evidence-sheet.tsx`.
3. `DataTable` (console/data-table.tsx): no controlled/initial column filters and no change
   callback, so facets cannot mirror URL filters; Detections uses a view-local TanStack table in
   the same look (`alerts-table.tsx`). Its `rowHref` handler also reacts to clicks that bubble
   from portalled content (sheets, hover cards) through the React tree; guard with
   `event.currentTarget.contains(event.target)` (done in the view-local table).
4. `RelativeTime` (console/time.tsx) puts UTC in a native `title`; Detections/Health use the
   view-local `TimeHint` (shadcn Tooltip via `Hint`). Consider moving it into console/.
5. `src/lib/server/api.ts` `listAlerts`: fixed at 50 rows and single-valued filters while the API
   accepts `limit` up to 200 and arrays for severity/status; Detections uses the route-local
   loader `src/app/(console)/detections/data.ts` (through `apiRequest`). Consider a shared one.
6. `src/lib/filters.ts` / frontend/AGENTS.md: document the Detections URL additions (repeated
   values, `sim`, `tab`); `scripts/smoke.mjs` could add markers for the tabs ("Alerts", "Rules")
   and the evidence chip (`aria-label="Evidence: ..."`).

## Blockers
- None.
