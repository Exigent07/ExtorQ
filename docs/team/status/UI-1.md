# UI-1 status: console design lead (frontend/**)

Last updated: 2026-11-22 06:52 UTC (stage complete: theme, components, shell, Login, Overview)

## Goal of this stage
Premium dark console on shadcn/ui (art direction in the lead's brief, refined in
`frontend/DESIGN.md`): theme, shadcn components, app shell (sidebar, top bar, Cmd/Ctrl-K),
shared console components, Login + Overview as the reference implementation. Other routes keep
working with the restyled shared primitives; later stages rebuild them.

## Done
- [x] M0 read AGENTS.md, frontend/AGENTS.md, PLAN.md, baseline screenshots
- [x] M1 `frontend/DESIGN.md`: colour roles with values and measured contrast, type scale,
      spacing, radii, elevation, motion, component catalogue with usage rules, page anatomy,
      states, untrusted text, data-viz rules, badge specs, accessibility, how to verify a page
- [x] M2 theme (`src/app/globals.css`): shadcn dark variables (background ... sidebar-*,
      chart-1..5), ExtorQ semantic tokens (brand, hairlines, text tiers, severity, health,
      coverage), dark by default, Geist via `geist/font` (next/font/local), legacy utility names
      of the first console mapped onto the new palette
- [x] M3 shadcn components with the CLI at the repo's version (4.23.0), style switched from
      `radix-mira` (10 px badges, 28 px controls: below the type floor) to `radix-nova` (same APIs):
      sidebar, breadcrumb, command, card, badge, tabs, table, sheet, tooltip, hover-card,
      dropdown-menu, select, popover, toggle-group, toggle, progress, separator, skeleton,
      scroll-area, avatar, chart, button, input, input-group, label, dialog (+ alert, collapsible,
      textarea, spinner refreshed). Security edits re-applied: `table.tsx` no `"use client"`,
      `chart.tsx` no raw-HTML style (validated CSS variables). Further edits: `scroll-area.tsx`
      CSP nonce, `sidebar.tsx` SidebarInset `<div>` + 240 px, `use-mobile.ts` via
      `useSyncExternalStore` (lint), floating surfaces `shadow-float`, overlays without blur.
      CLI run in a scratch copy so it could not touch pinned versions; new deps pinned exactly:
      `cmdk 1.1.1`, `get-nonce 1.0.1` (already in the lockfile tree).
- [x] M4 app shell (`src/app/(console)/layout.tsx`): shadcn Sidebar (brand lockup, Monitor /
      Detect / Operate / Analytics groups, Grafana external link from `EXTORQ_GRAFANA_URL`,
      collapse to icons with Cmd/Ctrl+B or rail, sheet on phones, user menu with role badge,
      shortcuts and sign out), sticky top bar (URL-derived breadcrumbs with validated ids,
      Cmd/Ctrl-K palette, LAB pill, data-freshness indicator fed by each page's `receivedAt`).
      Palette lists (assets, 40 newest alerts of 30 days) are fetched server-side
      (`src/lib/server/shell.ts`, React `cache` per request, shared with the Overview) and passed
      as props inside a Suspense boundary.
- [x] M5 shared components (`src/components/console/`, catalogue below and in DESIGN.md §4)
- [x] M6 Login and Overview rebuilt (Overview: KPI row, alert activity stacked by severity with a
      24 h / 7 d toggle, asset coverage for the four classes with icons and reasons from API
      counts, recent important alerts, collection health, service coverage donut + per-kind bars,
      findings by severity). Pure rules in `src/lib/overview.ts`, `src/lib/navigation.ts`.
- [x] M7 screenshots read and iterated (3 rounds; see Verified); final set in
      `frontend/docs/screenshots/` (README updated)
- [x] M8 lint / typecheck / test / build / smoke green (see Verified)
- Also fixed: a CSP violation that every Radix modal (dialog, popover, dropdown, select) caused
  in production (react-style-singleton's `<style>` had no nonce); `NonceProvider` now hands the
  per-request nonce to `get-nonce`. Smoke markers updated for the new Overview + shell checks.
- `scripts/screenshots.mjs`: `--first-screen`, `--anon`, `--press`, `--click`, `--scale`,
  `EXTORQ_SHOTS_HEIGHT`; full-page captures grow the viewport so the fixed sidebar spans the page.

## Verified (commands run in `frontend/` unless noted; results observed)
| Claim | Command | Result |
|---|---|---|
| Lint clean | `pnpm lint` | exit 0, 0 problems |
| Types + OpenAPI contract check | `pnpm typecheck` | exit 0 |
| Unit tests (12 new in `src/lib/__tests__/shell-overview.test.ts`) | `pnpm test` | 86 passed, 0 failed |
| Production build (Node 20.11.1, Tailwind 4.3.3) | `pnpm build` | exit 0, 10 routes + proxy |
| End to end on the production build over the compose API | `pnpm start` (3100, `EXTORQ_API_BASE_URL=http://127.0.0.1:8000`) + `EXTORQ_SMOKE_ANALYST_PASSWORD_FILE=../var/secrets/analyst_password EXTORQ_SMOKE_VIEWER_PASSWORD_FILE=../var/secrets/viewer_password node scripts/smoke.mjs --base http://127.0.0.1:3100` | run 1 (06:28 UTC): 105 passed, 0 failed; run 2 (06:40-06:44 UTC): 105 passed; run 3 on the final build (after the sidebar `<nav aria-label="Primary">` landmark fix, ~06:50 UTC): 105 passed, 0 failed, exit 0 (incl. new checks: shell groups/palette/LAB, no "Show all N characters" walls) |
| No XSS sinks / browser credentials (F's checks) | repo root: `uv run pytest tests/security/test_security_frontend_static.py tests/security/test_security_containers.py -q` | 49 passed (1 pre-existing warning about A's compose hardening) |
| No secrets or server config in the client bundle | `grep -rIl` over `.next/static` for EXTORQ_API_TOKEN, EXTORQ_SESSION_SECRET, EXTORQ_ANALYST_PASSWORD_FILE, NEXT_PUBLIC, clickhouse, Bearer, api_service_token, frontend_session_secret | 0 files each |
| No CSP violations, console errors or exceptions in Chrome | headless Chrome through a loopback cookie-adding proxy (scratch tool): Overview with the palette open and a query typed, Detections, Linux VM asset | "no console errors, CSP violations or exceptions" (before the get-nonce fix: 1 style-src-elem violation on opening the palette) |
| Design inspector (tasteskill `inspect.mjs --app`, 1440/768/390) | Overview (via the loopback proxy) and `/login` | Overview: 0 FAIL, 1 WARN (58% of text at 12 px: badges, ticks, sublines; nothing under 12 px). Fixed on the way: top bar overflow at 768 px, donut label flagged as covered, left-aligned numbers in the sr-only chart table, heavy login-card shadow. `--allow palette-purple` and the login glow are required by the binding art direction |
| Console image builds and serves the new UI hardened | `docker build -t extorq-ui1-frontend:check .`; `docker run` as `extorq-ui1-console-check` (`--read-only`, tmpfs, `--cap-drop ALL`, `no-new-privileges`, secrets bind-mounted read-only, `127.0.0.1:3110`, API via `host.docker.internal:8000`); `/healthz`; Overview screenshot | build exit 0; healthz 200; uid 1001; Overview renders identically; container and image removed |
| Screenshots inspected | `node --experimental-websocket scripts/screenshots.mjs ...` (README in docs/screenshots) | login 1440x900, Overview 1440x900 + full page + palette + 7 d toggle + collapsed sidebar + 390 px phone, other routes in the new shell; all read |

## Not verified
- The compose `frontend` service (port 3000) still runs the previous image; redeploying it is
  owned by A (`docker compose ... up -d --build frontend`). The same build context was built and
  run as a throwaway hardened container (see Verified), and everything else ran on a local
  production build on 3100 against the compose API on 8000.
- Browsers other than headless Chrome; screen readers (only semantics reviewed in code).
- DetailSheet, DataTable, Timeline and EvidenceChip are built, typed and linted but no page uses
  them yet (they are for the page stages); exercise them when a page adopts them.

## Handoff for page agents (shared components and props)
Rules: DESIGN.md (binding with the art direction) and frontend/AGENTS.md (security). Import from
`@/components/console/<file>`.

| Component (file) | Props | Notes |
|---|---|---|
| `PageHeader` (page-header) | `title`, `subtitle?` (computed finding), `actions?`, `titleMeta?` (badges), `freshness?` (= `result.receivedAt`) | `finding`/`crumbs` still accepted (legacy); breadcrumbs come from the URL |
| `SectionCard`, `CardLink` (section-card) | `title`, `titleId` (h2 id, smoke uses it), `icon?`, `description?`, `meta?`, `action?`, `footer?`, `flush?`, `className?`, `bodyClassName?` | `flush` for tables (sets `--table-edge`); `footer` pins an action to the bottom of a stretched card |
| `Panel`, `SectionHeading` (panel) | legacy | prefer SectionCard |
| `KpiCard`, `SplitBar` (kpi-card) | `label`, `value`, `unit?`, `sub?`, `status?: {tone,label}`, `visual?`, `footer?`, `icon?`, `href?`; SplitBar `parts: {key,value,className}[]`, `label` | values as the API gives them; no invented deltas |
| `KeyValueList`, `MetricStrip` (key-values) | `rows: {label,value}[]`, `layout?: "split"|"stacked"`; MetricStrip `items: {label,value,sub?}[]` | |
| `SeverityBadge`, `SeverityDot`, `SEVERITY_*` (severity) | `severity`, `size?: "sm"|"md"` | `SeverityTag`/`SeverityPill` are legacy aliases |
| `StatusDot`, `StatusPill`, `HealthBadge`, `CoverageStatusDot`, `CoverageBadge`, `StaleBadge`, `COVERAGE`, `HEALTH` (status-badge) | `tone`+`label`; `status`; `variant?: "dot"|"pill"`; CoverageBadge `service` (adapter_support, monitoring_status, coverage_state, coverage_reasons) | |
| `ConfidenceBadge`, `SimulationBadge`, `RoleBadge`, `EnvironmentPill` (badges) | `confidence`; `runIds`; `role` | |
| `DataTable`, `Facet`, `FacetOption` (data-table) | `data`, `columns` (TanStack, `meta: {align?, className?, label?}`), `getRowId`, `label`, `initialSort?`, `facets?: {columnId,title,options:{value,label,icon?}[]}[]`, `search?: {placeholder,columnIds}`, `pageSize?`, `pageSizes?`, `rowHref?`, `emptyMessage?`, `toolbar?`, `initialColumnVisibility?` | client component: define columns in a `"use client"` file; keep a real link in the identity cell |
| `DetailSheet`, `DetailSection`, `RawBlock` (detail-sheet) | `trigger` (asChild element), `title`, `description?`, `badges?`, `children`, `footer?`, `size?: "md"|"lg"`; DetailSection `title`; RawBlock children | replaces inline expanders; raw excerpts via `<UntrustedText multiline mono limit={...} />` inside RawBlock |
| `Timeline`, `TIMELINE_MARK` (timeline) | `items: {id, time, kind: "evidence"|"direct"|"candidate"|"unestablished", title, description?, meta?, anchorId?}[]` | markers + words; `anchorId="evidence-<id>"` for chip jumps |
| `EvidenceChip` (evidence-chip) | `eventId`, `verified` | unverified ids are never links and never styled as verified |
| `UntrustedText` (untrusted-text) | `value`, `limit?`, `multiline?`, `mono?`, `oneLine?`, `plain?` | the only way to render telemetry; `oneLine` in tables, `plain` inside links |
| `EmptyState`, `ErrorState`, `Notice` (states) | `children`, `icon?`, `action?`, `compact?`; `what`, `error`; `tone?: "neutral"|"warn"` | ErrorState wording "Couldn't load X." is relied on by smoke |
| skeletons | `HeaderSkeleton`, `KpiRowSkeleton {count?}`, `ChartSkeleton {height?}`, `TableSkeleton {rows?}`, `PanelSkeleton {rows?, tall?}`, `PageSkeleton {label, strip?, panels?, columns?}`, `Bar` | flat, no shimmer |
| `Hint` (hint) | `content`, `children`, `side?` | console text only |
| `Sparkline` (sparkline) | `values`, `label`, `color?`, `width?`, `height?` | only with a real API series |
| `BrandMark`, `BrandTile`, `BrandLockup`, `CoverageMark` (brand-mark) | `tones: {top,right,bottom,left}`, `label` | CoverageMark arcs: macOS, Linux VM, Kubernetes, GitHub |
| `LinkTabs` (link-tabs), `SortableTable`/`FilterChips` (sortable-table), `IdText`, `Timestamp`, `RelativeTime` | unchanged APIs, restyled | |

Known page work for the next stages (from the lead's review, not done here): Detections (use
DataTable with severity/rule/asset/status facets, evidence in a DetailSheet instead of the inline
"Evidence (n events)" disclosure), Investigation (detail layout with tabs + right rail, Timeline,
EvidenceChip, entities/features as KeyValueList instead of raw JSON arrays), Assets and asset
detail, Service detail, System health (native `<select>`/`<textarea>` in the analyst status form
should become shadcn Select/Textarea).

## Blockers
- None.
