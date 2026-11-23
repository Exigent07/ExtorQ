# frontend/AGENTS.md: ExtorQ Security Console

Scoped guide for the Next.js console. The repository-wide rules in `../AGENTS.md` apply first.
Owner during the build: agent D2 (`docs/team/PLAN.md` §2).

## What it is

A server-rendered analyst console over the ExtorQ analyst API (`docs/api/openapi.json`):
Overview, Assets → Services / Workloads → Service, Detections (rules + alert history),
Investigation, System Health. It shows real API data only. Empty, stale, missing and error
states are explicit, and nothing is invented to fill a block.

## Stack (pinned, `save-exact`, lockfile committed)

| Piece | Version | Note |
|---|---|---|
| Node | 20.11 locally (`engines >=20.9`), 22.23.5 LTS in the image | |
| Next.js | 16.4.6, App Router, `output: "standalone"`, `src/proxy.ts` | Turbopack build |
| React / TypeScript | 19.3.1 / 5.9.3 strict (`noUncheckedIndexedAccess`) | |
| Tailwind CSS | **4.3.3** | 4.3.4+ depends on ESM-only `magic-string@1`, which Node 20.11 cannot `require()` (the build fails). Upgrade only with Node ≥ 20.19 locally. |
| shadcn/ui | CLI **4.23.0**, style **radix-nova** (Radix base), generated into `src/components/ui` | edited copies (re-apply after `shadcn add --overwrite`, see DESIGN.md §4): `chart.tsx` has no raw-HTML style injection, `table.tsx` has no `"use client"`, `scroll-area.tsx` passes the CSP nonce, `sidebar.tsx` `SidebarInset` is a `<div>`, `use-mobile.ts` uses `useSyncExternalStore`; floating surfaces use `shadow-float`, overlays have no backdrop blur; `sm` buttons and toggles use `text-sm` (13px). Run the CLI in a scratch copy of the project so it cannot change pinned dependencies, then copy the files back. |
| cmdk / get-nonce | 1.1.1 / 1.0.1 | Command palette; `get-nonce` hands the CSP nonce to Radix's modal scroll lock |
| zod / jose / TanStack Table / Recharts / lucide-react | 4.6.7 / 6.2.17 / 8.21.3 / 3.8.0 / 1.72.0 | |
| openapi-typescript | 7.13.0 | `pnpm gen:api` → `src/lib/api/openapi.d.ts` |

## Commands

```bash
pnpm install --frozen-lockfile
pnpm dev                 # http://127.0.0.1:3100 (never 3000: that is the compose console)
pnpm lint                # eslint, 0 warnings allowed
pnpm typecheck           # next typegen + tsc --noEmit (includes the OpenAPI contract check)
pnpm test                # node:test + tsx, src/**/*.test.ts
pnpm build && pnpm start # production server on 127.0.0.1:3100
pnpm gen:api             # regenerate types after D1 republishes docs/api/openapi.json
EXTORQ_SMOKE_ANALYST_PASSWORD_FILE=../var/secrets/analyst_password \
EXTORQ_SMOKE_VIEWER_PASSWORD_FILE=../var/secrets/viewer_password \
  node scripts/smoke.mjs [--base http://127.0.0.1:3100]   # read-only end-to-end check
EXTORQ_SHOTS_PASSWORD_FILE=../var/secrets/analyst_password \
  node --experimental-websocket scripts/screenshots.mjs --base http://127.0.0.1:3000 \
  --out docs/screenshots name=/path ...                    # headless Chrome PNGs (docs/screenshots)
  # flags: --first-screen (1440x900 viewport only), --anon (signed out, e.g. /login),
  #        --press Meta+k (open the palette; Escape closes a sheet), --click "<css selector>",
  #        --clicks "<sel>[@@text]|||<sel>" (in order), --focus / --hover "<css selector>"
  #        (hover cards, tooltips), --audit (sideways scroll, text under 12 px), --scale 2;
  #        EXTORQ_SHOTS_WIDTH / EXTORQ_SHOTS_HEIGHT for other viewports (390x844 phone).
  #        Every page also reports console errors, exceptions and CSP violations.
docker build -t extorq/frontend:0.1.0 .                     # compose builds the same context
```

The smoke test covers the overview, every asset class with its tabs (macOS host, Linux VM,
kind cluster, Kubernetes node: four tabs; GitHub repository: no Services tab), a Kubernetes
workload, a Kubernetes Service, a host service and the VM's ssh service (authentication card),
the investigation of each checked rule (default VM-001, VM-002, K8S-001, K8S-002, GH-001;
`EXTORQ_SMOKE_RULES="VM-003,K8S-003,..."` picks others: header, evidence, timeline, coverage,
involved services, honest Jev state), detection filters, health, the "Alert not found" page for
an invalid id and viewer read-only behaviour. Both account password files are required for a
passing run. Every page is also checked for retired product controls and branding. Real names
and evidence text can contain the same words. Pin the
investigations with `EXTORQ_SMOKE_ALERTS="VM-001=<id>,..."` (otherwise the newest alert per rule
in 30 days). It
paces requests (`EXTORQ_SMOKE_PACE_MS`, default 1500): the API's ClickHouse read identity has a
SHARED quota (6000 queries per minute since migration `0007_api_quota.sql`; it was 1200) and a
console page costs about 5-20 queries (the API caches aggregate endpoints for 15 s). Keep
pacing anyway: the quota is shared by every API user and the test suites, and an unpaced run
at the old quota once starved all of them for a minute. The API answers 429 +
`Retry-After` when the quota is exhausted, and the client does not retry 429 (only 502/503/504).

Configuration (server-side environment only; there are no `NEXT_PUBLIC_*` variables):

| Variable | Meaning |
|---|---|
| `EXTORQ_API_BASE_URL` | analyst API origin (required), e.g. `http://127.0.0.1:8100` or `http://api:8000` |
| `EXTORQ_API_TOKEN_FILE` | file with the API service token (`EXTORQ_API_TOKEN` fallback; avoid) |
| `EXTORQ_ANALYST_PASSWORD_FILE` / `EXTORQ_VIEWER_PASSWORD_FILE` | account passwords (≥ 12 chars) |
| `EXTORQ_SESSION_SECRET_FILE` | HS256 session signing secret (≥ 32 chars) |
| `EXTORQ_ANALYST_USERNAME` / `EXTORQ_VIEWER_USERNAME` | default `analyst` / `viewer` |
| `EXTORQ_HTTPS` | `auto` (default) / `true` / `false`: `Secure` + `__Host-` cookie and HSTS |
| `EXTORQ_API_TIMEOUT_MS` | per-attempt API timeout, default 8000 |
| `EXTORQ_GRAFANA_URL` | browser URL of Grafana for the sidebar link (default `http://127.0.0.1:3001/`; http(s) without credentials, anything else falls back to the default) |

## Layout

```
src/proxy.ts                    auth gate, per-request CSP nonce, security headers, header stripping
src/app/login/                  sign-in page + server action (throttled, constant-time)
src/app/(console)/              authenticated views (layout re-checks the session)
  page.tsx                      Overview
  assets/, assets/[assetId]/    asset classes; asset detail tabs: overview | services | findings | events
                                (a Kubernetes node's services tab lists the cluster workloads whose
                                Pods/containers run on it: API `hosted`)
  services/[serviceId]/         service drill-down
  detections/                   alert history + rules; URL: `severity`, `rule`, `asset`, `status`
                                (repeatable: OR within one, AND across), `range`
                                (1h|24h|7d|30d), `tab=rules`, `offset` (only past 200 alerts);
                                allow-listed in `views/detections/model.ts` (parseDetectionsQuery)
  investigations/[alertId]/     investigation (also reads /health for Jev's flags, cached 15 s by the
                                API, so the AI tab can say when Jev is turned off)
  health/                       system health
  actions.ts                    server actions (logout, alert state change, read-only drill-downs)
src/components/console/         app shell (sidebar, breadcrumbs, command palette, freshness) and shared
                                components (SectionCard, KpiCard, DataTable, DetailSheet, Timeline, badges,
                                states, skeletons, UntrustedText): catalogue in DESIGN.md §4
src/components/views/<view>/    view-specific components
src/components/ui/              generated shadcn/ui components (radix-nova)
src/hooks/                      generated shadcn hooks (use-mobile)
src/lib/api/                    zod schemas, generated OpenAPI types, compile-time contract check
src/lib/auth/                   roles, password check, throttle, session tokens (pure, unit-tested)
src/lib/security/               display sanitiser, CSP, id validation, redirect guard
src/lib/server/                 server-only: config, secrets, API client, session, log
src/lib/services.ts             service coverage / exposure / attribution presentation rules
src/lib/navigation.ts           sidebar groups and the URL-derived breadcrumb trail (ids validated)
src/lib/overview.ts             Overview KPIs, class coverage rows, activity series, chart ticks (unit-tested)
src/lib/palette.ts              command-palette data shapes; built in src/lib/server/shell.ts
DESIGN.md                       design system: tokens, components, page anatomy, states, data viz, a11y
scripts/smoke.mjs, run-tests.mjs
```

## Data-fetching and security rules (must hold for every change)

1. **All data is fetched on the server** (server components, server actions) through
   `src/lib/server/api-client.ts`, the only module that holds the API token. It is
   `server-only`; the browser never receives the token, database credentials or API URLs.
   Never call the API from client components and never add `NEXT_PUBLIC_*` variables (lint
   bans both the identifier and the string).
2. **Every response is validated with zod** (`src/lib/api/schemas.ts`); `z.object` strips unknown
   keys. Enum-like tokens that may grow (asset types, service kinds, coverage states) are
   validated as strings and rendered as themselves when unknown. `contract-check.ts` makes
   `pnpm typecheck` fail when the OpenAPI document and the schemas drift.
3. **Identifiers from the URL are validated before they reach a path** (`src/lib/security/ids.ts`)
   and encoded as one path segment; the client also refuses paths that normalise outside
   `/api/v1/`. Filters are allow-listed (`src/lib/filters.ts`).
4. **Every page and every server action re-checks the session**; mutations also check the role
   (`authorizeAction`). The API enforces the role again (`X-ExtorQ-User` / `X-ExtorQ-Role` come
   from the verified session only; the proxy strips client-supplied copies). Viewers cannot
   change alert state: the form is not rendered, the server action refuses, and the API returns
   403. The smoke test replays the analyst form as the viewer.
5. **All telemetry is attacker-controlled.** Render strings through `UntrustedText` (plain text,
   visible markers for bidi/zero-width/tag/control characters; long values cut with the full
   value in a popover, `oneLine` ellipsis with a hover card, `plain` inside links, `RawBlock`
   in a DetailSheet for raw excerpts: never "Show all N characters" walls). Never render
   telemetry as HTML, never `dangerouslySetInnerHTML` (lint error), never turn a URL from
   telemetry into a link, never put telemetry in a `Hint`/`title`. Links are built only from
   validated ids.
6. **Unknown stays unknown.** Missing values render as a grey dash, real zeros as `0`. Counts
   shown in a view come from the API or from the rows on screen, never typed in. Stale data
   carries a stale badge; capped lists say they are capped.
7. **Secrets** are read from files (bounded, cached by mtime), never logged; logs name settings,
   never values. `src/lib/server/log.ts` redacts sensitive-looking keys defensively.
8. **Headers**: per-request CSP nonce (`script-src 'self' 'nonce-…' 'strict-dynamic'`, no
   `unsafe-eval` in production, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'`,
   `form-action 'self'`), `nosniff`, `no-referrer`, `X-Frame-Options: DENY`, COOP/CORP,
   Permissions-Policy, HSTS over HTTPS. Style *attributes* are allowed (React style props).
   Library `<style>` elements carry the nonce: the root layout reads `x-nonce` into
   `NonceProvider`, which feeds Radix ScrollArea (`useNonce`) and `get-nonce` (modal scroll lock).
   The command palette and every shell list come from server components as props.
9. **AI is advisory.** Jev (TypeSafe) is the one AI provider (contracts 2.0). Its triage card is
   labelled advisory, shows the typed answers, the sufficient-context band and the input hash it
   was computed from, and says when it was made on an earlier context. The ai-worker assesses
   alerts on its own: the console never triggers an AI call and offers no AI button.

## Design system (see `DESIGN.md` and `src/app/globals.css`)

Premium dark security-operations console (Linear / Vercel / Wiz / Datadog dark class): canvas
`#09090b`, sidebar a half step lifted, cards `#111113` with a 1px white-7% hairline and a faint
top highlight, 12px card / 8px control radius, 32px gutters. One brand accent (indigo-violet
`oklch(0.66 0.19 280)`) for the primary action, active nav, focus rings and chart series 1; colour
otherwise only carries meaning: severity pills (red/orange/amber/blue/zinc 400 on 10% tint),
health dots (emerald/amber/red/zinc), service coverage. Geist Sans for UI and every count,
duration and relative time (tabular figures; KPI figures proportional); Geist Mono only for ids,
hashes, paths, addresses, event types, raw excerpts and absolute UTC times; scale
12/13/14/16/20/24/30 (nothing smaller than 12px). One status per object; one format for
fractions (`Fraction`: "15 / 84"); one line per KPI sub-label (`KpiFigures`). States: loading =
flat skeletons at real size (no shimmer), empty = dashed frame + one sentence, not found =
`NotFoundState` with a way back, error = inside the failed block with a retry. Charts use flat
fills (no per-segment gradients); the only gradient is the login glow; motion 150-200 ms on
hover/focus/open only. Use the token names in DESIGN.md (the first console's
legacy utility aliases were removed with the last view that used them). Shell: shadcn Sidebar
(Monitor / Detect / Operate / Analytics), top bar with
breadcrumbs, Cmd/Ctrl-K palette and data-freshness indicator (Cmd/Ctrl+B collapses). No
environment pill or "lab" label anywhere in the product UI (2026-11-22 decision); real resource
names (hostnames, cluster and repository names) are shown as reported.

## Adding a view

1. Add or extend the zod schema in `src/lib/api/schemas.ts` (field names as in the OpenAPI
   document) and a line in `contract-check.ts`; run `pnpm gen:api && pnpm typecheck`.
2. Add a typed endpoint function in `src/lib/server/api.ts` (validate ids first).
3. Create `src/app/(console)/<route>/page.tsx` (server component): `requireSession()`, fetch in
   parallel, render `ErrorState` per failed block, `EmptyState` for honest empties, and a
   `loading.tsx` with the skeleton presets. Put the page's one-line finding in `PageHeader`
   (`subtitle`) and pass `freshness={result.receivedAt}`. Lay cards out per DESIGN.md §3
   (`SectionCard`, `KpiCard`, 12-column grid, rows that end level).
4. Render strings with `UntrustedText`; use `DataTable` for lists (TanStack: sorting, faceted
   filters, uncontrolled or controlled column filters to mirror the URL, custom search, column
   visibility, pagination, `rowHref` or a portal-safe `onRowClick`, `rowAnchorId` + `handleRef`
   `reveal(rowId)` for jump targets) and `DetailSheet` for row details (open it from the row's
   identity button; `onRowClick` can delegate to that button).
5. Add the route's markers to `scripts/smoke.mjs`, a unit test for any new pure logic, then run
   lint, typecheck, test, build and the smoke test.

## Notes for maintainers

- `next.config.ts` sets `agentRules: false`: Next.js 16 `next dev` otherwise appends a generated
  block to this file whenever it detects an AI coding agent.
- Investigation display rules live in `src/lib/investigation.ts` and
  `src/components/views/investigation/{model,signals}.ts` (unit-tested): timeline and correlation
  rows drop the event type the summary repeats, evidence rows are chronological. `signals.ts`
  lifts the decisive
  part of an alert out of the feature lists: key signals (true risk flags and non-empty risk
  lists), threshold checks (`threshold_<x>` against `peak_window_<x>`), the ordered stages of a
  sequence rule (`stage_order` with `*_stage_at` times) and the remaining correlation features
  grouped by source; a new rule's features show up in the lists until a signal is defined for
  them. Related observations are grouped by relationship, strength and event type
  (`groupRelated`), each group opening its members in a sheet. The evidence tab lists the IDs
  of unavailable references and identifies those outside event retention where the API knows
  their event time. The detections drawer displays the same distinction as counts. Rule
  descriptions and caveats shown as alert metadata must match the alert's rule version.
- Health shows the ingestion spool backlog once (gateway and writer report the same SQLite
  spool; detector and ai-worker queues are not ingestion) from fresh reports only
  (`src/lib/health.ts`). Pipeline counters are cumulative since each component started (the
  column headers say so; counters that are 0 on every component are named under the table).
  OpenTelemetry collector entries show delivery state by node and source. Their expandable
  measurements distinguish an unavailable counter from zero and label the shared node queue
  in exporter requests.
  Collector counts say when they are inherited from the cluster (`src/lib/assets.ts`), and
  Kubernetes nodes are counted with their cluster on the Overview and the Assets page alike.
- Finding titles drop a doubled scanner prefix for display (`displayFindingTitle`), and one
  advisory reported by several scanners is marked "2 scanners" (`scannersByAdvisory`); the rows
  and their counts stay as the API reports them.

## Known limitations

- Sessions are stateless signed tokens (8 h): logout clears the cookie, but a copied token stays
  valid until expiry; rotating the session secret revokes all sessions (F-13, accepted).
- Login throttling is per process (in memory); restarts reset it.
- With JavaScript disabled, a server-action form post on console pages returns the full page
  (including the result) but Next.js 16.4.6 keeps the response open afterwards; JavaScript
  clients use the RSC fetch path and are unaffected.
- Very large investigation contexts are summarised: the timeline draws evidence, direct links
  and the 20 candidate links closest in time; correlation lists are capped at 58 entries with
  the remainder counted.
