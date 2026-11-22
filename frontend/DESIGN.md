# ExtorQ console design system

Binding for every console view. Art direction: a premium dark security-operations console in
the class of Linear, Vercel, Wiz and Datadog dark mode. Calm near-black neutrals, one
indigo-violet accent used sparingly, colour only where it carries meaning (severity, health,
coverage), generous spacing, crisp type, honest data.

Source of truth for values: `src/app/globals.css`. Components: `src/components/console/`
(ExtorQ) and `src/components/ui/` (shadcn/ui, style `radix-nova`, shadcn CLI 4.23.0).
Reference implementations: Login (`src/app/login/`) and Overview (`src/app/(console)/page.tsx`,
`src/components/views/overview/`). Security rules from `AGENTS.md` (rules 1-9) override anything
here.

## 1. Tokens

### 1.1 Colour roles (dark only; `.dark` on `<html>`)

| Role | Token | Value | Use |
|---|---|---|---|
| Canvas | `--background` / `bg-background`, `bg-canvas` | `#09090b` | page ground |
| Sidebar | `--sidebar` / `bg-sidebar` | `#0c0c0f` | half a step above the canvas |
| Card | `--card` / `bg-card` | `#111113` | cards, sheets |
| Raised | `--muted`, `--secondary` / `bg-raised` | `#18181b` | nested wells, inputs on cards |
| Popover | `--popover` / `bg-popover` | `#151518` | menus, popovers, tooltips, dialogs |
| Hover / active fill | `bg-hover` / `bg-active` (`--accent`) | white 4% / 7% | row hover, selected nav, toggles |
| Hairline | `--border` / `border-hairline`, `ring-hairline` | white 7% | card edges, table header rule |
| Soft hairline | `border-hairline-soft` | white 5% | row rules, dividers inside cards |
| Strong hairline | `--input` / `ring-hairline-strong` | white 11% | inputs, outlined controls, chips |
| Text | `text-foreground` | `#fafafa` | titles, figures, primary values (17-19:1) |
| Secondary text | `text-fg-2` | `#b1b1b9` | values in rows, labels that matter (8-9:1) |
| Muted text | `text-muted-foreground` | `#8b8b94` | labels, meta, axis ticks (5.2-5.9:1) |
| Faint | `text-fg-faint` | `#6b6b74` | decoration only (separators, idle icons): never words |
| Brand accent | `text-brand`, `bg-brand`, `--ring`, `--chart-1` | `oklch(0.66 0.19 280)` | active nav icon, focus ring, chart series 1, links on hover, the role badge |
| Primary fill | `--primary` / `bg-primary` | `oklch(0.555 0.21 280)` | the one primary button per screen (white label 5.1:1); hover `bg-brand-hover` (4.5:1) |
| Brand tint | `bg-brand-soft` | accent at 12% | avatar, role badge |

The accent appears on: the primary action, the active nav item's icon, focus rings, chart
series 1, the active tab underline, the LAB pill's dot and the user avatar. Nowhere else.

### 1.2 Meaning colours

Severity (soft tinted pills: 400-shade text, 10% fill, 25% inset ring):

| Severity | Token | Hue |
|---|---|---|
| Critical | `sev-critical` | red-400 `oklch(0.704 0.191 22.2)` |
| High | `sev-high` | orange-400 `oklch(0.75 0.183 55.9)` |
| Medium | `sev-medium` | amber-400 `oklch(0.828 0.189 84.4)` |
| Low | `sev-low` | blue-400 `oklch(0.707 0.165 254.6)` |
| Info | `sev-info` | zinc-400 |

Health (6px dot + word): ok `health-ok` emerald-400, degraded/stale `health-warn` amber-400,
failed/missing `health-bad` red-400, unknown/disabled `health-off` zinc-500 (label in muted text).

Service coverage: monitored `cov-monitored` (emerald), degraded `cov-degraded` (amber),
unmonitored `cov-unmonitored` (orange), planned adapter `cov-planned` (zinc-500, hollow in
badges), unsupported `cov-unsupported` (zinc-700).

Charts: `--chart-1` brand, `--chart-2` light lavender, `--chart-3` deep violet, `--chart-4`
zinc-400, `--chart-5` zinc-600; severity charts use the severity hues. Grid `--xq-grid`
(white 6%), axis text `--xq-axis` (= muted).

Legacy utility names of the first console (`bg-surface`, `bg-ground`, `bg-overlay`,
`text-ink`, `text-ink-2`, `border-rule`, `border-control`, `border-line`, `text-ok`,
`bg-warn-bg`, `bg-sev-high-bg`, ...) are mapped onto this palette so routes that are not rebuilt
yet keep a consistent look. New code uses the names in the tables above.

### 1.3 Type

Geist Sans for UI (via `geist/font`, i.e. `next/font/local`), Geist Mono for ids, hashes,
asset ids, rule ids, raw excerpts and UTC timestamps. Figures use tabular numerals
(`tabular-nums`; every `<table>` and `.num` has them by default).

| Step | Class | Size / line | Use |
|---|---|---|---|
| 12 | `text-xs` | 12/16 | meta, table headers, axis ticks, badges (floor: nothing smaller) |
| 13 | `text-sm` | 13/20 | dense tables, nav, controls, card descriptions |
| 14 | `text-base` | 14/20 | body (default on `<body>`), card titles (600) |
| 16 | `text-lg` | 16/24 | section headings between card groups, sheet titles |
| 20 | `text-xl` | 20/28 | detail-page figures in a MetricStrip |
| 24 | `text-2xl` | 24/32 | page title (600, `tracking-tight`) |
| 30 | `text-3xl` | 30/36 | KPI figures (600, `tracking-tight`, tabular) |

`text-2xs` is a legacy alias of 12px. Weights: 400 body, 500 emphasis and nav-active,
600 titles and figures. No uppercase tracked labels.

### 1.4 Spacing, radii, elevation, motion

- 4px base. Canvas gutters 32px (`px-8`) on desktop, 16px on phones. Gap between cards 24px
  (`gap-6`), inside KPI rows 16px (`gap-4`). Card padding 20px (`px-5`, header `pt-4 pb-3`).
- Radii: cards 12px (`rounded-xl`), controls 8px (`rounded-lg`), chips and badges 6px
  (`rounded-md`), dots full.
- Elevation by lightness: canvas < sidebar < card < popover. Cards: 1px hairline ring plus a
  faint top highlight (`shadow-card`). Floating surfaces (menus, popovers, tooltips, dialogs,
  sheets): `shadow-float` (hairline ring + soft drop shadow). Never a resting glow.
- Motion: 150 ms colour/opacity/transform transitions on hover and focus (`duration-150`),
  100-200 ms fade/zoom on open/close of menus, popovers, dialogs and sheets (shadcn defaults).
  No decorative animation, no shimmer, no pulse on loading states. Everything respects
  `prefers-reduced-motion` (globals.css).
- Gradients: only inside charts (bar fills fade 95% to 55%, area fades to 0) and the faint radial
  glow of the login backdrop (`.login-backdrop`). Never on buttons, cards or text.

## 2. App shell

`src/app/(console)/layout.tsx`:

- **Sidebar** (`AppSidebar`, shadcn Sidebar, `collapsible="icon"`, 240px): brand lockup (the
  ExtorQ mark on a brand tile + "ExtorQ" + "Security console · Lab"), labelled groups
  **Monitor** (Overview, Assets), **Detect** (Detections), **Operate** (System health),
  **Analytics** (Grafana, external, `EXTORQ_GRAFANA_URL`), user menu in the footer (avatar,
  name, role, role badge, shortcuts, sign out). Collapses to icons with Cmd/Ctrl+B or the rail;
  state persists in the `sidebar_state` cookie (UI preference only); a sheet on phones.
- **Top bar** (sticky, 56px, hairline below): sidebar trigger, breadcrumbs derived from the URL
  (`src/lib/navigation.ts`: group > section > object; ids validated, shown as text), the
  Cmd/Ctrl-K **command palette** trigger, the **LAB** environment pill, the **data freshness**
  indicator (time the page's data was received from the API; amber dot when the view is older
  than 5 minutes; refresh re-runs the server components).
- **Command palette** (`CommandPalette`, shadcn Command in a Dialog): pages, recent alerts (30
  days, 40 newest, by rule, title, id, asset), assets; quick actions built from validated
  input (a rule id opens the Detections filter, a 32-hex id opens the investigation). Lists come
  from the server (`src/lib/server/shell.ts`) as props, inside a Suspense boundary so they never
  delay the page; the palette never calls the API.

## 3. Page anatomy

1. `PageHeader`: h1 noun title, optional badges beside it (`titleMeta`), one subtitle line
   computed from the data (the page's finding), actions on the right (at most one primary
   button), `freshness={result.receivedAt}` (feeds the top bar).
2. KPI row: 3-4 `KpiCard`s (`grid gap-4 sm:grid-cols-2 xl:grid-cols-4`). Each states what its
   number is made of in its sub-label and links to the page that explains it.
3. Card grid: 12 columns at `xl` with 24px gaps; the block that answers the page's question gets
   8 columns, its companion 4. Cards in a row end level (the grid stretches them); a card that
   stretches must have content to fill (a chart that grows, a footer action pinned to the
   bottom), never a blank band.
4. Data tables: inside a `SectionCard flush` so rows bleed to the card edge and cell text aligns
   with the card title (`--table-edge`).
5. Detail pages: `PageHeader` with badges, a `MetricStrip`, `LinkTabs` (underline, brand
   indicator) or shadcn `Tabs`, a main column (8) and a right rail (4) of `SectionCard`s with
   `KeyValueList`s. Row details open in a `DetailSheet` (right drawer), not inline expanders.

## 4. Components (src/components/console)

| Component | Use it for | Rules |
|---|---|---|
| `PageHeader` | every page's title row | noun title; subtitle = computed finding; one primary action; pass `freshness` |
| `SectionCard` | every card | `titleId` is the h2 id (smoke tests find sections by it); `icon` 16px muted; `description` one line; `meta` grey; one `action` (`CardLink`); `flush` for tables; `footer` pins an action to the bottom |
| `Panel` | legacy alias of SectionCard | do not use in new code |
| `KpiCard` | headline figures | value from the API as is (DASH for unknown, 0 for zero); `unit` for "/ total"; `status` tone+word; `footer` for a `SplitBar`; `visual` for a `Sparkline` or `CoverageMark`; no delta unless the API gives a comparable earlier value |
| `SplitBar` | parts of one total (severity mix, collector states) | true proportions, zero parts omitted, `label` describes the parts |
| `SeverityBadge` | the one severity mark per row / header (`size="md"`) | always shows the word |
| `SeverityDot` | legends, palette rows | pair with the word or a count |
| `StatusDot`, `StatusPill`, `HealthBadge`, `CoverageStatusDot` | health of collectors, pipeline, rules, providers, asset coverage | dot + word; pill only in headers |
| `CoverageBadge` | service coverage state | dot (hollow for planned) + word; meaning and API reasons in the hint |
| `StaleBadge` | stale data, always | never let old data pass as current |
| `ConfidenceBadge` | alert evidence confidence | three neutral signal bars + word; it is completeness, not a verdict |
| `SimulationBadge` | alerts whose evidence carries `extorq-sim-*` | neutral outline + flask; telemetry is genuine |
| `RoleBadge`, `EnvironmentPill` | shell | neutral; role badge in brand tint |
| `DataTable` | any list that needs sorting/filtering/paging | TanStack: sorting, `facets` (popover checkboxes with counts), `search` over listed columns, column visibility (`meta.label`), pagination with range and total, `rowHref` row click (keep a real link in the identity cell); filters run on loaded rows: say so when the API capped the list |
| `SortableTable`, `FilterChips` | legacy small sortable tables | prefer DataTable |
| `DetailSheet`, `DetailSection`, `RawBlock` | event / evidence / finding details | right drawer, `KeyValueList` fields, raw excerpt via `UntrustedText multiline mono` inside `RawBlock` |
| `KeyValueList` | facts in rails and sheets | `layout="stacked"` for long values; DASH for missing |
| `MetricStrip` | detail-page headline figures in one divided card | |
| `Timeline` | investigation timeline | markers: filled brand = evidence, filled white = direct, dashed = candidate, faint = unestablished; word beside each; times UTC mono; `anchorId` for `#evidence-<id>` jumps |
| `EvidenceChip` | AI-cited evidence ids | verified: link to `#evidence-<id>` with an emerald check; unverified: dashed amber outline, warning icon, not a link, never styled as verified |
| `UntrustedText` | every telemetry string | see section 6 |
| `EmptyState` | honest empty blocks | dashed frame + one sentence; `compact={false}` for a whole-card empty |
| `ErrorState` | failed blocks | "Couldn't load X." + API message + request id + Retry (wording used by smoke) |
| `Notice` | capped lists, lifecycle caveats | neutral or `tone="warn"` |
| `Skeleton` presets (`HeaderSkeleton`, `KpiRowSkeleton`, `ChartSkeleton`, `TableSkeleton`, `PanelSkeleton`, `PageSkeleton`) | `loading.tsx` | final layout, flat bars, no shimmer |
| `Hint` | short definitions on hover and focus | console text only, never raw telemetry |
| `Sparkline` | a real trend in a KPI's `visual` slot | only with an API series; name series and window in the sub-label |
| `CoverageMark` | the four asset classes at a glance | the brand mark's arcs in each class's health colour (top macOS, right Linux VM, bottom Kubernetes, left GitHub); unknown = zinc, never green |
| `IdText`, `Timestamp`, `RelativeTime` | ids, UTC times, recency | ids mono + copy; UTC always |

shadcn/ui (src/components/ui): Sidebar, Breadcrumb, Command, Dialog, Sheet, Card, Badge, Tabs,
Table, Tooltip, HoverCard, Popover, DropdownMenu, Select, ToggleGroup/Toggle, Progress,
Separator, Skeleton, ScrollArea, Avatar, Chart, Button, Input, InputGroup, Label, Textarea,
Alert, Collapsible, Spinner. Which for what: Tabs for in-page views that need no URL, LinkTabs
for server-rendered tab routes; ToggleGroup for time ranges and view modes; Select for single
choice filters; Popover + Command for multi-select facets; DropdownMenu for row and account
menus; HoverCard for previews (full untrusted value); Tooltip for definitions; Sheet for row
details; Dialog for confirmations and the palette; Progress for quota/usage bars.

ExtorQ edits to generated files (re-apply after `shadcn add --overwrite`): `table.tsx` has no
`"use client"` and uses the hairline/`--table-edge` styles; `chart.tsx` sets series colours as
validated CSS variables (no raw-HTML `<style>`); `scroll-area.tsx` passes the CSP nonce
(`useNonce`); `sidebar.tsx` renders `SidebarInset` as a `<div>` (the layout owns `<main>`) and
is 240px wide; `use-mobile.ts` uses `useSyncExternalStore`; tooltip, dialog, sheet, popover,
hover card, dropdown and select use `shadow-float` and no backdrop blur; card uses
`shadow-card ring-hairline`; button hover uses `bg-brand-hover`.

## 5. States

- **Loading**: `loading.tsx` per route with skeleton presets at real sizes; labels are not
  invented; no layout shift when data lands.
- **Empty**: the block keeps its frame and header and says in one sentence what is absent
  ("No high or critical alert in the last 7 days."). Charts draw their axis and grid with one
  sentence centred over the plot.
- **Zero vs unknown**: a real zero prints `0`; an unknown value prints a muted em dash
  (`DASH`). Never round up, never fill a gap with a fixture.
- **Stale**: `StaleBadge` on the stale object; the freshness indicator turns amber when the
  view is older than 5 minutes; capped lists say they are capped.
- **Error**: `ErrorState` inside the failed block (other blocks still render), with retry.
- **Viewer role**: mutating controls are not rendered; say "read-only" where an analyst would
  see a form.

## 6. Untrusted text

All telemetry (log lines, paths, user agents, commit messages, Kubernetes fields, names) goes
through `UntrustedText`: React text only, bidi/zero-width/tag/control characters shown as
visible `⟨U+XXXX⟩` markers with a "hidden characters" warning, never linkified, never HTML.

- Default: cut at `limit` characters, the full value in a popover (button, keyboard accessible,
  copy button, scrollable).
- `oneLine`: ellipsis at the column width, the full value in a hover card on hover or focus
  (no click, so row links keep working). Use it in tables and lists.
- `plain`: inside a link or button (no nested interactive elements); the destination shows the
  full value.
- `multiline mono` inside `RawBlock` for raw excerpts (sheets).

Never "Show all N characters" walls; never put telemetry in `Hint` or `title`.

## 7. Data visualisation

- One question per chart; stacked bars by severity for alert activity (most severe on top,
  rounded top on the topmost segment only, 1px card-coloured seams), donut for parts of a whole
  (thin ring, no slice labels, total in the centre, parts listed beside it), bar lists for
  rankings (bar length = value / largest value, count and share right-aligned).
- Axes: no y-axis line, 3-4 round integer ticks with the top tick at or above the maximum
  (`niceTicks`), dashed faint horizontal grid only, x labels on whole steps (every 4 h, or daily
  at 00:00), never rotated, UTC.
- Legends list only series with data, as a dot + label + total in the card. Tooltips are a
  plain popover box: the bucket range in UTC, one line per series with data, the total.
- Empty buckets are drawn as nothing (no alert stored), never interpolated; say so in the
  caption. A truncated series says it was truncated.
- Every chart has a screen-reader table (`sr-only`) or an `aria-label` that states the values.

## 8. Badge specs

| Badge | Height | Text | Shape |
|---|---|---|---|
| Severity (sm / md) | 20 / 24px | 12px 500, 400-shade hue | `rounded-md`, 10% fill, 25% inset ring, 6px dot |
| Status pill | 20px | 12px 500 | as severity, health hues |
| Status dot | text height | 12-13px in `text-fg-2` | 6px dot + word |
| Coverage | text height | 13px in `text-fg-2` | 8px dot (hollow ring for planned) + word |
| Confidence | text height | 13px | 3 bars (4 / 7 / 10px) in `fg-2`, empty bars `hairline-strong` |
| Simulation | 20px | 12px | `ring-hairline-strong` outline, flask icon |
| Role / environment | 20-24px | 12px 500 | brand tint (analyst) / neutral outline |

## 9. Accessibility

- Text contrast >= 4.5:1 on every surface (measured, see section 1.1); the faint tier is never
  used for words. Primary button label 5.1:1 (hover 4.5:1).
- Visible focus everywhere: 2px brand outline (`:focus-visible`) or `ring-2 ring-ring/50`.
- Keyboard: skip link to `#main`; sidebar Cmd/Ctrl+B; palette Cmd/Ctrl+K with arrow keys and
  Enter; every Hint, hover card and popover trigger is focusable; menus are Radix (roving
  focus); table sort headers are buttons with `aria-sort`.
- Colour is never the only carrier: severity, status, coverage and relationship always have a
  word; charts have an sr-only table or label.
- Landmarks: the top bar is the page's banner `<header>`, `<nav>` for the sidebar and the
  breadcrumbs, one `<main id="main">`, one h1 per page, cards are `<section aria-labelledby>` with
  h2 titles.
- `prefers-reduced-motion` disables transitions and animations globally.

## 10. Verifying a page

Run the dev server (`pnpm dev`, port 3100) or `pnpm build && pnpm start`, then capture:

```bash
EXTORQ_SHOTS_PASSWORD_FILE=../var/secrets/analyst_password \
  node --experimental-websocket scripts/screenshots.mjs --base http://127.0.0.1:3100 \
  --out /tmp/shots --first-screen overview=/          # 1440x900 first screen
node --experimental-websocket scripts/screenshots.mjs --base http://127.0.0.1:3100 \
  --out /tmp/shots overview-full=/                     # full page
node --experimental-websocket scripts/screenshots.mjs --anon --first-screen login=/login
EXTORQ_SHOTS_WIDTH=390 EXTORQ_SHOTS_HEIGHT=844 ... --first-screen overview-phone=/
```

Look at every PNG: the page's question answered by its biggest block, rows ending level, no
blank bands, colour only on data, every zero a zero and every unknown a dash, no text under
12px, nothing overflowing at 390px.
