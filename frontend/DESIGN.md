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
series 1, the active tab underline and the user avatar. Nowhere else.

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
badges), unsupported `cov-unsupported` (zinc-600: visible on a card, never mistaken for an empty
track).

Charts: `--chart-1` brand, `--chart-2` light lavender, `--chart-3` deep violet, `--chart-4`
zinc-400, `--chart-5` zinc-600; severity charts use the severity hues. Grid `--xq-grid`
(white 6%), axis text `--xq-axis` (= muted).

The first console's utility names (`bg-surface`, `text-ink-2`, `border-rule`, ...) are gone:
every view uses the names in the tables above.

### 1.3 Type

Geist Sans for UI (via `geist/font`, i.e. `next/font/local`), Geist Mono only for identifiers:
ids, hashes, asset and rule ids, paths, addresses, event types, raw excerpts and absolute UTC
timestamps. Counts, durations, percentages and relative times are sans with tabular numerals
(`tabular-nums`; every `<table>` and `.num` has them by default): Geist Mono's slashed zero and its
short dash never appear next to sans figures, and a missing value is always the sans em dash
(`DASH`). KPI figures use proportional numerals (`proportional-nums`, no slab-footed "1"); dates
inside a sentence are sans ("Newest event Nov 22 13:56 UTC").

| Step | Class | Size / line | Use |
|---|---|---|---|
| 12 | `text-xs` | 12/16 | meta, table headers, axis ticks, badges (floor: nothing smaller) |
| 13 | `text-sm` | 13/20 | dense tables, nav, controls, card descriptions |
| 14 | `text-base` | 14/20 | body (default on `<body>`), card titles (600) |
| 16 | `text-lg` | 16/24 | section headings between card groups, sheet titles |
| 20 | `text-xl` | 20/28 | detail-page figures (asset / service header strips) |
| 24 | `text-2xl` | 24/32 | page title (600, `tracking-tight`) |
| 30 | `text-3xl` | 30/36 | KPI figures (600, `tracking-tight`, proportional; 24 on phones) |

Weights: 400 body, 500 emphasis and nav-active,
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
- Gradients: only the faint radial glow of the login backdrop (`.login-backdrop`) and area fills
  that fade to 0. Bars are flat (severity colour at 90% opacity, 1px card-coloured seams between
  stacked segments): a per-segment gradient muddies every seam. Never on buttons, cards or text.

## 2. App shell

`src/app/(console)/layout.tsx`:

- **Sidebar** (`AppSidebar`, shadcn Sidebar, `collapsible="icon"`, 240px): brand lockup (the
  ExtorQ mark on a brand tile + "ExtorQ" + "Security console"), labelled groups
  **Monitor** (Overview, Assets), **Detect** (Detections), **Operate** (System health),
  **Analytics** (Grafana, external, `EXTORQ_GRAFANA_URL`), user menu in the footer (avatar,
  name, role, role badge, shortcuts, sign out). Collapses to icons with Cmd/Ctrl+B or the rail;
  state persists in the `sidebar_state` cookie (UI preference only); a sheet on phones.
- **Top bar** (sticky, 56px, hairline below): sidebar trigger, breadcrumbs derived from the URL
  (`src/lib/navigation.ts`: group > section > object; ids validated, shown as text), the
  Cmd/Ctrl-K **command palette** trigger, the **data freshness**
  indicator ("Updated 13:57:12 UTC" at every width: the time the page's data was received from
  the API; amber dot when the view is older than 5 minutes; refresh re-runs the server
  components). Detail pages name their object in the trail (asset display name, service name,
  "Alert 7763c537…"), truncated at 28ch.
- **Command palette** (`CommandPalette`, shadcn Command in a Dialog pinned at 14vh, so the input
  does not move as results change): pages, recent alerts (30
  days, 40 newest, by rule, title, id, asset), assets; quick actions built from validated
  input (a rule id opens the Detections filter, a 32-hex id opens the investigation). Lists come
  from the server (`src/lib/server/shell.ts`) as props, inside a Suspense boundary so they never
  delay the page; the palette never calls the API.

## 3. Page anatomy

1. `PageHeader`: h1 noun title, optional badges beside it (`titleMeta`), one subtitle line
   computed from the data (the page's finding), actions on the right (at most one primary
   button), `freshness={result.receivedAt}` (feeds the top bar).
2. KPI row: 3-4 `KpiCard`s (`grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4`; phones get a
   compact two-column grid of label and figure). Each states what its number is made of in a
   one-line sub-label (`KpiFigures`: "45 critical · 795 high · 5 unverified") and links to the page
   that explains it. Figures that two pages show are counted the same way on both (Kubernetes
   nodes report through their cluster: counted with it on the Overview and on Assets).
3. Card grid: 12 columns at `xl` with 24px gaps; the block that answers the page's question gets
   8 columns, its companion 4. Cards in a row end level (the grid stretches them); a card that
   stretches must have content to fill (a chart that grows, a footer action pinned to the
   bottom), never a blank band.
4. Data tables: inside a `SectionCard flush` so rows bleed to the card edge and cell text aligns
   with the card title (`--table-edge`).
5. Detail pages: a title row (`PageHeader`, or the investigation's header card) with the status
   badge, a facts card (type, ids, owner, first seen...), headline figures in one divided strip or
   a KPI row, then tabs with the brand underline: `LinkTabs` when each tab loads different API
   data (asset detail: `?tab=` is a server route), shadcn `Tabs` when every panel is rendered at
   once (service, investigation: `?tab=` is mirrored with `history.replaceState`, no API call).
   Main column plus a right rail of `SectionCard`s with `KeyValueList`s where the page has facts
   to keep in view (investigation: analyst status, key facts with provenance folded, activity
   once an analyst acted). One control per action: the investigation header shows the status
   read-only with a "Change" link to the rail's form. The primary button only when there is
   something to act on ("View 8 open alerts"; "Alert history" in outline otherwise). Detail pages
   name their object in the breadcrumb trail (`PageCrumbs`). Row details open in a `DetailSheet`
   (right drawer), never inline expanders. Rail and main column end close together: cards that
   would leave a band (attributes, recent alerts) go full width below the two columns.
6. Investigation hierarchy: "Why this rule fired" leads with the rule's logic, what the detector
   found, then **Key signals** (`views/investigation/signals.ts`, unit-tested): a sequence rule's
   ordered stages as a stepper with the gaps between them (CORR-002), threshold checks as
   observed / threshold with "Fired" or "Not met" (VM-001), risk signals in amber (SSH success
   after failures, write-all, untrusted checkout, privileged Pod, risky RBAC, boot persistence)
   and corroboration in neutral (auditd, audit + state). Only true flags and non-empty lists
   become signals. The feature lists below keep what the signals do not show: detector features
   with clear labels, then correlation features grouped by source (SSH, HTTP, application, host
   changes, Kubernetes, GitHub, scope) with zero counters folded behind one `Disclosure`.
   Caveats are said once: a shared NAT/gateway source address is a warning chip in the header
   ("Shared NAT source 10.0.2.2", explanation in its hint), not a notice repeated on every tab.
   Timeline: bursts carry their expander at the row end ("9 ›"), link strength is a 3-dot meter
   with its word. Correlation: one toggle per relationship type (count and strength mix; a press
   filters the list), observations grouped by relationship, strength and event type (each group
   opens its members in a sheet), "Every observation" for the flat list. AI (Jev triage only):
   the recommendation, the sufficient-context probability on its documented bands, each typed
   answer with its bar, rationale codes in words (the code in a hint), and the input hash it was
   computed from (a notice when it differs from the current context). Context: one status per source, and
   the card meta counts gaps and missing-telemetry notes together so no two lines disagree.

## 4. Components (src/components/console)

| Component | Use it for | Rules |
|---|---|---|
| `PageHeader` | every page's title row | noun title; subtitle = computed finding; one primary action; pass `freshness` |
| `SectionCard` | every card | `titleId` is the h2 id (smoke tests find sections by it); `icon` 16px muted; `description` one line; `meta` grey; one `action` (`CardLink`); `flush` for tables; `footer` pins an action to the bottom |
| `KpiCard` | headline figures | value from the API as is (DASH for unknown, 0 for zero); `unit` for "/ total"; `status` tone+word; `footer` for a `SplitBar` (the slot is reserved, so bars and sub-labels line up across a row); `visual` for a `CoverageMark` (32px); a one-line `sub` (truncates, never wraps); no delta or trend unless the API gives a comparable series |
| `KpiFigures` | the parts of a KPI figure | "45 critical · 795 high · 5 unverified": dot separators, `strong` / `tone` for non-zero counts, `hideZero` |
| `Fraction` | a part of a whole anywhere | "15 / 84", denominator muted; the one fraction format (KPI units, donut centres, class rows, by-kind rows) |
| `SplitBar` | parts of one total (severity mix, collector states) | true proportions, zero parts omitted, `label` describes the parts; not drawn when only one part is non-zero (a full single-colour bar is decoration, not proportion) |
| `Disclosure` | secondary detail folded behind one quiet line | "Show 9 zero counters", "Provenance", "Timeline as summarised 14": a real button with `aria-expanded`; never for evidence rows (sheets) and never to hide a warning |
| `NotFoundState` | a 404 or an invalid id in the address | calm dashed frame, one sentence, the request id, a "Back to …" link; the page title says "Alert not found" / "Asset not found" / "Service not found". `ErrorState` stays for failures (5xx, timeouts) |
| `SeverityBadge` | the one severity mark per row / header (`size="md"`) | always shows the word |
| `SeverityDot` | legends, palette rows | pair with the word or a count |
| `StatusDot`, `StatusPill`, `HealthBadge` | health of collectors, pipeline, rules, providers, asset coverage | dot + word; pill only in headers |
| `LifecycleBadge` | an asset or collector the API marks `stale` or `retired` | one status per object: the lifecycle state when it has one, otherwise its health; the API's reason in the hint. The same rule everywhere: a stale collector on System health is "Stale" (its last health in the hint), never "OK" and "Stale"; a stale or gapped source in an investigation context is one pill |
| `CoverageBadge` | service coverage state | dot (hollow for planned) + word; meaning and API reasons in the hint |
| `StaleBadge` | stale data, always | never let old data pass as current |
| `ConfidenceBadge` | alert evidence confidence | three neutral signal bars + word; it is completeness, not a verdict |
| `RoleBadge` | user menu | brand tint for analysts, neutral outline for viewers |
| `DataTable` | any list that needs sorting/filtering/paging | TanStack: sorting, `facets` (popover checkboxes with live counts; a facet with fewer than two values is hidden), uncontrolled (`initialColumnFilters`) or controlled filters (`columnFilters` + `onColumnFiltersChange`, to mirror the URL; applied in the server render), `search` over listed columns or a custom `match`, column visibility (`meta.label`), pagination with range and total (`summary` / `footerNote` to word it): the rows-per-page menu appears once the rows outgrow the default page and the arrows with "1 / N" only with more than one page, so a one-page table never shows a pager that cannot page; `busy` while new data loads. Rows: `rowHref` navigates, `onRowClick` runs a callback (`clickRowOpener` clicks the row's `data-row-open` button to open its sheet); both ignore clicks from portalled content, controls and text selections. Keep a real link or button in the identity cell. `rowAnchorId` + `handleRef.reveal(rowId)` for jump targets (`#evidence-<id>`). Filters run on loaded rows: say so when the API capped the list |
| `FacetFilter` | a facet outside a DataTable (or wired to one) | controlled: `selected`, `counts`, `onChange`; options may carry an icon and a description |
| `DetailSheet`, `DetailSection`, `RawBlock` | event / evidence / finding details | right drawer, `KeyValueList` fields, raw excerpt via `UntrustedText multiline mono` inside `RawBlock` |
| `KeyValueList` | facts in rails and sheets | `layout="stacked"` for long values; DASH for missing |
| `Timeline` | investigation timeline | markers: filled brand = evidence, filled white = direct, dashed = candidate, faint = unestablished; word beside each; times UTC mono; `anchorId` for `#evidence-<id>` jumps |
| `UntrustedText` | every telemetry string | see section 6 |
| `EmptyState` | honest empty blocks | dashed frame + one sentence; `compact={false}` for a whole-card empty |
| `ErrorState` | failed blocks | "Couldn't load X." + API message + request id + Retry (wording used by smoke) |
| `Notice` | capped lists, lifecycle caveats | neutral or `tone="warn"` |
| `Skeleton` presets (`HeaderSkeleton`, `KpiRowSkeleton`, `ChartSkeleton`, `TableSkeleton`, `PanelSkeleton`; route presets in their view folders) | `loading.tsx` | final layout, flat bars, no shimmer |
| `Hint` | short definitions on hover and focus | console text only, never raw telemetry |
| `CoverageMark` | the four asset classes at a glance | the brand mark's arcs in each class's health colour (top macOS, right Linux VM, bottom Kubernetes, left GitHub); unknown = zinc, never green |
| `IdText`, `Timestamp`, `RelativeTime` | ids, UTC times, recency | ids mono + copy; UTC always; `RelativeTime` shows the UTC instant in a tooltip (`plain` inside links) |
| `PageCrumbs`, `Freshness` | detail pages | name the object in the breadcrumb trail; report the data's `receivedAt` to the top bar |

shadcn/ui (src/components/ui): Sidebar, Breadcrumb, Command, Dialog, Sheet, Card, Badge, Tabs,
Table, Tooltip, HoverCard, Popover, DropdownMenu, Select, ToggleGroup/Toggle, Progress,
Separator, Skeleton, ScrollArea, Avatar, Chart, Button, Input, InputGroup, Label, Textarea,
Alert, Collapsible, Spinner. Which for what: Tabs for panels rendered together (they may mirror
`?tab=` with replaceState), LinkTabs for tabs that load different data per tab; ToggleGroup for
time ranges and view modes; Select for single choice filters; Popover + Command for multi-select
facets; DropdownMenu for row and account menus; HoverCard for previews (full untrusted value);
Tooltip for definitions; Sheet for row details; Dialog for confirmations and the palette;
Progress for quota/usage bars.

ExtorQ edits to generated files (re-apply after `shadcn add --overwrite`): `table.tsx` has no
`"use client"` and uses the hairline/`--table-edge` styles; `chart.tsx` sets series colours as
validated CSS variables (no raw-HTML `<style>`); `scroll-area.tsx` passes the CSP nonce
(`useNonce`); `sidebar.tsx` renders `SidebarInset` as a `<div>` (the layout owns `<main>`) and
is 240px wide; `use-mobile.ts` uses `useSyncExternalStore`; tooltip, dialog, sheet, popover,
hover card, dropdown and select use `shadow-float` and no backdrop blur; card uses
`shadow-card ring-hairline`; button hover uses `bg-brand-hover`; the `sm` button and toggle
sizes use `text-sm` (13px, on the type scale) instead of the generated `text-[0.8rem]`.

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
- **Not found**: `NotFoundState` (a 404 is not a system failure): what is missing, why it may be,
  a way back.
- **Provider off**: when System health reports Jev disabled, the AI tab says so next to its
  advisory label and the empty state explains why no assessment exists (read from `/health`).
- **Capped lists**: the count says so ("Events 50+", "Newest 50 shown").
- **Viewer role**: mutating controls are not rendered; say "read-only" where an analyst would
  see a form.

## 6. Untrusted text

All telemetry (log lines, paths, user agents, commit messages, Kubernetes fields, names) goes
through `UntrustedText`: React text only, bidi/zero-width/tag/control characters shown as
visible `⟨U+XXXX⟩` markers with a "hidden characters" warning, never linkified, never HTML.

- Default: cut at `limit` characters, the full value in a popover (button, keyboard accessible,
  copy button, scrollable).
- `oneLine`: ellipsis at the column width, the full value in a hover card on hover or focus
  (no click, so row links keep working). Use it in tables and lists. In clickable rows a press
  closes the hover card until the pointer leaves, and it never opens while a sheet or dialog
  that does not contain it is open (it would cover the sheet and take its first Escape).
- `plain`: inside a link or button (no nested interactive elements); the destination shows the
  full value.
- `multiline mono` inside `RawBlock` for raw excerpts (sheets).

Never "Show all N characters" walls; never put telemetry in `Hint` or `title`.

## 7. Data visualisation

- One question per chart; stacked bars by severity for alert activity (most severe on top, flat
  fills at 90%, rounded top on the topmost segment only, 1px card-coloured seams; the card opens
  on 7 days when fewer than 6 of the last 24 hourly buckets hold alerts), donut for parts of a whole
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
- The investigation activity strip is a histogram per relationship lane (60 equal buckets over
  the observations padded 5 %, each lane on its own scale, totals on the right), so a 3-second
  evidence burst on a 10-minute context is a visible bar, not a 1px tick.

## 8. Badge specs

| Badge | Height | Text | Shape |
|---|---|---|---|
| Severity (sm / md) | 20 / 24px | 12px 500, 400-shade hue | `rounded-md`, 10% fill, 25% inset ring, 6px dot |
| Status pill | 20px | 12px 500 | as severity, health hues |
| Status dot | text height | 12-13px in `text-fg-2` | 6px dot + word |
| Coverage | text height | 13px in `text-fg-2` | 8px dot (hollow ring for planned) + word |
| Confidence | text height | 13px | 3 bars (4 / 7 / 10px) in `fg-2`, empty bars `hairline-strong` |
| Role | 20px | 12px 500 | brand tint (analyst) / neutral outline (viewer) |

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
