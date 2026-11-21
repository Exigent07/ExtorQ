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
| shadcn/ui | components generated into `src/components/ui` (Radix base) | edited copies: `chart.tsx` has no raw-HTML style injection, `table.tsx` has no `"use client"` |
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
docker build -t extorq/frontend:0.1.0 .                     # compose builds the same context
```

Configuration (server-side environment only; there are no `NEXT_PUBLIC_*` variables):

| Variable | Meaning |
|---|---|
| `EXTORQ_API_BASE_URL` | analyst API origin (required), e.g. `http://127.0.0.1:8100` or `http://api:8000` |
| `EXTORQ_API_TOKEN_FILE` | file with the API service token (`EXTORQ_API_TOKEN` fallback; avoid) |
| `EXTORQ_ANALYST_PASSWORD_FILE` / `EXTORQ_VIEWER_PASSWORD_FILE` | account passwords (≥ 12 chars) |
| `EXTORQ_SESSION_SECRET_FILE` | HS256 session signing secret (≥ 32 chars) |
| `EXTORQ_ANALYST_USERNAME` / `EXTORQ_VIEWER_USERNAME` | default `analyst` / `viewer` |
| `EXTORQ_HTTPS` | `auto` (default) / `true` / `false`: `Secure` + `__Host-` cookie and HSTS |
| `EXTORQ_API_TIMEOUT_MS` / `EXTORQ_SUMMARY_TIMEOUT_MS` | 8000 / 90000 |

## Layout

```
src/proxy.ts                    auth gate, per-request CSP nonce, security headers, header stripping
src/app/login/                  sign-in page + server action (throttled, constant-time)
src/app/(console)/              authenticated views (layout re-checks the session)
  page.tsx                      Overview
  assets/, assets/[assetId]/    asset classes; asset detail tabs: overview | services | findings | events
  services/[serviceId]/         service drill-down
  detections/                   alert history (GET filters) + rules
  investigations/[alertId]/     investigation
  health/                       system health
  actions.ts                    server actions (logout, state change, AI summary, drill-downs)
src/components/console/         shell and primitives (panel, tables, badges, UntrustedText, skeletons)
src/components/views/<view>/    view-specific components
src/components/ui/              generated shadcn/ui components
src/lib/api/                    zod schemas, generated OpenAPI types, compile-time contract check
src/lib/auth/                   roles, password check, throttle, session tokens (pure, unit-tested)
src/lib/security/               display sanitiser, CSP, id validation, redirect guard
src/lib/server/                 server-only: config, secrets, API client, session, log
src/lib/services.ts             service coverage / exposure / attribution presentation rules
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
   change alert state or request AI summaries: the form is not rendered, the server action
   refuses, and the API returns 403. The smoke test replays the analyst form as the viewer.
5. **All telemetry is attacker-controlled.** Render strings through `UntrustedText` (plain text,
   visible markers for bidi/zero-width/tag/control characters, truncation with an expand
   control). Never render telemetry as HTML, never `dangerouslySetInnerHTML` (lint error),
   never turn a URL from telemetry into a link. Links are built only from validated ids.
6. **Unknown stays unknown.** Missing values render as a grey dash, real zeros as `0`. Counts
   shown in a view come from the API or from the rows on screen, never typed in. Stale data
   carries a stale badge; capped lists say they are capped.
7. **Secrets** are read from files (bounded, cached by mtime), never logged; logs name settings,
   never values. `src/lib/server/log.ts` redacts sensitive-looking keys defensively.
8. **Headers**: per-request CSP nonce (`script-src 'self' 'nonce-…' 'strict-dynamic'`, no
   `unsafe-eval` in production, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'`,
   `form-action 'self'`), `nosniff`, `no-referrer`, `X-Frame-Options: DENY`, COOP/CORP,
   Permissions-Policy, HSTS over HTTPS. Style *attributes* are allowed (React style props).
9. **AI is advisory.** Jev and Gemini panels are labelled advisory; Gemini evidence ids are chips
   that jump to `#evidence-<event_id>` only when verified, and unverified ids are flagged and
   never styled as verified. A summary is requested only by an analyst click (it spends budget).

## Design tokens (see `src/app/globals.css`)

Dark graphite, "data terminal": panels one step darker than the ground (`--xq-ground` #171719,
`--xq-surface` #131217), separation by 1px lines (`--xq-border`, row rules `--xq-rule`), three
text tiers (`--xq-text`, `--xq-text-2`, `--xq-muted`, each ≥ 4.5:1), the only selection mark a
1px ink line (`--xq-line`). Colour is reserved for data: severity (`--xq-sev-*` with dark tints)
and health (`--xq-ok|warn|bad|off`). Geist Sans for text, Geist Mono for ids and figures; type
scale 11/12/13/14/16/20/26 px. Components use the Tailwind utilities mapped from the tokens
(`bg-surface`, `text-ink-2`, `text-sev-high`, `border-rule`, …), never raw hex values.
States: loading = flat bars at real size (no shimmer), empty = dashed frame + one sentence,
error = inside the failed block with a retry. No gradients, glows or decorative motion.

## Adding a view

1. Add or extend the zod schema in `src/lib/api/schemas.ts` (field names as in the OpenAPI
   document) and a line in `contract-check.ts`; run `pnpm gen:api && pnpm typecheck`.
2. Add a typed endpoint function in `src/lib/server/api.ts` (validate ids first).
3. Create `src/app/(console)/<route>/page.tsx` (server component): `requireSession()`, fetch in
   parallel, render `ErrorState` per failed block, `EmptyState` for honest empties, and a
   `loading.tsx` with `PageSkeleton`. Put the page's one-line finding in `PageHeader`.
4. Render strings with `UntrustedText`; use `SortableTable` (TanStack) for client-side sorting.
5. Add the route's markers to `scripts/smoke.mjs`, a unit test for any new pure logic, then run
   lint, typecheck, test, build and the smoke test.

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
