# UI-5 status: integration + visual QA (owns frontend/**)

Last updated: 2026-11-22 12:30 UTC (M0-M7 done; nothing committed)

## Goal
Integrate the page agents' work into one consistent premium dark console (frontend/DESIGN.md),
resolve the shared-component requests in UI-2/UI-3/UI-4/UI-4b status files, delete dead
components, rebuild the compose console (port 3000), screenshot every page (1440x900 + full page,
1024 px checks), read every PNG and fix what looks broken; lint / typecheck / test / build / smoke
green at the end; final screenshots in frontend/docs/screenshots/ with a regenerated README.

## Baselines
| When | Check (in frontend/) | Result |
|---|---|---|
| 07:47 UTC (session 1) | `pnpm typecheck` / `pnpm lint` / `pnpm test` | exit 0 / exit 0 / 132 passed |
| 11:40 UTC (session 2, after UI-4b, uncommitted UI-4b work on b375fbe) | same | exit 0 / exit 0 / 175 passed, 0 failed |

## Milestones
- [x] M0 (session 1) context, baseline screenshots
- [x] M1 (session 1) API contract refresh: lifecycle fields, `include_retired`, LifecycleBadge, `?retired=1`
- [x] M2 (session 1) DetailSheet width / ScrollArea / focus; DataTable portal-click guard; RelativeTime tooltip;
      summary refusal reason; UntrustedText `wrap-anywhere`; breadcrumbs name the object
- [x] M3 Assets / asset detail / service detail: finished by UI-4b (docs/team/status/UI-4b.md)
- [x] M4 (11:58 UTC) shared components, part 2: DataTable controlled (`columnFilters` + `onColumnFiltersChange`)
      or initial filters, custom search `match`, `rowAnchorId` + `handleRef.reveal(rowId)` (clears filters,
      turns the page, highlights, focuses), portal-safe `onRowClick` (`isRowActivation`) + `clickRowOpener`
      (`data-row-open`), `busy`, `summary` / `footerNote`, `tableClassName` / `cellClassName`, "Clear
      filters" in the empty row, pager hidden for one page, facets with < 2 values hidden; exported
      controlled `FacetFilter` (descriptions, 20rem popover). UntrustedText `oneLine` hover card: closed on
      press until the pointer leaves, never opens while a sheet/dialog that does not contain it is open.
      Migrated: Detections alert table and Investigation evidence table now run on the shared DataTable
      (view-local TanStack tables and both local FacetFilters deleted); evidence cells show hover cards
      again; asset/service findings and events rows open their sheet on row click. Also: alert loader
      consolidated into `src/lib/server/api.ts` `listAlerts` (route-local `detections/data.ts` and the
      dead 50-row loader + `parseAlertFilters` removed); service header says "No adapter for this type"
      instead of "None (none)"; attribute labels spell acronyms (`keyLabel`: "OS pretty name")
- [x] M5 (12:05 UTC) consistency pass on round-1 screenshots of all 72 routes + 1024 px: investigation
      header figure strip follows the card width (container queries; 1/2/3/5 columns, rules drawn by
      1px grid gaps) instead of overflowing UTC times into the next cell at 1024 px; top bar at
      1024-1279 px: group crumb hidden below xl, parent crumbs keep their width (only the object
      truncates), search trigger w-44, "Updated" word from xl; no pulse on the refreshing dot;
      evidence table edge padding when columns are container-hidden; `sm` buttons/toggles 13 px
      (`text-sm`, was 12.8 px off-scale); breadcrumb mono size on the scale. Dead code removed:
      `sparkline.tsx`, `MetricStrip`, `PageSkeleton`, `CoverageStatusDot` + `COVERAGE`, `ConfidenceText`,
      `alertListCap`, `assetIcon`, PageHeader legacy `finding` / `crumbs` props,
      `views/detections/facet-filter.tsx`, `detections/data.ts`. Docs: frontend/AGENTS.md (quota
      6000/min since 0007 + 15 s cache, keep pacing; legacy aliases gone; screenshot flags; DataTable
      capabilities; Detections URL params; sm text edit), DESIGN.md (catalogue, detail-page anatomy,
      Tabs vs LinkTabs, one-line hover-card rule, edited generated files). `scripts/screenshots.mjs`:
      `--clicks`, `--focus`, `--hover`, `--audit`, console/CSP capture. `scripts/smoke.mjs`: Alerts/Rules
      tab markers, evidence-chip and no-inline-disclosure checks. UI-4b request: Overview "N retired"
      link goes to `/assets?retired=1#retired-assets`.
- [x] M6 compose console rebuilt and recreated three times, last on the final tree (12:26:53 UTC
      image `sha256:1a4eabd4…`): `docker compose --profile full build frontend` + `up -d --no-deps
      frontend` (`--no-deps` because the running api uses an older backend image than the current
      tag and is not this task's to redeploy; api untouched, "Up 5 hours"). Final screenshots of every
      page from the 12:10 image (identical rendering: the 12:26 rebuild only changed the target of the
      Overview's retired link, which is not shown while no asset is retired), read, no defect left.
- [x] M7 (12:28 UTC) lint / typecheck / test / build / smoke against 3000 green; screenshots published.

## Found and fixed on the way
- (session 1) Dev server reload loop from a stale `.next/dev` cache; deleted `.next/dev`.
- Investigation header at 1024 px: "First seen" / "Last seen" UTC times ran into the next cell and
  under the evidence count (5 viewport-breakpoint columns in a 720 px card). Fixed (container queries).
- Top bar at 1024 px: breadcrumb collapsed to "D.. > D.. > C.. > Ale..". Fixed.
- Kubernetes Service header "Adapter: None (none)". Fixed.
- Attribute labels "Os codename" / "Os id". Fixed ("OS codename", "OS id").

## Verified
| Claim | Command (in `frontend/` unless noted) | Result |
|---|---|---|
| Lint (0 warnings), final tree | `pnpm lint` | exit 0 (12:26 UTC) |
| Types + OpenAPI contract check, final tree | `pnpm typecheck` | exit 0 (12:26 UTC) |
| Unit tests, final tree | `pnpm test` | 174 passed, 0 failed (175 at baseline: -2 tests of the deleted `parseAlertFilters`, +1 `keyLabel`) |
| Production build, final tree (Node 20.11.1, Tailwind 4.3.3) | `pnpm build` | exit 0 (12:26 UTC); the compose image build (`pnpm build` in Node 22) also compiled |
| End to end against the compose console, final image | `EXTORQ_SMOKE_ALERTS="VM-001=7763c537…,VM-002=5ac7d8f5…,K8S-001=cfbff556…,K8S-002=afc76864…,GH-001=e7063925…" EXTORQ_SMOKE_ANALYST_PASSWORD_FILE=../var/secrets/analyst_password EXTORQ_SMOKE_VIEWER_PASSWORD_FILE=../var/secrets/viewer_password node scripts/smoke.mjs --base http://127.0.0.1:3000` (paced 1500 ms) | 12:27:10-12:28:32 UTC: 102 passed, 0 failed, exit 0 (also 12:24:00-12:25:23 on the 12:10 image: 102/0). 102 vs UI-4b's 105: pinned alerts skip the 5 per-rule discovery pages; +2 new checks (evidence chips present, no inline evidence disclosures) |
| No API errors from this work's traffic | repo root: `docker compose --profile full logs --since 15m api` grep quota_exceeded / 429 / storage_error / unhandled_error | 0 matches (covers captures, probes, both smoke runs) |
| Shared-component fixes work in a real browser, production build | scratch CDP probe `ui5/probe.mjs` (real mouse/keyboard) against 3000 (12:10 image) and earlier the dev server | 15/15 both: evidence row click opens the sheet with no hover card over it, first Escape closes it, focus back on the row's opener, hover cards still open on plain hover; CORR-002 Gemini chip reveals its evidence row on page 3/3, highlighted, in view; Detections severity facet writes `?severity=high` and filters 24 -> 11 in place; asset events row click opens a 672 px sheet (scrollWidth 671 = clientWidth); no console errors / CSP violations |
| The probe detects the original bug | same probe with `full-value.tsx` from HEAD restored temporarily (dev server) | 4 FAIL (hover card open over the sheet, first Escape swallowed, focus lost); fix restored (diff clean) |
| Every page: no sideways scroll, no text < 12 px, no console errors / CSP violations | `scripts/screenshots.mjs --audit` over 72 routes (round 1, dev), then the final capture against 3000: 67 routes x (first screen + full page) + login + palette + 4 routes x 2 at 1024 px | final capture 12:11:16-12:22:32 UTC: 144 PNGs, 0 layout findings, 0 console problems. Also 390 px phone audit of Overview, Detections, CORR-002, VM services, Health: clean |
| Screenshots read | round 1 (dev, full resolution, tiles of every asset class/tab, services, detections, health, VM-001 + CORR-002 + GH-001 tabs, 1024 px), previous pass + final pass (contact sheets of all 67 first screens, structural sheets of all 67 full pages, full-resolution crops of the changed parts) | defects found and fixed above; final set clean |
| Security headers on the production console | `curl -sI http://127.0.0.1:3000/login`; smoke "security headers" checks | nonce CSP (`script-src 'self' 'nonce-…' 'strict-dynamic'`, no `unsafe-eval`), nosniff, no-referrer, `X-Frame-Options: DENY`; smoke PASS |
| No XSS sinks / browser credentials | repo root: `uv run pytest tests/security/test_security_frontend_static.py -q` | 26 passed (final tree) |
| No secrets or server config in the client bundle | `grep -rIl` over `.next/static` for EXTORQ_API_TOKEN, EXTORQ_SESSION_SECRET, EXTORQ_ANALYST_PASSWORD_FILE, NEXT_PUBLIC, clickhouse, Bearer, api_service_token, frontend_session_secret, 127.0.0.1:8000, /api/v1/ | 0 files each (final build) |
| Final screenshots published | `frontend/docs/screenshots/` (gitignored PNGs) + regenerated `README.md` | 144 PNGs (73 views: 1440x900 first screen + full page; 1024x768 + full at 1024 px), 34 MB; previous PNGs moved to the scratchpad (`ui5/old-docs-shots/`), not deleted |

## Not verified
- The real retired state on the live API: the mechanics-test GitHub assets and the two stopped
  collectors retire at 2026-11-22 15:01:41 UTC (API-DATA), after these captures. Until then the
  Overview/Assets/Health show them as stale and the GitHub class as degraded (honest transitional
  state, also in the screenshots). UI-4b verified the retired rendering against a synthetic proxy;
  UI-5's only change there is the `#retired-assets` anchor of the Overview link (not rendered yet).
- Live "Generate overview" (spends Gemini budget) and live analyst status changes (write audit
  records on demo alerts): not clicked. Server actions unchanged; smoke replays the forged viewer form.
- Browsers other than headless Chrome; screen readers (semantics reviewed in code only).

## Notes for others
- Recapture after 15:02 UTC to show the demo-day state (GitHub healthy, retired section):
  commands in `frontend/docs/screenshots/README.md`.
- `scripts/screenshots.mjs --audit` and its console/CSP report make a capture a cheap regression
  check; `--clicks`, `--hover`, `--focus` drive sheets and hover cards.

## Blockers
- None.
