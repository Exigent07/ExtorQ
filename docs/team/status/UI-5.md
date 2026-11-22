# UI-5 status: integration + visual QA (owns frontend/**)

Last updated: 2026-11-22 08:15 UTC (M0-M2 done, M3 in progress)

## Goal
Integrate the page agents' work into one consistent premium dark console (frontend/DESIGN.md),
resolve the shared-component requests in UI-1..UI-4 status files, finish UI-4's unfinished
Assets / asset detail / service detail work, delete dead components, rebuild the compose console
(port 3000), screenshot every page (1440x900 + full page, one 1024 px check), read every PNG and
fix what looks broken; lint / typecheck / test / build / smoke green at the end.

## Baseline (07:47 UTC, before any UI-5 change)
| Check | Command (in frontend/) | Result |
|---|---|---|
| typecheck | `pnpm typecheck` | exit 0 |
| lint | `pnpm lint` | exit 0 |
| unit tests | `pnpm test` | 132 passed, 0 failed |

## Milestones
- [x] M0 read AGENTS.md, frontend/AGENTS.md, PLAN.md, DESIGN.md, UI-1..UI-4 status, screenshots; baseline
      screenshots of every route on the dev server (scratchpad r0/)
- [x] M1 API contract refresh: `pnpm gen:api`; zod lifecycle fields (asset lifecycle_state / last_observed_at /
      lifecycle_reason, retired_excluded, assets_retired, collectors_retired, collector self_test,
      overview lifecycle); `include_retired` on overview / assets / health; `src/lib/lifecycle.ts` +
      LifecycleBadge; Assets `?retired=1` toggle + stale/retired notice; Overview retired note; Health
      retired toggle + Self-test badge
- [x] M2 shared component fixes requested by UI-2/UI-3: DetailSheet width / ScrollArea block / focus /
      single minmax track (detections + investigation sheets now use it); DataTable portal-click guard +
      exported FacetFilter; TimeHint moved into console `RelativeTime` (tooltip, `plain` in links);
      summary refusal reason (cooldown vs daily cap); UntrustedText `wrap-anywhere` (the old
      `break-words [overflow-wrap:anywhere]` pair lost to `break-words`, so long ids widened sheets);
      breadcrumbs name the object (service: asset > name; investigation: rule > alert)
- [ ] M3 finish Assets / asset detail / service detail (UI-4 stopped after M2)
- [ ] M4 consistency pass + dead component removal
- [ ] M5 compose console rebuilt; screenshots of every page read and iterated
- [ ] M6 lint / typecheck / test / build / smoke green; final screenshots listed

## Found and fixed on the way
- Dev server reload loop (every page re-requested ~4x/s, 4 API reads each): a stale `.next/dev`
  cache from 2026-11-21 made Turbopack's HMR answer "HMR hash mismatch" forever. Deleted
  `.next/dev` (dev output only); not a production issue.

## Verified
(in progress)

## Not verified
(none yet)

## Blockers
- None.
