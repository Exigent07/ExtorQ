# UI-3 status: investigation page (frontend)

Owner scope: `frontend/src/app/(console)/investigations/**`, `frontend/src/components/views/investigation/**`.
Shared files (`src/components/console`, `src/components/ui`, `src/lib/**`, `scripts/**`) are read-only for UI-3;
requests for shared changes are listed under "Requests to shared owners".

Last updated: 2026-11-22 07:50 UTC (all milestones done; final checks green on the final code)

## Goal
Rebuild `/investigations/[alertId]` as a premium detail layout per `frontend/DESIGN.md`: header card,
Tabs (Overview, Timeline, Evidence, Correlation, AI, Context), right rail (analyst status, key facts,
activity log). Usable for the five mandatory alerts and CORR-002; screenshots of each.

## Milestones
- [x] M0 read AGENTS.md, frontend/AGENTS.md, PLAN.md, DESIGN.md, UI-1 status, baseline screenshots,
      current investigation code, smoke markers; real data shapes of the six demo alerts (read-only API
      calls, paced, cached in the scratchpad)
- [x] M1 page: header card, shadcn Tabs (all panels server-rendered and kept mounted, `?tab=` in the
      address via history.replaceState, no API call on tab switch), right rail
- [x] M2 Overview + Context tabs
- [x] M3 Timeline (activity strip, bursts, relationship hover cards, NAT caveat) + Correlation tabs
- [x] M4 Evidence tab (view-local TanStack table, detail sheet, `#evidence-<id>` anchors, reveal)
- [x] M5 AI tab (Jev meter/answers, Gemini sections + evidence chips, Generate overview states)
- [x] M6 loading skeleton, phone layout (390 px), viewer role (read-only header + rail)
- [x] M7 screenshots of the six alerts read and iterated (3 rounds), CDP interaction probe green
- [x] M8 final lint / typecheck / test / build / smoke on the final code (see Verified)

## What changed (files)
- `src/app/(console)/investigations/[alertId]/page.tsx`: three API reads in parallel (unchanged
  contract), header card, tabs, rail; per-block errors; `Freshness` reported.
- `src/app/(console)/investigations/[alertId]/loading.tsx`: skeleton of the new layout.
- `src/components/views/investigation/`: `model.ts` (pure rules, 23 unit tests in
  `investigation-model.test.ts`), `labels.ts`, `ai-labels.ts` (kept `questionTypeLabel`, used by
  `src/lib/__tests__/views.test.ts`), `marks.tsx`, `feature-value.tsx` (FeatureTable: scalars in two
  balanced columns, lists as chips, never JSON text), `more-chips.tsx`, `investigation-tabs.tsx`,
  `header-card.tsx`, `status-controls.tsx` (header picker + rail form on the existing server action;
  shadcn Select/Textarea; hidden `status` input keeps the no-JS post and the smoke replay working),
  `overview-panel.tsx`, `timeline-panel.tsx`, `activity-strip.tsx`, `burst-rows.tsx`,
  `relationship.tsx`, `evidence-panel.tsx`, `evidence-table.tsx`, `evidence-sheet.tsx`,
  `correlation-panel.tsx`, `correlation-table.tsx` (shared DataTable), `ai-panel.tsx`,
  `summary-request.tsx`, `context-panel.tsx`, `rail.tsx`.
- Removed (only the old page imported them): `context-sections.tsx`, `gemini-panel.tsx`,
  `jev-panel.tsx`, `state-control.tsx`, `timeline.tsx`.

## Demo alerts (docs/demo-runbook.md)
VM-001 `7763c537f998a058fb4ca13926dec7da`, VM-002 `5ac7d8f5a069eabf1f0468397d9327a9`,
K8S-001 `cfbff55664cf6d62121a96e4cbe6692a`, K8S-002 `afc76864b4200260d47959111b0fdf01`,
GH-001 `e70639259d3044a6da955d9bc79e48cd`, CORR-002 `b46da3805d1c6f17b6c1ed363b49a777`.

## Verified (commands run in `frontend/` unless noted; results observed)
| Claim | Command | Result |
|---|---|---|
| Model rules | `node --conditions=react-server --import tsx --test src/components/views/investigation/investigation-model.test.ts` | 23/23 pass |
| Unit tests (repo, final code) | `pnpm test` | 132 passed, 0 failed |
| Lint (final code) | `pnpm lint` | exit 0 |
| Types + contract check (final code) | `pnpm typecheck` | exit 0 |
| Static frontend security (F) | repo root: `uv run pytest tests/security/test_security_frontend_static.py -q` | 26 passed |
| Production build (final code) | isolated APFS clone of `frontend/` in the scratchpad (another agent serves its own in-place build on 3101, so no in-place build): `pnpm build` | exit 0, all 10 routes + proxy (clone removed afterwards) |
| End to end on that build over the compose API | `next start` on 127.0.0.1:3102 + `EXTORQ_SMOKE_ALERTS=VM-001=7763…,VM-002=5ac7…,K8S-001=cfbf…,K8S-002=afc7…,GH-001=e706… EXTORQ_SMOKE_ANALYST_PASSWORD_FILE=… EXTORQ_SMOKE_VIEWER_PASSWORD_FILE=… node scripts/smoke.mjs --base http://127.0.0.1:3102` | run 1 and final run (07:43 UTC, final code): 100 passed, 0 failed (all investigation markers for the five rules, viewer read-only page, forged viewer state change refused) |
| No console errors / CSP violations | scratchpad CDP probe (headless Chrome, real login) on the production build: tabs, hover card, Gemini chip jump, sheet open | "no console errors, warnings or exceptions" |
| Interactions | same probe on dev + prod | tab click updates `?tab=`; back/forward restores the tab; Gemini chip on CORR-002 jumps to its evidence row on page 3 of 3 (row highlighted, focused, in view); shared `#evidence-<id>` link opens the row; row click opens the 672 px sheet with focus on Close; Escape closes it and focus returns to the row trigger; bursts expand; correlation paging; no horizontal page scroll at 1440 |
| Screenshots read | `scripts/screenshots.mjs` on the dev server (1440 full pages per tab for VM-001, CORR-002, GH-001, K8S-002; viewer VM-002; 390 px K8S-001; final first screens of all six alerts) | iterated 3 rounds; scratchpad `ui3/shots/` (rounds) and `ui3/final/` (final set) |

## Not verified
- The compose console (3000) runs an older image; redeploying it is owned by A.
- Live "Generate overview" (it spends Gemini budget) and live status changes (they write audit records
  on demo alerts): not clicked. Both use the unchanged server actions; the smoke test's forged viewer
  replay of the status form passed.
- Unverified Gemini evidence ids: no stored overview contains one (GH-001 17/17, CORR-002 64/64
  verified); the chip classification is unit-tested and the shared EvidenceChip renders them.
- Screen readers (semantics reviewed in code only); browsers other than headless Chrome.

## Requests to shared owners
1. `src/components/console/detail-sheet.tsx` (UI-1): the sheet renders 384 px wide because its
   `sm:max-w-xl/2xl` loses to the base sheet's `data-[side=right]:sm:max-w-sm` (use
   `data-[side=right]:sm:max-w-2xl`), and the Radix ScrollArea's `display: table` wrapper lets long
   values overflow sideways (measured scrollWidth 574 vs 383). The investigation uses a view-local sheet
   on the shadcn Sheet primitives (`evidence-table.tsx`) until this is fixed.
2. `src/components/console/data-table.tsx` (UI-1): optional row props (anchor `id`, `onClick`),
   a controlled pagination or "reveal row" API, and an exported `FacetFilter`, so tables whose rows are
   jump targets (evidence) can use it. The evidence table is view-local for now.
3. `src/app/(console)/actions.ts` (D2): `requestSummaryAction` could return the refusal reason of a
   `budget_exceeded` result (`assessment.error`: per-alert cooldown with seconds vs daily cap) so the
   console can say which; it currently says "cooldown active or daily cap reached".
4. `src/components/views/services/service-badges.tsx` (services owner): its comment still mentions the
   removed `views/investigation/context-sections.tsx` (comment only, no import).
5. `frontend/docs/screenshots/02-investigation-gh-001.png` and `03-investigation-vm-002.png` show the
   old layout; replacements are in the scratchpad (`ui3/final/`), for the screenshot owner to copy.

## Blockers
None.
