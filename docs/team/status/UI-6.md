# UI-6 status: final polish (owns frontend/**)

Last updated: 2026-11-22 14:40 UTC (M0-M7 done; nothing committed)

## Goal
Fix every blocker and major issue of the independent design critique (overall 6.8/10) plus the
cheap minor ones; re-screenshot and read the PNGs; rebuild + recreate the compose console; lint /
typecheck / test / build / paced smoke against 3000 green; DESIGN.md + AGENTS.md updated;
frontend/docs/screenshots refreshed. The task text cut the critique at 9000 characters; the full
JSON (18 pages, 4 blockers) was recovered from the workflow journal into the scratchpad
(`ui6-critique.json`) and worked through in full.

## Milestones
- [x] M0 (13:25 UTC) context, critique, baseline: typecheck exit 0, lint exit 0, test 174 passed;
      dev server 3100 -> compose API 8000
- [x] M1 blockers (13:35 UTC, screenshots r1 read)
  - Gemini disabled: the investigation page reads `/health` (cached 15 s by the API) for the AI
    provider flags; "Generate overview" is disabled with the reason when the API's AI settings
    disable Gemini; "Jev disabled now" / "Gemini disabled now" beside the advisory labels
    (`providerAvailability`, `summaryUnavailableReason` in `views/investigation/model.ts`).
  - Context tab: the card meta counts gaps and missing-telemetry notes together ("1 missing-telemetry
    note" in amber; never "No source gap recorded" over a missing-telemetry notice); with a gap but
    no note it says so; one status pill per source (Stale / Gap in window / health, the rest in the
    hint); lag in sans; "12 evaluation(s)" -> "12 evaluations" (`resolvePlurals`).
  - System health: one status per collector ("Stale" with its last health and the API reason in
    the hint, never "OK" + "Stale"); buffered counts neutral.
  - coredns: the Instances figure, the tab badge and the card meta count the table's rows (2 Pods,
    "2 containers" as sub-label), never Pods + containers as one number (`instanceHeadline`).
- [x] M2 investigation hierarchy (13:50 UTC, r2 read): `views/investigation/signals.ts` (+14 tests):
  Key signals block (CORR-002 stage stepper with gaps, VM-001 threshold checks "9 / 5 Fired",
  "0 / 10 Not met", risk signals in amber such as "SSH login succeeded after the failures:
  extorq-admin", corroboration in neutral); detector features with clear labels; correlation
  features grouped (SSH / HTTP / Application / Host changes / Kubernetes / GitHub / scope), zero
  counters folded (`Disclosure`), duplicates of detector values dropped; feature figures sans,
  rule times through `Timestamp`; "Evaluated span" + "sliding window" labels; header: read-only
  status with "Change" (one control: the rail form, Save disabled until something changed),
  "Shared NAT source 10.0.2.2" chip (NAT notices removed from Timeline and Correlation), First
  seen sub-label relative, Evidence events sub-label = the type mix; rail: duplicates removed,
  Provenance folded, Activity card only once an analyst acted. Timeline: per-lane histogram
  activity strip (60 buckets over the observations, each lane on its own scale), strength as a
  3-dot meter, burst expander inline ("9 ›"). Correlation: compact relationship toggles that
  filter, observations grouped by relationship + strength + event type (88 rows -> 8 groups, each
  opening its members in a sheet), "Every observation" toggle. Evidence: neutral role badge,
  open icon at the row end on hover/focus, wider actor column. AI: chips capped at 3 + "+N more"
  (unverified ids never folded), chip legend, rationale codes in words (code in a hint), neutral
  uncertain band and white knob, "Timeline as summarised" folded. Context: posture findings as a
  severity summary + folded table.
- [x] M3 shared (14:00 UTC): DataTable pager only when it can page; KpiCard figure row centred
  (32px coverage mark), reserved footer slot, one-line sub-labels (`KpiFigures`), proportional
  KPI figures, phones: compact two-column KPI grid; `Fraction` ("15 / 84") everywhere;
  `NotFoundState` (alert / asset / service not found, request id, way back); `Disclosure`;
  palette at 14vh; "Updated" at every width; breadcrumbs name assets by display name (28ch).
- [x] M4 pages (14:05 UTC, r3/r4 + phone + 1024 read): Overview (flat stacked bars with card seams,
  7 d when the 24 h view is sparse, "2 stale GitHub repositories" as the cause, collection health
  values without green dots on zeros and one rule row, no internal view name, unsupported
  coverage zinc-600); Assets (Kubernetes node counted with its cluster on both pages: Overview
  4 / 6 = Assets "4 of 6 monitored assets healthy"; one stale count; two-line stale reasons; "No
  collector"; node titled by its own name); asset overview (attributes full width or in the
  GitHub rail, recent alerts full width, "View 8 open alerts" primary only with open alerts,
  recency instead of four freshness marks, sans figures, no single-colour split bars); asset tabs
  (GitHub: no Services tab; node workloads: one hierarchy line, caveat in the card footer; finding
  titles without doubled prefixes, "2 scanners" mark, scanners instead of the view name; link
  styling); service (declared source without collector health said next to "Monitored", "Last
  service event" with "collectors fresh · service quiet", informative figure sub-labels, facts
  wrap, Events "50+" + notice, authentication card only where it informs, note not repeated);
  Detections (Rules KPI amber "N quiet sources", first-seen line only when it differs, amber
  quiet-source chips, maturity badge); Health (4 KPIs, "(since start)" counter headers, amber
  write errors while OK, all-zero counters named under the table, flat stale segment); Login
  (one quiet line instead of the floating strip, password reveal toggle).
- [x] M5 docs: DESIGN.md (tokens, type rules, gradients, shell, KPI and investigation anatomy,
  components, states, data viz) and frontend/AGENTS.md (smoke coverage, AI flags read,
  investigation display rules, health counters, findings display) match the final system.
- [x] M6 compose console rebuilt + recreated (last at 14:33:20 UTC, image `sha256:e086c3b0…`, after
      two late fixes: recorded values out of signal titles, two KPI sub-labels shortened); lint /
      typecheck / test / build / smoke green on that tree
- [x] M7 (14:36 UTC) final screenshots published: `frontend/docs/screenshots/` 149 PNGs (79 views;
      1440x900 first screens + full pages, 1024 px, 390 px, not-found, evidence sheet) + regenerated
      README.md; the previous set moved to the scratchpad (`ui6/old-docs-shots/`), not deleted

## Verified
| Claim | Command (in `frontend/` unless noted) | Result |
|---|---|---|
| Lint (0 warnings), final tree | `pnpm lint` | exit 0 (14:32 UTC) |
| Types + OpenAPI contract check, final tree | `pnpm typecheck` | exit 0 (14:32 UTC) |
| Unit tests, final tree | `pnpm test` | 199 passed, 0 failed (174 at baseline; +15 `signals.test.ts`, +5 `instanceHeadline`, +3 `findings.test.ts`, +1 node counting, +1 overview cause; window-length cases in `model.test.ts`) |
| Production build, final tree (Node 20.11.1, Tailwind 4.3.3) | `pnpm build` | exit 0, 10 routes + proxy (14:32 UTC); the compose image build (`pnpm build` in Node 22) compiled too |
| Compose console runs the final tree | repo root: `docker compose --profile full build frontend` + `up -d --no-deps frontend` | image `sha256:e086c3b0…` created 14:33:20 UTC; container healthy; strings of the last edits found in its server chunks (`docker exec … grep`); api and the other services untouched |
| End to end against the compose console, final image | `EXTORQ_SMOKE_ALERTS="VM-001=7763c537…,VM-002=5ac7d8f5…,K8S-001=cfbff556…,K8S-002=afc76864…,GH-001=e7063925…" EXTORQ_SMOKE_ANALYST_PASSWORD_FILE=../var/secrets/analyst_password EXTORQ_SMOKE_VIEWER_PASSWORD_FILE=../var/secrets/viewer_password node scripts/smoke.mjs --base http://127.0.0.1:3000` (paced 1500 ms) | 14:33:35-14:34:58 UTC: 103 passed, 0 failed, exit 0 (also 14:10:07-14:11:30 and 14:15:02-14:16:25 on the two previous images: 103/0). A first run (14:06-14:08) failed 1 check: React streamed the end of GH-001's large Gemini card after later sections, so the smoke's slice up to the next h2 stopped early; the page itself was right (captured). The AI-card checks now read the whole page (phrases unique to each card). New checks: "Alert not found" page, ssh service authentication card, GitHub repository has no Services tab |
| No API warnings or errors from this work | repo root: `docker logs --since 60m extorq-api-1` (the API logs warnings and errors only) | 0 lines (no quota exhaustion, storage or unhandled errors across the dev rounds, captures and smoke runs) |
| Final screenshots | `scratchpad/ui6/shoot-final.sh` + `shoot-extra.sh` (`scripts/screenshots.mjs --audit`, paced) against 3000, 14:16-14:36 UTC | 149 PNGs: 0 layout findings, 0 console errors / CSP violations; all first screens read as contact sheets, the changed pages at full resolution. Taken on image `sha256:1227ce60…` (14:14 UTC); the final image `e086c3b0…` differs from it only by two KPI sub-label strings of the asset overview, so those five pages (first screen + full page) were retaken on the final image |
| Security headers | `curl -sI http://127.0.0.1:3000/login` + smoke | nonce CSP (`'strict-dynamic'`, no `unsafe-eval`), `X-Frame-Options: DENY`, `no-referrer`; smoke PASS |
| No XSS sinks / browser credentials | repo root: `uv run pytest tests/security/test_security_frontend_static.py -q` | 26 passed |
| No secrets or server config in the client bundle | `grep -rIl` over `.next/static` for EXTORQ_API_TOKEN, EXTORQ_SESSION_SECRET, EXTORQ_ANALYST_PASSWORD_FILE, NEXT_PUBLIC, clickhouse, Bearer, api_service_token, frontend_session_secret, 127.0.0.1:8000, /api/v1/ | 0 files each |
| Pages read after the changes | `scripts/screenshots.mjs --audit` on the dev server: rounds r1-r4 (blocker pages, all investigation tabs of VM-001/CORR-002/GH-001/K8S-002, overview, assets, VM, node workloads, GitHub findings, ssh, coredns, detections, rules, health, not-found pages), 390 px (overview, VM, VM-001, health), 1024 px (overview, detections, CORR-002, VM-001 correlation) | every capture: no sideways scroll, no text under 12 px, no console errors or CSP violations (dev-only server-log forwarding on the deliberate 404s) |

Scratchpad captures: `/private/tmp/claude-501/-Users-exigent-Development-ExtorQ/5613ba9c-4f02-44a4-90cb-7e9748b9b4aa/scratchpad/ui6/{r1,r2,r3,r4,phone,w1024,final}/`.

## Not verified
- Live "Generate overview" and live analyst status changes (spend Gemini budget / write audit
  records on demo alerts): not clicked. The Gemini button is disabled while the API reports Gemini
  disabled; the server actions are unchanged.
- The retired state of the mechanics-test assets on the live API (they retire at 15:01:41 UTC,
  after this capture): the Overview subtitle then reads "all monitored classes reporting" and the
  Assets page lists them in the collapsed retired section (UI-4b verified that rendering).
- Sidebar collapsed by default below 1280 px (critique minor): not done; the server cannot know the
  viewport and a client-side collapse would shift the layout after hydration.
- "840 critical + high is 95 % one asset" second KPI line (critique minor): needs per-asset
  findings summaries on the Overview (one extra API read per asset); not done.
- Browsers other than headless Chrome; screen readers (semantics reviewed in code only).

## Blockers
- None.
