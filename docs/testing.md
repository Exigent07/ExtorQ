# Testing

Owner: agent F. Strategy for every test layer and a results log that contains
**only results that were actually produced**: each row names the exact command,
when it ran, its outcome and who recorded it. Owners record their runs in
`docs/team/status/<agent>.md`; rows marked "F" were run by F. Anything not
listed in section 3 or 4 has not been verified; section 5 lists the known gaps
explicitly.

## 1. Strategy

| Layer | Location | Runs without the stack | Purpose | Owner |
|---|---|---|---|---|
| Unit | `tests/unit/<area>/` | yes | parsers from real, scrubbed fixtures; normalisation; contracts; API with fakes at the repository boundary | per area |
| Rules | `tests/rules/`, `rules/<platform>/tests/<ID>/*.jsonl` | needs Docker (ephemeral ClickHouse `extorq-c2-*`) | every rule has positive and negative fixtures; engine properties (idempotent re-runs, late evidence, dedup, catch-up) | C2 |
| Integration | `tests/integration/` (marker `integration`) | no: compose stack (and the debug proxy) | gateway round trip, 401/403 + `ingest_audit`, RBAC, API SQL and Grafana panels on ClickHouse, live API and Grafana | A, D1, F |
| Failure | `tests/failure/` (marker `failure`, serial, platform owner only) | no: stops and starts shared services | ClickHouse outage, gateway and writer restarts during delivery | A |
| Lab | marker `lab` (declared in `pyproject.toml`) | no | no pytest test carries it; live lab verification uses the owners' read-only checkers (`python -m extorq_collectors.linux.verify`, `python -m extorq_collectors.kubernetes.verify`, `simulations/lib/verify_scenario.py`, `simulations/github/verify_gh001.py`) | B1, B2, C1, C2 |
| AI | `tests/unit/ai/`, `tests/ai/`, `eval/` (live calls only with marker `live_ai` and a granted budget) | yes, except `live_ai` and the throwaway-ClickHouse store test | prompt-injection defences, evidence-id verification, budgets, evaluation harness | E |
| Security | `tests/security/` | yes (Docker for gitleaks); live RBAC is `integration` | invariants from AGENTS.md section 3 | F |
| Frontend | `frontend/` (`pnpm lint`, `pnpm typecheck`, `pnpm test`, `node scripts/smoke.mjs`) | unit yes; smoke needs a running console | sanitiser, sessions, CSP, API client, every view end to end | D2 |

Defaults: `uv run pytest -q` (`make test`) runs everything except the
`integration`, `lab`, `live_ai` and `failure` markers (`pyproject.toml`
`addopts`), including the rule harness (Docker). Select a marker explicitly, for
example `uv run pytest -m integration tests/security -q`. CI
(`.github/workflows/ci.yml`) runs ruff, mypy, the default pytest selection, the
frontend lint/typecheck/build, gitleaks over the full history and Trivy
filesystem scans.

Fixture policy: fixtures come from real tool output, scrubbed of secrets and
personal data; synthetic fixtures are labelled synthetic in their file name or
content; no committed file contains a secret-shaped value (enforced by
gitleaks; synthetic secrets are built at runtime). Unit tests never call
external services; AI unit tests never call providers.

## 2. Security test suite (`tests/security/`)

| File | What it enforces |
|---|---|
| `test_security_repo_hygiene.py` | `.env`, `var/`, keys, tokens, kubeconfigs are gitignored and not committable; `.dockerignore` excludes secrets |
| `test_security_secret_scan.py` | gitleaks (pinned image, `--redact`, network-less container) over committable files and git history, with a positive control |
| `test_security_python_static.py` | no shell execution, no SQL built from dynamic strings (AST), no `eval`/unsafe deserialisation, TLS verification never disabled; reviewed exceptions need an owner pragma |
| `test_security_frontend_static.py` | no raw-HTML sinks, no browser credentials, no secret `NEXT_PUBLIC_*`; ESLint config bans `dangerouslySetInnerHTML` |
| `test_security_containers.py` | loopback-only ports, ClickHouse unpublished except the debug profile, internal data network, non-root and hardened services, pinned images, AI keys only where needed |
| `test_security_ci.py` | least-privilege workflow permissions, SHA-pinned actions, no script injection |
| `test_security_lab_boundaries.py` | Kubernetes RBAC without secrets or write verbs, workload hardening, audit policy, kind and QEMU bind loopback |
| `test_security_rule_sql.py` | rule SQL is a single parameterised read-only statement over allowed tables |
| `test_security_api_authz.py` | every analyst API route requires the principal; mutations require `analyst` |
| `test_security_prompt_injection_corpus.py` | 47-case synthetic injection corpus (`tests/security/fixtures/`, reused by E) and the gateway sanitiser contract |
| `test_security_ingest_redaction.py` | runtime-generated canary secrets in every free-text field of all nine record kinds never reach the spool payload or quarantine excerpts |
| `test_security_service_adapters.py` | adapters declare `never_collects` with per-category minimums; planned adapters stay silent and never "monitored"; ports never identify products; discovery needs evidence; lab log formats do not log query strings, bodies, cookies or Authorization |
| `test_security_adapter_canaries.py` | implemented HTTP adapters (nginx access/error, Apache, lab portal) strip secrets in query strings and Referer values from emitted events |
| `test_security_service_identity_binding.py` | correctly derived service records are accepted; a service carrying another asset's `service_id` and an instance with an underived `instance_id` are quarantined as `identity_mismatch` (F-19 gateway part; the former `xfail` markers were removed on 2026-11-22) |
| `test_security_clickhouse_rbac_live.py` (`integration`) | each ClickHouse identity is denied outside PLAN 4.4 (zero-row probes only) |

## 3. Results log

### 3.1 Whole repository

| When | Command | Result | Recorded by |
|---|---|---|---|
| 2026-11-22 (session 3 brief) | `uv run pytest -q` | 1738 passed | lead |
| 2026-11-22 (session 3 brief) | `uv run mypy` | clean | lead |

### 3.2 Security (F)

| When (IST) | Command | Result |
|---|---|---|
| 2026-11-22 ~01:39 | `uv run pytest tests/security -q -rxXs` (baseline) | 294 passed, 2 xpassed (F-19 identity binding), 32 deselected, 2 warnings |
| 2026-11-22 ~01:42 | `uv run pytest tests/security/test_security_service_identity_binding.py -q` (markers removed, quarantine reason asserted) | 3 passed |
| 2026-11-22 ~01:46 | `uv run pytest tests/security -q -rxXs` | 1 failed (gitleaks: a secret-shaped literal in A's in-progress `tests/unit/platform/test_platform_gateway.py`), 295 passed; A changed the literal to be built at runtime one minute later |
| 2026-11-22 01:48 | `uv run pytest tests/security -q -rxXs` | **296 passed**, 32 deselected, 2 warnings (api and ai-worker root filesystems writable; posture-lab workload deliberately weak) |
| 2026-11-22 01:49 | `uv run pytest tests/security/test_security_clickhouse_rbac_live.py -m integration -q` | **32 passed** |
| 2026-11-22 01:59 | `uv run pytest tests/security/test_security_secret_scan.py -q` after replacing the F-22 working-tree allowlist entry by a history-only entry (commit `4ee5baa` AND path) | 3 passed. Controls with the pinned gitleaks image: history without any F-22 entry -> 1 finding (`tests/unit/ai/test_ai_sanitize.py:75`, commit `4ee5baa`); history with the new entry -> 0; the old literal re-introduced in a working-tree copy of the same path -> 1 finding (no longer hidden) |
| 2026-11-22 02:03 | `uv run pytest tests/security -q -rxXs`; `uv run ruff check tests/security`; `uv run ruff format --check tests/security` | **296 passed**, 32 deselected, 2 warnings; all checks passed; 18 files already formatted |
| 2026-11-22 02:05 | `uv run pytest tests/security/test_security_secret_scan.py -q` after removing the obsolete F-24 `square-access-token` allowlist entry (B3's minimised fixtures no longer contain the label; never in history) | 3 passed |
| 2026-11-22 02:08 | `uv run pytest tests/security -q -rxXs` and `uv run pytest tests/security/test_security_clickhouse_rbac_live.py -m integration -q` (final runs of the session) | **296 passed**, 32 deselected, 2 warnings; live RBAC **32 passed** |
| 2026-11-21 20:35 | `uv run pytest tests/security -q` (end of session 2) | 294 passed, 2 xfailed, 32 deselected |
| 2026-11-21 20:24 | `uv run pytest tests/security/test_security_adapter_canaries.py -q` | 4 passed |

### 3.3 Unit and rule suites (latest run recorded by each owner)

| Area | Command | Result | Recorded by |
|---|---|---|---|
| Platform (common, rows, gateway, writer/spool, SDK, bootstrap, migrate, CLI) | `uv run pytest tests/unit/platform -q` | 139 passed (session 2); 182 passed in A's latest session-3 record (work in progress) | A |
| Linux collector | `uv run pytest tests/unit/linux -q` | 113 passed | B1 |
| Kubernetes | `uv run pytest tests/unit/kubernetes -q` | 122 passed | B2 |
| macOS collector | `uv run pytest tests/unit/macos -q` | 103 passed | B3 |
| GitHub collector | `uv run pytest tests/unit/github -q` | 176 passed | C1 |
| Rules, detection, correlation | `uv run pytest tests/rules tests/unit/detection tests/unit/correlation -q` | 148 passed (ephemeral ClickHouse removed afterwards) | C2 |
| Simulation verification tooling | `uv run pytest tests/rules/test_simulation_verify.py -q` | 5 passed | C2 |
| Scanners | `uv run pytest tests/unit/scanners -q` | 159 passed, 5 skipped (0005-only checks on the 0003 variant) | C3 |
| Analyst API and Grafana generator | `uv run pytest tests/unit/api -q` | 201 passed | D1 |
| AI (unit, adversarial, evaluation) | `uv run pytest tests/unit/ai tests/ai -q` | 278 passed, 3 deselected (`live_ai`) | E |
| AI storage on a real ClickHouse 26.8.42.13 | `uv run pytest tests/ai/test_ai_store_clickhouse.py -q` | 6 passed (throwaway `extorq-e-store-ch` removed) | E |
| Console | `pnpm lint`; `pnpm gen:api && pnpm typecheck`; `pnpm test`; `pnpm build` (in `frontend/`) | 0 problems; passes; 61 passed; passes | D2 |

### 3.4 Integration and live checks

| Check | Command | Result | Recorded by |
|---|---|---|---|
| Gateway round trip, dedup/replay counts, 401/403 audit, RBAC matrix, default user, profiles, F-19 on the deployed gateway | `uv run pytest -q -m integration tests/integration/platform` | 26 passed (session 2); 29 passed in session 3 (new: a 91-day-old event is quarantined as `older_than_retention` and absent from `events`, an 89-day-old one is stored; JSON booleans survive redaction; status reports the window) | A |
| HTTPS ingest to ClickHouse | `uv run python scripts/smoke_ingest.py` | HTTP 202, accepted 1, read back as `extorq_api_ro` | A |
| SDK end to end through the real gateway | `make sdk-selftest` | exit 0; `collector_health` row for `sdk-heartbeat-example` | A |
| All API SQL on throwaway ClickHouse (real 0001-0004 and 0002 roles) | `uv run pytest tests/integration/api/test_api_sql_clickhouse.py -m integration -q` | 18 passed | D1 |
| All 55 Grafana panel queries as the real `extorq_grafana` role (throwaway ClickHouse) | `uv run pytest tests/integration/api/test_grafana_sql_clickhouse.py -m integration -q` | 58 passed | D1 |
| Live Grafana: datasource, plugin signature, 5 dashboards, every panel query, privileged reads denied | `uv run pytest tests/integration/api/test_grafana_live.py -m integration -q` | 66 passed | D1 |
| Live API on real telemetry, counts consistent with direct SQL | `uv run pytest tests/integration/api/test_api_live.py -m integration -q` | 6 passed | D1 |
| Console end to end on the live store (prod server, every view, viewer read-only, forged viewer state change refused) | `node scripts/smoke.mjs` (in `frontend/`, password files via `EXTORQ_SMOKE_*_PASSWORD_FILE`) | 23 passed, 0 failed (also against a hardened standalone container) | D2 |
| Unauthenticated access is refused | `curl` without credentials to `POST https://127.0.0.1:8443/v1/ingest`, `http://127.0.0.1:8000/api/v1/alerts`, Grafana's API; `127.0.0.1:8123` | 401, 401, 401; ClickHouse port not listening (2026-11-22 ~01:44 IST) | F |
| Console requires a session and sends security headers | `curl` to `http://127.0.0.1:3000/assets` and `/login` | 303 to `/login?next=%2Fassets`; nonce-based CSP, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `nosniff` (2026-11-22 ~02:05 IST) | F |
| Demo readiness report (A's first version) | `make demo-check` (debug proxy up) | `core platform ready`, migrations 0001-0006; linux, macOS and k8s-inventory collectors stale since 2026-11-21 ~15:20 UTC (not running at that moment) (2026-11-22 ~01:43 IST) | F |
| Demo readiness report (A's session-3 version, incl. scenario checks) | `make demo-check` | 02:01 IST: NOT READY, API `/api/v1/health` 503 and ClickHouse unreachable because the `extorq_api_ro` quota was exhausted (`queries = 1374/1200` per minute, right after two console smoke runs by F); 02:02 IST: **DEMO READY: all checks passed** (warnings: debug proxy running; inventory token ~18.1 h left); VM-001, VM-002, K8S-001, K8S-002, GH-001 alerts with all evidence stored; four host collectors fresh | F |
| Console through compose (127.0.0.1:3000) | `node scripts/smoke.mjs --base http://127.0.0.1:3000` (in `frontend/`, D2's script as of 02:00 IST) | 2026-11-22 02:01 IST: 98 passed, 5 failed; the 5 failing checks (Kubernetes node "workloads on node" view and links, detections rule and asset filters) were added in D2's uncommitted session-3 script, and the running image (built 01:56 IST) predates D2's latest source changes | F |
| Audit policy guarantees on the real kind audit log | `infra/kind/kind.sh audit-check` | 2,579 lines, no violations; negative control reported both bad lines | B2 |
| Pods reach the gateway with TLS verified | `infra/kind/kind.sh netcheck` | `GET /healthz -> HTTP 200 (TLS verified with ExtorQ CA)` | B2 |
| VM dispatcher denies everything outside its allow-list | ssh with the collector key: `cat /etc/shadow`, `journal - 99999`, `id; cat /etc/shadow`, `-tt` | `denied`, exit 77; PTY refused; live `dispatch.denied` event in ClickHouse | B1 |
| `extorq_ai` least privilege | `INSERT INTO extorq.alerts` and `SELECT count() FROM extorq.events` as `extorq_ai` | both ACCESS_DENIED | E |

### 3.5 Failure and restart behaviour

| Check | Command | Result | Recorded by |
|---|---|---|---|
| ClickHouse outage | `uv run pytest -q -m failure tests/failure -s` (2026-11-21 14:58-14:59 UTC, announced) | ClickHouse stopped 9.1 s, the gateway kept answering 202, 100/100 buffered events delivered after the restart | A |
| Gateway and writer restarts during delivery | same run | 800/800 records of a paced collector stream delivered, 800 rows, 2 transient ConnectErrors retried by the SDK | A |
| Linux collector restart | SIGTERM, `uv run extorq-collect run --once`, ClickHouse counts | 5283 -> 5295 unique events equal to rows; 0 re-ingested ids; journald resumed after the checkpoint; audit offset advanced | B1 |
| OTel collector restart | delete the collector Pod during marker traffic | each marker exactly one row; "Resuming from previously known offset(s)"; 0 duplicates | B2 |
| Scanner outbox during a gateway outage | gitleaks with an unreachable gateway URL, then `uv run extorq-scan flush` | 4 records buffered (exit 5), then delivered 4 (exit 0) | C3 |
| Failed scan never resolves findings | Trivy forced out of memory, then a normal run | 38 findings `unverified` (0 resolved), then `open` again | C3 |
| Late-arriving telemetry | `uv run pytest tests/rules -q -k late_arriving`; live `uv run extorq detector --once` | 0 alerts without catch-up, 1 with, idempotent; live: VM-001 run `c7cbc976ecaf` ingested ~26 min late was alerted, no duplicate alerts | C2 |

### 3.6 AI (live, within granted budgets)

| Check | Command | Result | Recorded by |
|---|---|---|---|
| Jev smoke (SYNTHETIC context) | `EXTORQ_AI_LIVE=1 uv run pytest tests/ai/test_ai_live.py::test_jev_live_smoke -m live_ai -s` | ok, `jev-1.14.0`, 515 ms | E |
| Jev evaluation (27 SYNTHETIC cases) | `uv run extorq ai eval --live --max-calls 27 --date 2026-11-21` | Jev 77.8% (21/27) versus baseline 44.4% (12/27); latency mean 309 ms | E |
| Gemini smoke (SYNTHETIC context, `summary-v2`) | `EXTORQ_AI_LIVE=1 uv run pytest tests/ai/test_ai_live.py::test_gemini_live_smoke -m live_ai -s` | ok, `gemini-3.6-flash`, 23.0 s, 37 ids cited, 37 verified, 0 rejected | E |
| Gemini prompt injection | `... test_gemini_live_prompt_injection` | ok, 52.3 s, injection not followed, canary absent, no fake id | E |
| Jev on real contexts | `EXTORQ_JEV_ENABLED=true EXTORQ_AI_WORKER_BATCH_SIZE=2 EXTORQ_INSTANCE_NAME=ai-worker-hostrun uv run extorq ai-worker --once` | 2 calls on real K8S-002 contexts, both ok (483 / 336 ms), `priority_investigation`, `uncertain` | E |
| Jev on real alerts after the projection fix (session 3) | E's live run; rows read back by F from `extorq.ai_assessments` as `extorq_api_ro` (2026-11-22 ~02:07 IST) | 17 assessments, question set `triage-v2`, all `ok`, 284-461 ms (2026-11-21 20:32 UTC): VM-001 (2), VM-002 and GH-001 `priority_investigation` (VM-002, GH-001 and one VM-001 not uncertain); K8S-002 (8) all `priority_investigation`, uncertain; K8S-001 (4) 2 `priority_investigation` and 2 `routine_review`, all uncertain; CORR-002 `routine_review`, uncertain | E (run), F (read-back) |
| Gemini on real alerts (session 3) | same read-back | `summary-v3`, `gemini-3.6-flash`: GH-001 `e7063925...` 22.9 s, 17 evidence ids cited / 17 verified / 0 rejected; CORR-002 `b46da380...` 25.9 s, 64 / 64 / 0; schema valid, 0 statements without evidence | E (run), F (read-back) |

## 4. Scenario verification (genuine telemetry)

Each scenario was run against the lab assets, collected through the normal
pipeline and checked with
`uv run python simulations/lib/verify_scenario.py <run_id> --expect <RULE>` (exit
0 = expected alert present, evidence from authenticated producers,
`synthetic-labelled: 0`), recorded by C2 unless noted. Alert ids were read back
by F on 2026-11-22 (~01:43 IST, `extorq_api_ro`).

| Scenario | Run id | Alert id | Severity / confidence |
|---|---|---|---|
| VM-001 | `bace7dc4a3d2` | `7763c537f998a058fb4ca13926dec7da` | medium / medium (shared NAT `10.0.2.2`) |
| VM-001 (late data) | `c7cbc976ecaf` | `76fec91ab730250b5e7d12cdffb071d5` | medium / medium |
| VM-002 | `b7a712bc786d` | `5ac7d8f5a069eabf1f0468397d9327a9` | high / high (auditd + inventory) |
| K8S-001 | `bcfcb726ff01` | `cfbff55664cf6d62121a96e4cbe6692a` | medium / high |
| K8S-002 | `c9c96ff29f33` | `afc76864b4200260d47959111b0fdf01` | high / high (audit + state) |
| GH-001 (verified end to end by the lead, commit `0b88fe5`) | `8dwz3wf6zji4` | `e70639259d3044a6da955d9bc79e48cd` | high / high; baseline and cleanup commits: no alert |
| HTTP-001 | `8c8e999442ed`, `fff5113314b3` | `469374702a500e83756c08a1bf3054ce`, `ffd77b50cfba0afb3d0cd053f6cf0ea6` | low / medium |
| APP-001 | `8c8e999442ed`, `fff5113314b3` | `a94ee8dd2ab946a71245f2b43caeb4b8`, `a7dc2bc48ca86ea04e63892615ca08f7` | medium / medium |
| MAC-001 | `51ff258a3b7d` | `fe5a072442b438711726ed51a5597bfd` | medium / high |
| CORR-002 | B1's runs above | `b46da3805d1c6f17b6c1ed363b49a777` | high / low (all stages via `10.0.2.2`; never causation) |

Simulation telemetry counts recorded by the producers: VM-001 `bace7dc4a3d2`
invalid_user 9, preauth_closed 8, max_auth_exceeded 2; VM-002 `b7a712bc786d`
unit_created 1, unit_enabled 1, file.audit.watch 2, sudo 2 (and the cleanup's
unit_deleted 1, service.removed 1); HTTP-001 `8c8e999442ed` 11 `http.request`,
5 `app.auth.login_failed`, 1 `app.authz.denied` (B1); K8S-001 audit 403 with
PSA `baseline:latest` violation; K8S-002 audit 201 plus inventory
`k8s.resource.created`, cleanup verified (B2); MAC-001 item created and deleted,
plist verified absent (B3).

## 5. Not verified

State as of 2026-11-22 02:05 IST.


* CI on GitHub itself (no push; actions pinned to SHAs resolved with `gh api`).
* A clean checkout: `tests/unit/macos` reads fixtures that are currently
  untracked (`tests/fixtures/macos/services/`, `.../launchd/apple/`, two `dscl`
  files) while B3 minimises them (PLAN 11, F-24); until they are committed a
  fresh clone, and therefore CI, cannot pass those tests.
* The compose console end to end with the final image: A started `frontend`
  and `ai-worker` around 01:56 IST and `make demo-check` passed at 02:02, but
  D2's latest smoke still had 5 failing (new) checks against that image.
* The compose `ai-worker` with Jev enabled (`make up-demo`) and the compose
  `api` with Gemini enabled: not exercised (no budget for F).
* AI on real data beyond the stored records: Jev accuracy on real alerts is
  unmeasured (no labels), and only two real alerts have Gemini summaries
  (section 3.6). The two session-2 real-context Jev assessments were made with
  a projection that dropped evidence key fields (fixed by E in session 3).
* Secret rotation (`make rotate`, `make rotate-apply`).
* The failure suite after the session-3 changes (run once, by A, on 2026-11-21).
* Live source gap events (journald vacuum, audit log rotation past the offset):
  unit tests only (B1).
* The Apache adapter on a running Apache (none in the lab), and macOS Remote
  Login / Screen Sharing enabled (left off on purpose): unit tests only.
* Grafana rendering in a browser (panels verified through the query API).
* Analyst mutations (`POST .../state`, `POST .../summary`) against the live stack
  (covered with fakes and a throwaway ClickHouse).
* `infra/kind/kind.sh up` from scratch since session 1, and `kind.sh down`.
* End-to-end alert latency (simulation to alert): not measured.
* Pytest marker `lab`: declared, no tests use it (see section 1).
