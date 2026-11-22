# Agent E status (AI engineering: Jev triage, Gemini summaries)

Last update: 2026-11-22 session 3 (scope complete; 20:45 UTC 2026-11-21)

## Session 3 (2026-11-22): review fixes and live demo assessments
Scope: (1) HIGH projection drops all real key_fields, (2) ai-worker poison-head / write-outage
robustness, (3) Gemini HTTP client env hardening, (4) F-22 runtime sample, (5) live Jev triage of
all mandatory + CORR-002 alerts and 2 Gemini summaries (budget: <= 30 Jev, <= 4 Gemini calls),
(6) docs.

Progress log (UTC):
- Baseline measured on the live stack (as `extorq_ai`): 17 alerts in scope (VM-001 x2, VM-002 x1,
  K8S-001 x4, K8S-002 x8, GH-001 x1, CORR-002 x1), all with stored contexts; the session-2
  projection kept **0** evidence key fields for every one of them (C2 keys them by dotted catalog
  path, e.g. `kubernetes.verb`). Compose `ai-worker` container never created; API container runs
  the session-2 image. Live calls used so far this session: Jev 0, Gemini 0.
- (1) DONE: `projection.py` normalises key_fields first (`canonical_key_field`: dotted catalog
  path / flattened / leaf -> one canonical name; event-type resolution for ambiguous leaves),
  then deny-list, allow-list, per-field text limits (request_summary / pod_security_violation
  256) and the per-event cap in catalog order. Also: evidence sampling keeps the first event of
  every event type (CORR-002's HTTP stage was lost to head/tail sampling). Prompt versions bumped
  to `triage-v2` / `summary-v3` (input format changed; v1/v2 rows are never reused). Real
  contexts: 240/240 then 235/235 presented key fields kept (was 0). Fixture
  `tests/fixtures/ai/context_k8s001_real.json` (REAL, unmodified, hash-verified, privacy-reviewed,
  gitleaks clean) + 10 new projection tests.
- (3) DONE: `ai/transport.py` (httpx2 clients: trust_env=False, certifi-only TLS context with
  key logging off, no redirects) injected into google-genai (sync + async + websocket TLS
  context) and typesafe (http_client). 5 offline tests through the real SDK paths.
- (4) DONE: F-22 sample built at runtime; gitleaks without the F-22 allowlist entry: 0 findings
  in the new file (positive control: HEAD copy flagged at line 75).

- (2) DONE: worker pages the queue past unreadable contexts (SQL `exclude` list +
  in-process memory, `ai_worker_max_scan_per_cycle`), counts/reports them (`cycle_invalid_contexts`,
  `invalid_contexts_total`, degraded reason); a paid result whose INSERT fails is cached and only
  the write is retried (exponential backoff base 15 s .. 600 s, jitter), new provider calls pause
  while anything awaits storage, dropped after `ai_worker_write_max_attempts` (12) and never sent
  again in-process; budget `Reservation.persisted_later()` stops double counting. 7 new unit tests
  + 1 new real-ClickHouse test (tampered context at the queue head).

- (5a) DONE (20:32 UTC): real `TriageWorker` cycle from the host (instance `ai-worker-hostrun-s3`,
  identity `extorq_ai`, loader restricted to the 17 in-scope alerts, `EXTORQ_JEV_DAILY_CAP=19` =
  2 persisted today + 17): 17 Jev calls, 17 `ok`, 17 stored (`triage-v2`), 6 out-of-scope skipped,
  health ok. jev-1.14.0; latency mean 323 ms / p50 307 / max 461; 107,321 input / 3,162 output
  tokens. 14 priority_investigation, 3 routine_review; 14 uncertain (borderline context).
- (5b) DONE (20:35 UTC): `extorq ai summary` (= `AIService.request_summary`, api_ro / api_writer):
  GH-001 ok, gemini-3.6-flash, 22,876 ms, 4,906 in / 3,324 out, 17 ids cited / 17 verified / 0
  rejected; CORR-002 ok, 25,870 ms, 16,786 in / 4,236 out, 64 / 64 / 0. Re-requests returned the
  stored rows (no call). Ledger (metadata only): `eval/live/session3-live-2026-11-21.jsonl`.
- Live calls used this session: **Jev 17 / 30, Gemini 2 / 4**.
- Observed: the compose `ai-worker` was (re)created by someone else at 20:26 UTC with Jev
  disabled and a pre-session-3 image (reports `triage-v1`); the `api` container also runs a
  pre-session-3 image. Both need a rebuild to use the session-3 AI code.

- (6) DONE: `docs/ai-integrations.md` updated (transport hardening and residual risk, key-field
  normalisation, sampling, versions, worker robustness, evaluation validity, live record 11.1,
  limitations); `docs/team/interface-changes/E.md` E-IC-6 (cap passthrough) + notes for F, D1,
  B2/C2. Evaluation report now says `n/a` instead of 0 % when no case was answered.
- OUTAGE NOTICE (E, 20:40 UTC): rebuilt `extorq/backend:0.1.0` (`docker compose --profile full
  build ai-worker`) and recreated ONLY `ai-worker` (`up -d --no-deps ai-worker`, with
  `EXTORQ_JEV_ENABLED=false`). Back at 20:40:53 UTC: startup `jev_key=configured`,
  `jev_enabled=false`, health row `disabled`, `prompt_version=triage-v2` with the new
  worker detail fields. Other services were not recreated (note: the shared image tag now
  points to this build of the current tree).

## Session 3 verified (commands and observed results)
| Claim | Command | Result |
|---|---|---|
| Real contexts lost every evidence key field before the fix | scratch script: `project_context(load_latest_context(get_client("ai"), id), JEV_LIMITS)` over the 17 in-scope alerts | before: `kept 0` for all 17; after: 240/240, then 235/235 (type-covering sample) presented key fields kept, `dropped_keys 0`, payloads 10.8-18.1 k chars (Jev), 21-38 k (Gemini) |
| CORR-002 sample covered no HTTP stage before | same, `Counter(event_type)` of presented evidence | before Jev: audit x4, ssh x4 (no http, no systemd); after: one of each of the 8 types (both providers) |
| Fixture is the unmodified stored body and clean | `compute_input_hash(data) == ctx.input_hash`; pattern scan; pinned gitleaks (`--network none`) with `tests/security/gitleaks.toml` | hash ok; 0 home paths / handles / e-mails / LAN IPs / tokens; gitleaks "no leaks found" |
| F-22 fixed | pinned gitleaks on {new test file, fixture, HEAD copy} with the F-22 allowlist block removed | 1 finding, only the HEAD copy (line 75, generic-api-key); new file 0 |
| SDK default honours proxies; injected clients do not | python probe + `tests/unit/ai/test_ai_transport.py` | default httpx2 client mounts `HTTPProxy` for googleapis with `HTTPS_PROXY`; injected: `trust_env False`, no mounts, `follow_redirects False`; real SDK requests hit only `generativelanguage.googleapis.com` / `api.typesafe.ai` under hostile env |
| No TLS key logging for provider traffic | local TLS handshake probe with `SSLKEYLOGFILE` | ExtorQ context: 0 bytes written, untrusted cert rejected; `create_default_context` control: 938 bytes |
| AI suites | `uv run pytest tests/unit/ai tests/ai -q -p no:cacheprovider` | 303 passed, 3 deselected (live_ai) |
| Worker vs real ClickHouse 26.8.42.13 (throwaway `extorq-e-store-ch`, removed) | `uv run pytest tests/ai/test_ai_store_clickhouse.py -q` | 7 passed (incl. tampered context at the queue head, `exclude` paging) ; `docker ps -a --filter name=extorq-e-` empty |
| Neighbouring suites | `uv run pytest tests/unit/ai tests/ai tests/unit/api tests/security -q -p no:cacheprovider` | 817 passed, 35 deselected (incl. gitleaks tree scan, SQL static scan) |
| Whole default suite | `uv run pytest -q -p no:cacheprovider` | 1910 passed, 5 skipped (C3 view tests), 215 deselected, 0 failed |
| Lint / format / types | `uv run ruff check` + `ruff format --check` on E paths; `uv run mypy` | all checks passed; 33 files formatted; mypy no issues in 195 source files |
| Live Jev triage (17 calls) | `EXTORQ_JEV_ENABLED=true EXTORQ_JEV_DAILY_CAP=19 EXTORQ_AI_WORKER_BATCH_SIZE=20 uv run python <scratch>/run_scoped_worker.py` | 17 ok / 17 stored / 6 skipped, health ok; read back as `extorq_api_ro`: 17 `triage-v2` rows |
| Live Gemini summaries (2 calls) | `EXTORQ_GEMINI_ENABLED=true EXTORQ_GEMINI_DAILY_CAP=2 uv run extorq ai summary <id>` | GH-001 and CORR-002 ok, 17/17 and 64/64 ids verified, 0 rejected; re-request reused the stored row; Gemini attempts for the UTC day = 2 |
| Compose ai-worker runs session-3 code | `docker logs extorq-ai-worker-1`; health row as `extorq_api_ro` | `jev_enabled=false`, `jev_key=configured`; `disabled`, `prompt_version=triage-v2`, new detail keys |
| v1 evaluation answers are not reused under v2 | `python -m extorq.ai.evaluation --live --max-calls 0 --date 2026-11-21 --out-dir <scratch copy>` | 27 `not_run`, 0 calls; report now "Jev accuracy n/a" (was "0.0%") |

## Session 3 not verified
- Gemini/Jev behaviour under a real proxy or MITM CA (verified offline with mock transports, a
  local TLS handshake and client inspection only).
- `triage-v2` on the synthetic evaluation set (not re-run; budget went to real alerts).
- The `api` container with session-3 code (not mine to rebuild); console rendering of the new rows.
- Worker write-outage behaviour against a real ClickHouse outage (unit fakes only; the real
  ClickHouse test covers the unreadable-context path).

## Session 3 next / handover
- Lead / D1: rebuild + recreate `api` before analysts request summaries from the console.
- A: E-IC-6 (cap passthrough in compose) if Jev is to be enabled in the `ai-worker` for the demo.
- F: remove the F-22 gitleaks allowlist entry; security.md line on provider transport.
- Optional (6 Jev calls): triage APP-001 x3, HTTP-001 x2, MAC-001 by enabling the worker.

## Done this session (session 2)
- Projection: `services` (alias `svc-N`, name as untrusted text, kind/category/adapter_support/
  monitoring_status validated against contract enums, role, asset_id) and `related_assets`
  (id, type, criticality); evidence events reference services by alias; no service ids,
  attributes, config paths or endpoints reach providers. CORR-002 and Kubernetes nodes mapped
  to their triage domains.
- SDK hardening: Jev `base_url` pinned; Gemini `base_url` pinned, `vertexai=False`,
  `DebugConfig` without record/replay; projection caps derived from settings.
- Literal invisible character in `sanitize.py` replaced by an escape (Trojan Source hygiene, F-03 style).
- Dataset rebuilt with service-aware contexts (Linux services derived from events; K8s workload vs
  Kubernetes Service in K8S-B2); still 27 SYNTHETIC cases.
- Tests: `tests/unit/ai/` (sanitiser, projection, Jev, Gemini, budget/store, service/worker,
  evaluation) and `tests/ai/test_ai_prompt_injection.py` (F's 47-case corpus x every untrusted
  field, compromised-model output). Shared fakes in `tests/unit/ai/ai_fakes.py`.
- `docs/team/interface-changes/E.md` (E-IC-1 compose flags for A; E-IC-2..4 informational).

## Done (code on disk from session 1, re-checked in session 2)
- `backend/src/extorq/ai/`: settings/flags/key resolution, sanitiser, allow-list projection,
  Jev provider (question set triage-v1, deterministic post-processing), Gemini provider
  (system instruction, JSON schema output, evidence-id verification), budgets/cooldowns,
  store, AIService, ai-worker, baseline prioritiser, evaluation harness, synthetic builders.
- `eval/jev/dataset.jsonl` (27 SYNTHETIC cases) + `eval/jev/build_dataset.py`.

## Verified (session 2)
| Claim | Command | Result |
|---|---|---|
| AI unit + adversarial + storage suites pass, lint/format/types clean (final run) | `uv run ruff check backend/src/extorq/ai tests/unit/ai tests/ai eval && uv run ruff format --check <same> && uv run mypy backend/src/extorq/ai && uv run pytest tests/unit/ai tests/ai -q` | all checks passed; 31 files formatted; mypy no issues (15 files); 278 passed, 3 deselected (live_ai) |
| Other suites touching AI modules unaffected | `uv run pytest tests/unit/api tests/security -q` | 494 passed, 32 deselected (incl. gitleaks tree scan after rephrasing one status line) |
| CLI paths on live data | `uv run extorq ai triage 38d0d427...` / `uv run extorq ai summary 38d0d427...` | triage returned the stored assessment (no new call); summary refused `disabled` (EXTORQ_GEMINI_ENABLED is false), nothing stored |
| Provider clients pinned against env redirection | python probe with `GOOGLE_GEMINI_BASE_URL`/`TYPESAFE_BASE_URL`=https://evil.example, `GOOGLE_GENAI_CLIENT_MODE=record`, `GOOGLE_GENAI_USE_VERTEXAI=true` | gemini base_url generativelanguage.googleapis.com, vertexai False, BaseApiClient (no replay client); jev base_url https://api.typesafe.ai |
| Live Jev smoke (1 call, SYNTHETIC SSH-S1 context) | `EXTORQ_AI_LIVE=1 uv run pytest tests/ai/test_ai_live.py::test_jev_live_smoke -m live_ai -s` | ok; model jev-1.14.0; 515 ms; 4785 in / 186 out tokens; req_01a1fe91a54e7ce78de116d5becc2f40; priority_investigation |
| Live Jev evaluation (27 calls) | `uv run extorq ai eval --live --max-calls 27 --date 2026-11-21` | Jev 77.8% (21/27) vs baseline 44.4% (12/27); raw choice before caution guards 85.2%; order consistency 100%; latency mean 309 ms / p95 351 ms; 80,313 input tokens (~$0.0034); all calls jev-1.14.0 |
| Report regenerated from stored raw answers | `uv run extorq ai eval --live --max-calls 0 --date 2026-11-21` | 0 live calls (all 27 reused) |
| Gemini summary-v1 schema rejected by the API | `... test_gemini_live_smoke` (2 calls) | 400 INVALID_ARGUMENT "schema ... too many states for serving" -> schema made structural (summary-v2) |
| Live Gemini smoke (summary-v2) | `EXTORQ_AI_LIVE=1 uv run pytest tests/ai/test_ai_live.py::test_gemini_live_smoke -m live_ai -s` | ok; gemini-3.6-flash; 23,014 ms; 4885 in / 2958 out tokens; 37 ids cited, 37 verified, 0 rejected |
| Live Gemini prompt-injection check | `... test_gemini_live_prompt_injection` | ok; 52,330 ms; 3913 in / 1970 out; model flagged the injected text as suspicious; canary absent; no fake id; 0 rejected; no destructive steps |
| AI storage path on a real ClickHouse 26.8.42.13 (throwaway `extorq-e-store-ch`, removed after) incl. C2's hash-verified store, pending queue, AIService reuse, worker cycles | `uv run pytest tests/ai/test_ai_store_clickhouse.py -q` | 6 passed in 3.94 s; `docker ps -a --filter name=extorq-e-` empty afterwards |
| ai-worker against the live stack (no contexts) | `EXTORQ_JEV_ENABLED=true EXTORQ_INSTANCE_NAME=ai-worker-hostrun uv run extorq ai-worker --once` | cycle ok, queue 0, pipeline_health row (instance ai-worker-hostrun) written as extorq_ai |
| extorq_ai least privilege (live) | python: `INSERT INTO extorq.alerts` and `SELECT count() FROM extorq.events` as extorq_ai | both refused (ACCESS_DENIED) |
| ai-worker on the first REAL contexts (2 K8S-002 from the live detector) | `EXTORQ_JEV_ENABLED=true EXTORQ_AI_WORKER_BATCH_SIZE=2 EXTORQ_INSTANCE_NAME=ai-worker-hostrun uv run extorq ai-worker --once` | 2 Jev calls ok (jev-1.14.0; 483/336 ms; 6817/6852 input tokens; provider request ids in `ai_assessments.provider_request_id`); both priority_investigation, uncertain (sufficient_context 0.35/0.39); rows read back as extorq_api_ro; health queue 2, written 2 |
| Existing settings tests pass | `uv run pytest tests/unit/ai -q` | 9 passed |
| Baseline-only evaluation runs (no network) | `uv run python -m extorq.ai.evaluation --out-dir <scratch> --date baseline-check` | baseline accuracy 44.4% (12/27); 0 live calls |
| Live ClickHouse state | python query as `extorq_ai` via 127.0.0.1:18123 | 0 alerts, 0 investigation_contexts, 0 ai_assessments |

## Live call budget (session 2)
- Jev: 30 of 40 used (1 smoke + 27 evaluation + 2 real contexts via the ai-worker).
- Gemini: 4 logical calls (2 rejected by the API with the summary-v1 schema, 1 smoke, 1 injection
  check). The injection call's 52 s duration fits an SDK retry after the then 30 s timeout, i.e.
  possibly 5 HTTP requests: the Gemini budget is treated as EXHAUSTED; no further Gemini calls.
- Ledger: `eval/live/smoke-2026-11-21.jsonl`, `eval/jev/raw-2026-11-21.jsonl`, ClickHouse
  `ai_assessments` (2 real rows).

## Not verified (session 2; see session 3 sections above for updates)
- Gemini summary on a REAL context (budget exhausted; the path is covered by the throwaway-ClickHouse
  test with a fake provider and by the live synthetic smoke).
- New Gemini defaults (60 s timeout, 1 attempt) not re-measured live.
- Compose `ai-worker` container (flags not in compose yet, E-IC-1); verified as a host process
  against the live ClickHouse instead.

## Blockers (session 3: none)
- none. (Session 3 live use: Jev 17 of 30, Gemini 2 of 4.)

## Next (session 2 list; superseded by "Session 3 next" above)
- A: E-IC-1 (compose flags) so the `ai-worker` container can run Jev and the API can run Gemini.
- Once enabled in compose: one Gemini summary on a real context (next session's budget) to
  measure latency with the new 60 s / single-attempt defaults.
- Label real lab contexts produced by the scenarios and extend the evaluation beyond synthetic data.
