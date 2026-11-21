# Agent E status (AI engineering: Jev triage, Gemini summaries)

Last update: 2026-11-21 session 2 (scope complete)

## Doing
- Session 2 scope complete and verified (see Verified). Remaining items are under Not verified / Next.

## Done this session
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

## Done (code on disk from session 1, re-checked this session)
- `backend/src/extorq/ai/`: settings/flags/key resolution, sanitiser, allow-list projection,
  Jev provider (question set triage-v1, deterministic post-processing), Gemini provider
  (system instruction, JSON schema output, evidence-id verification), budgets/cooldowns,
  store, AIService, ai-worker, baseline prioritiser, evaluation harness, synthetic builders.
- `eval/jev/dataset.jsonl` (27 SYNTHETIC cases) + `eval/jev/build_dataset.py`.

## Verified
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

## Live call budget (this session)
- Jev: 30 of 40 used (1 smoke + 27 evaluation + 2 real contexts via the ai-worker).
- Gemini: 4 logical calls (2 rejected by the API with the summary-v1 schema, 1 smoke, 1 injection
  check). The injection call's 52 s duration fits an SDK retry after the then 30 s timeout, i.e.
  possibly 5 HTTP requests: the Gemini budget is treated as EXHAUSTED; no further Gemini calls.
- Ledger: `eval/live/smoke-2026-11-21.jsonl`, `eval/jev/raw-2026-11-21.jsonl`, ClickHouse
  `ai_assessments` (2 real rows).

## Not verified
- Gemini summary on a REAL context (budget exhausted; the path is covered by the throwaway-ClickHouse
  test with a fake provider and by the live synthetic smoke).
- New Gemini defaults (60 s timeout, 1 attempt) not re-measured live.
- Compose `ai-worker` container (flags not in compose yet, E-IC-1); verified as a host process
  against the live ClickHouse instead.

## Blockers
- none. (Gemini live budget for this session is used up; see Live call budget.)

## Next
- A: E-IC-1 (compose flags) so the `ai-worker` container can run Jev and the API can run Gemini.
- Once enabled in compose: one Gemini summary on a real context (next session's budget) to
  measure latency with the new 60 s / single-attempt defaults.
- Label real lab contexts produced by the scenarios and extend the evaluation beyond synthetic data.
