# Agent AI status (Jev triage only; successor of agent E for the AI area)

Owner paths: `backend/src/extorq/ai/**`, `tests/unit/ai/**`, `tests/ai/**`, `eval/**`,
`docs/ai-integrations.md`. Stage: schema 2.0 clean-up (user decisions 2026-11-22: Jev only,
no simulation category). Proposals for other owners: `docs/team/interface-changes/AI.md`.

## Milestone log (2026-11-22)

- M0 (start): read AGENTS.md, PLAN.md section 12, contracts 2.0 (`023fdb6`). Baseline:
  `uv run pytest tests/unit/ai tests/ai -q -p no:cacheprovider` -> 7 collection errors
  (`extorq.ai.store` / `gemini` import `InvestigationSummary`, `EvidenceStatement`, removed
  in schema 2.0); `projection.py` / `synthetic.py` still used `simulation_run_ids`.
- M1 (code): deleted `ai/gemini.py`; `settings.py` Jev-only (`resolve_key` refuses any name
  but `JEV_API_KEY`); `service.py` triage-only (summary path, cooldowns removed);
  `budget.py` without the summary cooldown; `store.py` output `{requested_model, triage}`,
  `last_attempt_at` removed, unreadable history rows skipped; `projection.py` without
  `GEMINI_LIMITS`/simulation marker and dead `_context_event_types`, domain routing follows
  the evidence event types (question wording and `triage-v2` fingerprints unchanged);
  `sanitize.py` without `clean_output` and the Gemini prompt-delimiter markers;
  `transport.py` sync client only; `synthetic.py` without `simulation_run_ids`;
  `evaluation.py` skips raw lines that no longer validate (counted in the report).
- M2 (tests): deleted `test_ai_gemini.py`; fakes, settings, budget/store, service/worker
  (AIService tests now on `request_triage`), projection (builder-path regression test via
  C2's `record_from_row` replaces the schema-1.1 fixture; routing tests), transport,
  sanitiser, evaluation (outdated raw lines), prompt injection (Jev input side + compromised
  output side), live (Jev only), real-ClickHouse store tests (container `extorq-ai-store-ch`).
- M3 (eval): `eval/jev/dataset.jsonl` rebuilt for schema 2.0 (27 SYNTHETIC cases, same
  labels/domains); Gemini records removed from `eval/live/*.jsonl` (6 lines; Jev records kept).
- M4 (docs): `docs/ai-integrations.md` rewritten Jev-only; `interface-changes/AI.md` written.

## Verified (commands and observed results)

| Claim | Command | Result |
|---|---|---|
| Lint / format clean on owned paths | `uv run ruff check backend/src/extorq/ai tests/unit/ai tests/ai eval` and `uv run ruff format --check` (same paths) | All checks passed; 31 files already formatted |
| Types | `uv run mypy backend/src/extorq/ai` | Success: no issues found in 15 source files |
| AI suites green (unit, adversarial, real ClickHouse) | `uv run pytest tests/unit/ai tests/ai -q -p no:cacheprovider` | 238 passed, 1 deselected (live_ai) in ~5 s |
| Storage SQL on real ClickHouse 26.8.42.13 incl. C2 hash-verified store, `AIService.request_triage` reuse, worker cycles, tampered context at queue head | `uv run pytest tests/ai/test_ai_store_clickhouse.py -q -p no:cacheprovider` | 7 passed; `docker ps -a --filter name=extorq-ai-store` empty afterwards |
| No google.genai importer anywhere in the repository | `grep -rn -E "google\.genai\|from google import genai\|import google\.genai" --include="*.py" .` (excluding .venv/node_modules/.git) | no match (exit 1); dependency only in `backend/pyproject.toml:18` and `uv.lock` |
| AI package imports without Gemini | `uv run python -c "import extorq.ai.*..."` | all 14 modules import; `google.genai` not in `sys.modules` |
| Package source free of Gemini (regression guard) | `tests/unit/ai/test_ai_settings.py::test_jev_is_the_only_provider` | passed (AIProvider = [typesafe-jev], AITask = [triage], no gemini/genai in `backend/src/extorq/ai/*.py`) |
| Question wording unchanged | `uv run python -c "...question_set(d).version..."` | github:fc7ff66f49eb, ssh_http:5bc46bb28903, k8s:ec7efb3a0d14, generic:b7bc57a81d96 (same as the recorded runs) |
| Dataset rebuilt and reproducible | `uv run python eval/jev/build_dataset.py`; `test_dataset_file_is_reproducible` | 27 cases, 54 `"schema_version": "2.0"`, 0 `simulation`; test passed |
| Evaluation harness offline on the new dataset | `EXTORQ_AI_DOTENV="" uv run extorq ai eval --out-dir <scratchpad>/eval-offline --date offline-check` | baseline accuracy 44.4% (unchanged), 0 live calls |
| Live mode refuses without a key (no key read) | `EXTORQ_AI_DOTENV="" uv run extorq ai eval --live --max-calls 0 ...` | `error: --live requires a usable key (JEV_API_KEY not configured)` |
| Historical raw answers never crash a re-run | `_load_raw(Path("eval/jev/raw-2026-11-21.jsonl"))` | 0 reusable, 27 skipped (schema 1.1) |
| CLI wiring (A's cli.py) matches the new interface | `uv run extorq ai --help`; `uv run extorq ai triage NOT-A-HEX-ID` | commands `triage`, `eval` only; invalid id rejected before I/O (traceback: proposal AI-IC-8) |
| Neighbouring suites do not depend on removed AI symbols | `uv run pytest tests/unit/api tests/security -q -p no:cacheprovider` | 547 passed, 4 failed, all outside AI (AI-IC-4: summary endpoint 404, `simulation_run` kind, A's spool.py SQL) |
| Whole default suite | `uv run pytest -q -p no:cacheprovider --ignore=<3 files that fail to import because of other agents' in-progress simulation removals>` | 1671 passed, 111 failed, 5 skipped; no failing file imports `extorq.ai` (checked with grep); failures are in correlation/detection/rules/platform/kubernetes/github/security work in progress |

## Not verified
- No live Jev call in this stage: the only key source on this host is the user's `.env`,
  which this stage's rules forbid reading. Offline coverage: the real TypeSafe SDK request
  path through the injected client (`test_jev_sdk_sends_only_through_the_pinned_client`).
  For VERIFY, after rebuilding the image: `EXTORQ_JEV_ENABLED=true docker compose --profile
  full up -d ai-worker` (key via compose file secret) or `EXTORQ_AI_LIVE=1 uv run pytest
  tests/ai/test_ai_live.py -m live_ai -s` (1 call).
- The compose `ai-worker` container still runs the pre-change image (not rebuilt: shared
  service, AI-IC-7). Not tested against the live stack (`extorq ai-worker --once` would write
  a health row into the shared database before the clean-slate reset).
- The evaluation was not re-run live under the current projection (27 calls exceed the
  20-call per-agent cap); `docs/ai-integrations.md` states this.

## Next / handover
- Lead: AI-IC-1 (drop `google-genai`, re-lock), AI-IC-2 (contract comment, PLAN text),
  AI-IC-5 (delete `tests/fixtures/ai/`), AI-IC-7 (rebuild image before VERIFY).
- A: AI-IC-3 (compose comment, `api` read_only, cap passthrough), AI-IC-8 (CLI error).
- F: AI-IC-4 (security tests), AI-IC-6 (docs still describing Gemini).
