# Agent AI interface notes and change proposals (2026-11-22, contract schema 2.0)

Owner: AI (successor of E for `backend/src/extorq/ai/**`, `tests/unit/ai/**`, `tests/ai/**`,
`eval/**`, `docs/ai-integrations.md`). Each item names the owner who must make the change;
AI does not edit lead-owned or other agents' files (PLAN section 8).

## What changed in the AI interface (informational, all consumers)

| Removed | Replacement / note |
|---|---|
| `extorq.ai.gemini` (whole module), `GeminiSummaryProvider`, `SUMMARY_PROMPT_VERSION` | none: Jev is the only provider |
| `AIService.request_summary`, `AIService.gemini`, constructor args `gemini=` / `cooldowns=` | `AIService.request_triage(alert_id, requested_by)` (unchanged) |
| `AISettings.gemini_*` fields | none |
| `budget.CooldownTracker`, `cooldown_remaining`, `shared_cooldowns`; `store.last_attempt_at` | none (only the summary path used them) |
| `projection.GEMINI_LIMITS`, `project_context(..., include_simulation_marker=)` | `JEV_LIMITS`; no simulation marker exists |
| `sanitize.clean_output` | none (Jev returns no free text) |
| `transport.async_client` | `transport.sync_client` |
| `ai_assessments.output` keys `summary`, `validation` | `output` is `{"requested_model", "triage"}`; readers ignore unknown keys and skip rows of removed providers |

Unchanged and used by others: `settings.get_ai_settings()`, `settings.resolve_key("JEV_API_KEY",
use_dotenv=False)` (now refuses any other name with `ValueError`), `settings.KeyState`,
`store.list_assessments(read_client, alert_id)`, `worker.main(once)`, `evaluation.main(argv)`.
`startup_report()` now returns `jev_enabled`, `jev_model`, `jev_key`, `jev_daily_cap`.

Behaviour change: Jev's question variant now follows the evidence event types
(`projection.classify_domain`): GitHub only for `github.workflow.*` evidence, Kubernetes
only for `k8s.api.*` / `k8s.resource.*` evidence, SSH+HTTP only for Linux-host alerts;
everything else (e.g. GH-005 credential, APP-001/HTTP-001 in the cluster, VM-003/004,
MAC-*) gets the generic variant. Question wording and `triage-v2` fingerprints unchanged.

## AI-IC-1 Drop the `google-genai` dependency (owner: lead, `backend/pyproject.toml`, `uv.lock`)

`grep -rn -E "google\.genai|from google import genai" --include="*.py"` over the whole
repository (excluding `.venv`) finds **no importer** after this stage. The dependency is
still declared in `backend/pyproject.toml` line 18 (`"google-genai>=3.6.1,<4"`) and in
`uv.lock`. Proposal: remove it and re-lock (`uv lock`). `httpx2` stays (typesafe-sdk needs
it); `certifi` comes with `httpx`.

## AI-IC-2 Contract comment (owner: lead, `backend/src/extorq/contracts/ai.py`)

`AIAssessment.model` still documents `e.g. "jev-1.14.0", "gemini-3.6-flash"`. Proposal:
`#: Versioned model id actually used (e.g. "jev-1.14.0").` Also PLAN section 1 diagram
("api (read API, Gemini on demand)"), section 4.5 (`GEMINI_API_KEY`), section 5 interface
list (`ai.gemini...`, `AIService.request_summary`) and section 7 ("Jev/Gemini live calls")
describe removed parts.

## AI-IC-3 Compose (owner: A, `compose.yaml`, `.env.example`, `backend/AGENTS.md`)

* Header comment line 14 still says "(ai-worker: Jev, api: Gemini)".
* The `api` service no longer receives any AI key, but keeps `read_only: false` with a comment
  about materialising the AI key; restoring `read_only: true` would close the hardening gap
  that `tests/security/test_security_containers.py` reports ("api: root filesystem not
  read_only"). Please verify nothing else in `api` needs a writable root.
* Still open from E-IC-6: pass the cap through so the operator can bound a demo run:
  `ai-worker: environment: EXTORQ_JEV_DAILY_CAP: ${EXTORQ_JEV_DAILY_CAP:-300}`.
* `.env.example` and `backend/AGENTS.md` ("ai/ | Jev triage, Gemini summaries") mention Gemini.

## AI-IC-4 Security tests (owner: F, `tests/security/**`)

Observed with `uv run pytest tests/unit/api tests/security -q` (2026-11-22, this stage):

* `test_security_api_authz.py::test_viewer_cannot_mutate` still POSTs to the removed
  `/api/v1/alerts/{id}/summary` and now gets 404 instead of 403.
* `test_security_ingest_redaction.py::test_every_record_kind_is_exercised` and
  `[simulation_run]` still exercise the removed `simulation_run` record kind.
* (Not AI) `test_security_python_static.py` flags `backend/src/extorq/pipeline/spool.py:486/501`
  (A's file, being edited in this stage).
* Stale wording only: `fixtures/README.md` and `prompt_injection_corpus.json` describe the
  `ai` domain as "Jev triage / Gemini summary"; the corpus placeholder
  `PASTE_GEMINI_API_KEY_HERE` could become `PASTE_JEV_API_KEY_HERE`;
  `test_security_containers.py` `AI_SECRET_HINT` still lists `gemini`.

## AI-IC-5 Delete `tests/fixtures/ai/` (owner: lead; formerly E)

`tests/fixtures/ai/context_k8s001_real.json` is a schema-1.1 context with
`simulation_run_ids` and `extorq-sim-*` object names; it no longer validates under schema 2.0
and is no longer referenced by any test. The regression it served is now covered by
`tests/unit/ai/test_ai_projection.py::test_builder_keyed_evidence_keeps_every_key_field`,
which runs C2's real event summariser (`extorq.correlation.records.record_from_row`) on a
SYNTHETIC audit row with `extorq-test-` names. Proposal: delete the directory.

## AI-IC-6 Documentation (owner: F, and D2 for the console docs)

Gemini or the summary path is still described in: `AGENTS.md` (sections 1-3, 5),
`README.md`, `docs/architecture.md`, `docs/threat-model.md`, `docs/security.md`,
`docs/deployment.md`, `docs/demo-runbook.md`, `docs/known-limitations.md`,
`docs/testing.md`, `docs/adr/0007-ai-advisory-boundaries.md`, `docs/api/README.md`,
`frontend/AGENTS.md`, `frontend/DESIGN.md`, `frontend/docs/screenshots/README.md`,
`frontend/scripts/smoke.mjs`. `docs/ai-integrations.md` is the Jev-only reference.

## AI-IC-7 Rebuild before VERIFY (owner: lead / A)

The running `extorq-ai-worker-1` container was built before this change. Rebuild the backend
image before the clean-slate verification; afterwards the `ai_worker_starting` log line
carries `jev_enabled`, `jev_model`, `jev_key` (state only) and `jev_daily_cap`, and no
Gemini field.

## AI-IC-8 CLI error handling for `extorq ai triage` (owner: A, `backend/src/extorq/cli.py`)

`uv run extorq ai triage NOT-A-HEX-ID` prints a Python traceback ending in
`extorq.ai.service.InvalidAlertId: alert_id must be 32 lower-case hex characters` (no data or
secret is exposed, but it reads like a crash). Proposal: catch
`extorq.ai.service.AIServiceError` (base of `InvalidAlertId`, `ContextNotFound`,
`ContextUnavailable`) in `ai_triage`, print the message on one line and exit with code 2.
