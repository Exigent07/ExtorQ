# Agent E (AI engineering) interface notes and change proposals

Owner: E. Each proposal names the owner who must make the change; E does not edit
lead-owned or other agents' files (PLAN section 8).

## E-IC-1 Compose: AI feature flags and no dotenv inside containers (owner: A, `compose.yaml`)

**What.** Both AI providers are disabled by default (`AISettings.jev_enabled` /
`gemini_enabled` = false), and `compose.yaml` does not set the flags, so the
`ai-worker` reports `disabled` and `POST /api/v1/alerts/{id}/summary` answers 503
even when the keys are mounted. Proposal (operator opt-in, still off by default):

```yaml
ai-worker:
  environment:
    EXTORQ_JEV_ENABLED: ${EXTORQ_JEV_ENABLED:-false}
    EXTORQ_AI_DOTENV: ""            # never look for a .env inside the container
api:
  environment:
    EXTORQ_GEMINI_ENABLED: ${EXTORQ_GEMINI_ENABLED:-false}
    EXTORQ_AI_DOTENV: ""
```

Optional caps (defaults shown, only if the operator wants to lower them):
`EXTORQ_JEV_DAILY_CAP` (300), `EXTORQ_GEMINI_DAILY_CAP` (50),
`EXTORQ_GEMINI_ALERT_COOLDOWN_SECONDS` (300).

**Why.** Keeps "works with AI completely unavailable" as the default while letting the
operator enable each provider for the demo without editing compose. `EXTORQ_AI_DOTENV=""`
is defence in depth: images contain no `.env` (`.dockerignore`), and the AI settings
layer only reads `JEV_API_KEY`/`GEMINI_API_KEY` from a dotenv file for local development.

**Affected.** A (compose), D1 (API answers 503 with the flag name while disabled; no code change).

## E-IC-2 Platform settings and AI keys (informational, owner: A)

`extorq.ai.settings.resolve_key` asks `extorq.common.config.get_settings()` first
(`jev_api_key` / `gemini_api_key`, which already accept `JEV_API_KEY_FILE` /
`GEMINI_API_KEY_FILE`). If the platform settings cannot be constructed (e.g. a
`ConfigError` for an unrelated secret, or both `X` and `X_FILE` set), the AI layer falls
back to its own `<NAME>_FILE` -> `<NAME>` -> dotenv resolution and reports only the key
*state* (configured / missing / malformed / unreadable). No change requested.

## E-IC-3 ClickHouse identities used by AI (informational, owner: A)

Verified against `0002_rbac.sql`: the ai-worker uses `extorq_ai` (SELECT alerts,
investigation_contexts, context_relationships, ai_assessments; INSERT ai_assessments,
pipeline_health). `AIService` called from the API uses `extorq_api_ro` for reads and
`extorq_api_writer` for the INSERT into `ai_assessments` (and, when it asks C2's builder
for a missing context, `investigation_contexts` / `context_relationships`). No AI code
path writes `alerts`. No change requested.

## E-IC-4 Context loading contract with C2 (informational, owner: C2)

AI calls `extorq.correlation.store.load_latest_context(read_client, alert_id)` and, when
nothing is stored and `EXTORQ_AI_BUILD_MISSING_CONTEXT` is true,
`ContextBuilder(read_client).build(alert_id)` + `save_context(write_client, ctx)`.
C2's store is in place (session 2) and is used by AI; the fallback (newest
`investigation_contexts.body`, validated) only applies if that module cannot be imported.
`ContextStoreError` / `ContextIntegrityError` from C2's loader are mapped to AI's
`ContextLoadError`, so the ai-worker skips a bad stored context instead of stalling.
`InvestigationContext.services` / `related_assets` (1.1) are projected into AI input as
names, kinds, categories, adapter support, monitoring status, role and asset ids only.
`ServiceSummary.service_kind` / `category` / `adapter_support` / `monitoring_status` are
free strings in the contract; AI passes contract enum values and the builder's `unknown`,
and maps anything else to `"unrecognised"`.

## E-IC-5 Doc references now implemented (owner: F, informational)

* `docs/threat-model.md` (T-prompt-injection section) says "Planned (E): evaluation with the
  corpus in `tests/ai`/`eval`". Implemented: `tests/ai/test_ai_prompt_injection.py` runs F's
  47-case corpus through every untrusted field for both providers plus a compromised-model
  output test (97 tests), and one live Gemini injection check is recorded in
  `docs/ai-integrations.md` section 7 (the model did not follow the injection; residual risk:
  injected claims can still colour "benign explanations").
* `docs/known-limitations.md` can now link `docs/ai-integrations.md`.
* Gemini client hardening worth a line in `docs/security.md`: provider base URLs, API version,
  Vertex switch and the SDK record/replay mode are pinned in code, so `TYPESAFE_BASE_URL`,
  `GOOGLE_GEMINI_BASE_URL`, `GOOGLE_GENAI_API_VERSION`, `GOOGLE_GENAI_USE_VERTEXAI` and
  `GOOGLE_GENAI_CLIENT_MODE` cannot redirect keys or write prompts to disk.
