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

## E-IC-6 Compose: pass the AI daily caps through (owner: A, `compose.yaml`) - session 3

**What.** `compose.yaml` passes `EXTORQ_JEV_ENABLED` / `EXTORQ_GEMINI_ENABLED` (E-IC-1, done)
but not the caps, so a container with a provider enabled always runs with the defaults (Jev
300, Gemini 50 calls per UTC day). Proposal (defaults unchanged, operator can lower them for the
demo):

```yaml
ai-worker:
  environment:
    EXTORQ_JEV_DAILY_CAP: ${EXTORQ_JEV_DAILY_CAP:-300}
api:
  environment:
    EXTORQ_GEMINI_DAILY_CAP: ${EXTORQ_GEMINI_DAILY_CAP:-50}
    EXTORQ_GEMINI_ALERT_COOLDOWN_SECONDS: ${EXTORQ_GEMINI_ALERT_COOLDOWN_SECONDS:-120}
```

**Why.** Enabling Jev in the compose `ai-worker` makes it triage every new or changed context
automatically; a per-demo cap is the only spend bound an operator can set without editing
compose. The cap counts attempts already stored that UTC day (fail closed if unreadable).
**Affected.** A (compose). No code change in E (the settings already exist).

## Session-3 notes for other owners (informational)

* **F (F-22, owner E: done).** `tests/unit/ai/test_ai_sanitize.py` now assembles the
  `api_key: '...'` sample at runtime (`_credential_pair_samples`). Verified with the pinned
  gitleaks image and a copy of `tests/security/gitleaks.toml` without the F-22 `[[allowlists]]`
  block: 0 findings for the new file (positive control: the HEAD version of the file is flagged
  at line 75 with `generic-api-key`). F can remove the F-22 allowlist entry.
* **F (docs/security.md, threat model).** Provider HTTP clients no longer trust the
  environment: `extorq.ai.transport` injects `httpx2` clients (`trust_env=False`, certifi-only TLS
  context with key logging off, no redirects) into both SDKs; `HTTPS_PROXY`, `SSL_CERT_FILE`,
  `SSL_CERT_DIR`, `SSLKEYLOGFILE` and `GOOGLE_GENAI_HTTP_CLIENT` cannot redirect or expose
  requests carrying the API keys. Residual: importing google-genai imports aiohttp, which creates
  an (empty, header-only) `SSLKEYLOGFILE`; `OPENSSL_CONF` is process-wide. Details:
  `docs/ai-integrations.md` section 3.
* **D1 / lead (api container).** The running `api` container image predates session 3 (it
  still has `summary-v2` and the projection that drops every evidence key field). Before
  analysts request summaries from the console, rebuild/recreate `api` with the current tree.
  The two session-3 summaries (GH-001, CORR-002) are already stored and are served by any API
  version.
* **B2 / C2 (Kubernetes coverage).** All 12 K8S-001/K8S-002 contexts report `k8s.audit` with
  status `unknown`, stale and with a gap ("No collector has reported health for this source
  type."), because the OTel audit path reports no `CollectorHealth`. Jev therefore answers
  `sufficient_context` 0.42-0.64 and every Kubernetes triage is `uncertain`. A health record for
  the OTel audit pipeline would make the coverage signal (and the AI) more accurate.
* **B2 / A (redaction false positive, already addressed; no action requested).** Stored K8S-001
  audit events from 2026-11-21 contain `"automount_sa_token":[REDACTED:secret]` in
  `attributes.request_summary` (a boolean redacted because of the key name). The current working
  tree already fixes both sides (A: literal `true`/`false`/`null` are never redacted; B2: the
  key is now `automount_service_account`); events stored before the fix keep the redacted value,
  so the real-context fixture `tests/fixtures/ai/context_k8s001_real.json` shows it.
