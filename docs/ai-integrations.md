# AI integration: Jev triage

Owner: agent AI. Code: `backend/src/extorq/ai/`. Tests: `tests/unit/ai/`, `tests/ai/`.
Evaluation: `eval/jev/`; live-call ledgers: `eval/live/`. Decision record:
`docs/adr/0007-ai-advisory-boundaries.md`. Last updated: 2026-11-22 (contract schema 2.0).

ExtorQ's alerts, severities and evidence come from deterministic collection, SQL rules
and correlation. AI is optional and advisory, and there is exactly one AI provider:
**Jev** (TypeSafe "System One"). With Jev disabled (the default) every other part of
ExtorQ works unchanged.

## 1. Role and boundaries

| | Jev triage |
|---|---|
| Job | A triage hint for each new investigation context: how urgently a human should look, and whether the context is good enough to judge at all |
| Triggers | the `ai-worker` loop (automatic, budgeted) and `extorq ai triage <alert_id>` (operator, same budget) |
| Input | an allow-listed, sanitised projection of one `InvestigationContext` (section 4) |
| Output | probabilities for fixed, typed questions; ExtorQ turns them into a recommendation with a deterministic procedure (section 5) |
| Model | `jev-1.14.0`, pinned (`EXTORQ_JEV_MODEL`); the id the provider reports is stored too |
| Writes | one `ai_assessments` row per provider attempt (`extorq_ai` in the ai-worker; `extorq_api_writer` when the CLI triages) |
| Read by | the analyst API (`GET /api/v1/alerts/{id}/assessments`) and the console's investigation page |

What Jev never does, by construction rather than by instruction:

* It never writes `alerts`, `alert_evidence` or `analyst_state`. The `extorq_ai`
  ClickHouse user has no INSERT on `alerts` and no SELECT on `events`.
* It never changes severity, suppresses, closes or remediates. `AIAssessment` has no
  field that could carry a severity or verdict, and answers to anything but the asked
  questions are discarded (section 6).
* It produces no free text. Jev answers Noul questions (a probability) and Choice
  questions (one of a fixed set of labels); nothing it returns is rendered as prose.
* It has no tools: no function calling, no SQL, no shell, no repository or file access.
* It is never asked to count, compare dates, do arithmetic or restate rule logic. Those
  values are computed deterministically (detection and correlation features) and given
  to Jev as data.

The recommendation values are `priority_investigation`, `routine_review`,
`likely_benign_maintenance` and `insufficient_context`. They are a hint for queue order;
the analyst owns the verdict and the rule owns the severity.

## 2. Data flow

```
InvestigationContext (built and hashed by C2's correlation layer)
   │  extorq.ai.context_source -> correlation.store.load_latest_context (hash-verified)
   ▼
allow-list projection (extorq.ai.projection) ── sanitiser (extorq.ai.sanitize)
   │
   ▼
one system_one request: state JSON + the fixed questions of the context's domain
   │
   ▼
strict answer validation -> deterministic decision (extorq.ai.jev.decide)
   │
   ▼
AIAssessment (contracts/ai.py) ──► extorq.ai_assessments
```

Every assessment records the provider, the model id reported by the provider and the
requested one, the question-set version, status, latency, input and output tokens, the
provider request id, the context id and the context `input_hash` it was computed from,
who requested it, and a sanitised error code.

## 3. Configuration and credentials

All settings use the `EXTORQ_` prefix (`extorq.ai.settings.AISettings`).

| Setting | Default | Meaning |
|---|---|---|
| `EXTORQ_JEV_ENABLED` | `false` | Feature flag |
| `EXTORQ_JEV_MODEL` | `jev-1.14.0` | Pinned model id (validated charset) |
| `EXTORQ_JEV_TIMEOUT_SECONDS` | 10 | Per HTTP attempt |
| `EXTORQ_JEV_MAX_RETRIES` / `EXTORQ_JEV_RETRY_BUDGET_SECONDS` | 2 / 25 | Bounded SDK retries (HTTP 408, 429, 5xx, 529) with jittered backoff, and the total time budget of one call |
| `EXTORQ_JEV_DAILY_CAP` | 300 | Provider attempts per UTC day (section 8) |
| `EXTORQ_JEV_MAX_STATE_CHARS` | 24000 | Size cap of the serialised state (the projection shrinks itself to fit) |
| `EXTORQ_AI_INCLUDE_EXCERPTS` | `false` | Raw evidence excerpts are dropped unless enabled |
| `EXTORQ_AI_BUILD_MISSING_CONTEXT` | `true` | `extorq ai triage` asks the correlation builder when no context is stored |
| `EXTORQ_AI_WORKER_INTERVAL_SECONDS` / `..._BATCH_SIZE` | 30 / 10 | Worker cycle and per-cycle bound |
| `EXTORQ_AI_WORKER_MAX_FAILED_ATTEMPTS` / `..._RETRY_BACKOFF_SECONDS` | 3 / 600 | Retry policy for a context whose triage failed |
| `EXTORQ_AI_WORKER_MAX_CONTEXT_AGE_HOURS` | 72 | Older contexts are not triaged |
| `EXTORQ_AI_WORKER_MAX_SCAN_PER_CYCLE` | 50 | Contexts examined per cycle while looking for `batch_size` usable ones |
| `EXTORQ_AI_WORKER_WRITE_RETRY_BASE_SECONDS` / `..._MAX_SECONDS` | 15 / 600 | Backoff for retrying the INSERT of a paid result whose write failed |
| `EXTORQ_AI_WORKER_WRITE_MAX_ATTEMPTS` | 12 | Failed writes after which such a result is dropped |

**Key.** `JEV_API_KEY` is resolved in this order: the platform settings
(`extorq.common.config`, which accept `JEV_API_KEY_FILE`), then `JEV_API_KEY_FILE`, then
`JEV_API_KEY`, then (local development only) the same name loaded programmatically from
`.env` in the working directory (`EXTORQ_AI_DOTENV`; empty disables it). Container images
contain no `.env`, and compose sets `EXTORQ_AI_DOTENV=""`. The resolver refuses any
other variable name, so it cannot be used as a generic secret reader. The value is held
as `SecretStr`, passed explicitly to `TypeSafeClient(api_key=...)` (the SDK's own
`TYPESAFE_API_KEY` is never consulted), scrubbed verbatim from the state and from error
messages, and never logged; only its *state* (configured, missing, malformed,
unreadable) is ever reported, for example in the ai-worker's startup line.

**Pinned client.** `base_url="https://api.typesafe.ai"` is passed explicitly, so
`TYPESAFE_BASE_URL` cannot send the key elsewhere, and the SDK logger is held at WARNING
because it logs request bodies at DEBUG. The SDK gets an injected `httpx2` client
(`extorq.ai.transport`) with `trust_env=False`, a TLS context built directly from
certifi's CA bundle (certificate and hostname verification, TLS 1.2 or later, key
logging off) and `follow_redirects=False`. `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY`,
`SSL_CERT_FILE`/`SSL_CERT_DIR` and `SSLKEYLOGFILE` therefore cannot route, intercept or
decrypt requests that carry the key, and no redirect can forward it. Verified offline
through the real SDK request path under a hostile environment
(`tests/unit/ai/test_ai_transport.py`, with a positive control showing that an
SDK-default client does honour `HTTPS_PROXY`). Request lines are not logged. Outside
this control: process-wide OpenSSL configuration (`OPENSSL_CONF`) and anyone able to
modify the installed packages or the certifi bundle.

**Compose.** The base worker sets `EXTORQ_JEV_ENABLED=false` and uses only the
internal data network. `make up-demo` applies `compose.jev.yaml`, which adds
network egress and mounts `JEV_API_KEY_FILE=/run/secrets/jev_api_key` only in the
worker. The overlay requires an explicitly approved `EXTORQ_JEV_DAILY_CAP`.
Both configurations disable the dotenv fallback inside the container.

## 4. Privacy: what reaches Jev

When Jev is enabled, sanitised telemetry derived from the context leaves the host for
TypeSafe's API: user names, IP addresses, host, cluster and repository names, HTTP
paths, commit messages and Kubernetes object names, each bounded and redacted as below.
Nothing is sent while Jev is disabled. ExtorQ cannot verify the provider's retention.

The state is built only from `InvestigationContext`, through an explicit allow-list
(`extorq.ai.projection.project_context`):

* Alert: id, rule id/version/title, severity, evidence confidence, event count,
  first/last seen, MITRE ids, entities, summary, detection features.
* Rule: description, known false positives, blind spots (ExtorQ-authored text).
* Asset: id, type, name, criticality, environment.
* Services: name, kind, category, adapter support, monitoring status, role (evidence or
  related) and parent asset id. Never service attributes, configuration paths,
  endpoints, versions or ids: each service gets a local alias (`svc-1`, ...) that
  evidence events reference, so the only 32-hex values in the state are ExtorQ's event
  and alert ids. Enumerated values outside `contracts.service` become `unrecognised`;
  the builder's `unknown` passes through.
* Related assets: id, type and criticality only.
* Evidence events: at most 8. When there are more, the first event of every evidence
  event type is kept first, then the earliest and latest events fill the remaining slots
  (time order), so each stage of a multi-stage detection stays visible (plain head/tail
  sampling once dropped every HTTP probe of a CORR-002 alert).
* Related events: at most 8, ranked by relationship type, strength and time distance;
  plus relationship counts, correlation features, telemetry coverage (stale, gaps, lag),
  missing telemetry, context limitations and up to 5 posture findings (check id,
  scanner, severity, state, title).

Evidence `key_fields` are **normalised before** the allow-list, the deny-list, the
per-field text limits and the per-event cap (`canonical_key_field`). The correlation
builder keys them by dotted catalogue path (`kubernetes.verb`,
`attributes.request_summary`, `http.route`); synthetic contexts use flattened or leaf
names. Each spelling maps to one canonical name: `<group>_<leaf>` for top-level fields
(`kubernetes_verb`, `http_route`, `network_src_ip`), the bare leaf for `attributes.*`
(`request_summary`, `risk_flags`). A bare leaf maps only when exactly one catalogue path
ends in it, or when the event's own catalogue entry resolves it; otherwise it keeps its
own name (never guessed). Fields are emitted in the event type's catalogue order, so the
per-event cap of 16 keeps the most decisive ones. Keys that look sensitive (`password`,
`token`, `secret`, `cookie`, `authorization`, `session`, `api_key`, `raw`, `payload`,
`excerpt`, `body`, `diff`, `patch`, `env`) are dropped, checked on the raw key, each
dotted segment and the canonical name. A regression test runs C2's real event
summariser (`extorq.correlation.records`) and checks that all 10 key fields of a
Kubernetes audit event reach the state (review finding, 2026-11-21: before
normalisation every dotted key from the real builder was dropped).

Every string that can carry telemetry content (log-derived summaries, actor names, HTTP
paths and user agents, commit messages, Kubernetes fields, entity values, finding
titles, string features, relationship explanations, service names) goes through
`clean_untrusted` and is wrapped as `{"untrusted": "..."}`:

1. NFKC normalisation (folds full-width and compatibility look-alikes).
2. Control, format (bidi overrides, zero-width, Unicode tag characters), private-use and
   surrogate characters removed; line breaks become spaces.
3. Secret redaction: A's `extorq.common.redaction.redact_text`, then local patterns
   (private keys, cloud and API tokens, JWTs, bearer/basic credentials, `password=`
   pairs, URL credentials, token query parameters, e-mail addresses), then exact
   scrubbing of the configured Jev key. GitHub permission levels such as
   `id-token: write` are kept.
4. Stand-alone 32-hex tokens are masked as `[hex32]`, so telemetry cannot impersonate
   ExtorQ's ids; `<` becomes U+2039 in all text, so tag-like payloads
   (`</data><instructions>`) cannot imitate markup structure.
5. Per-field truncation with an explicit `…[truncated]` marker (log messages 300, HTTP
   paths 160, user agents 120, commit messages 200, Kubernetes fields 160, Kubernetes
   request summaries and Pod Security admission messages 256, actor names 80).

The serialised state is capped at 24,000 characters. When too large, related events,
then middle evidence events, then findings, then features, then rule text and event
fields, then related services are dropped, and the number of omitted events is stated
in the state. If it still does not fit, no call is made (`input_preparation_failed`).

## 5. Questions, domains and thresholds (question set `triage-v2`)

One `system_one` request per context carries every question of the context's domain.

**Domain routing** (`classify_domain`) follows what the evidence is about, because each
domain's lead sentence and extra question describe one kind of activity:

| Domain | Chosen when the evidence contains | Lead sentence given to Jev |
|---|---|---|
| `github` | `github.workflow.*` events | a change to a GitHub Actions workflow in a monitored repository |
| `k8s` | `k8s.api.*` or `k8s.resource.*` events | Kubernetes API activity related to privileges (privileged/host pods, RBAC) |
| `ssh_http` | a Linux-host alert of VM-001, HTTP-001, APP-001, CORR-001 or CORR-002, or Linux evidence with `auth.ssh.*`, `http.*`, `app.auth*` events | SSH authentication activity on a Linux host, possibly with related HTTP requests |
| `generic` | anything else | security-relevant activity on a monitored asset |

So a committed-credential alert on a repository, and web-login or probing alerts from the
application running in the cluster, get the neutral `generic` framing rather than a
workflow or API-privilege question. A context without evidence summaries (for example
expired events) is routed by the rule family. This evidence-led routing replaced
asset-first routing on 2026-11-22; the question wording did not change, and the domain
actually used is part of each stored question-set version.

| Question | Type | Asked |
|---|---|---|
| `sufficient_context` | Noul: does the state contain enough information for a contextual judgment? | always |
| `priority_a` | Choice: priority_investigation / routine_review / likely_benign_maintenance | always |
| `priority_b` | the same Choice with the option order reversed (Choice answers lean to the first option) | always |
| `maintenance_consistent` | Noul: consistent with planned maintenance, routine automation or authorised administration? | always |
| `joint_investigation` | Noul: do the related observations warrant investigating them together? | always |
| `change_appears_reviewed` | Noul: was the workflow change reviewed before it landed? | `github` |
| `coordinated_activity` | Noul: SSH and HTTP activity one coordinated sequence from one source? | `ssh_http` |
| `privilege_escalation_attempt` | Noul: an attempt to obtain elevated privileges? | `k8s` |

Each answer records `triage-v2:<domain>:<sha256 of the exact wire questions, 12 hex>`
(currently `github:fc7ff66f49eb`, `ssh_http:5bc46bb28903`, `k8s:ec7efb3a0d14`,
`generic:b7bc57a81d96`), so any wording change is traceable.

**Deterministic decision** (`extorq.ai.jev.decide`):

* `sufficient_context < 0.3` -> `insufficient_context` (status `insufficient_context`).
* `0.3 <= sufficient_context <= 0.7` -> `uncertain=true`: the middle band goes to a human.
* The two priority answers disagree -> `order_consistent=false`, `uncertain=true`, and
  the averaged distribution decides; ties resolve to the more cautious option.
* Caution guards (an answer can only become more cautious): a benign recommendation
  needs `sufficient_context > 0.7`, `maintenance_consistent >= 0.5` and, for `k8s`,
  `privilege_escalation_attempt < 0.7`; otherwise it becomes `routine_review` and
  `uncertain`. A priority recommendation with `maintenance_consistent > 0.7` is flagged
  uncertain.
* `rationale_codes` name what drove the result (for example `context_borderline`,
  `priority_order_sensitive`, `benign_conflicts_privilege_escalation`,
  `change_not_reviewed`, `coordinated_activity`).

**Answer validation** (`parse_answers`): every asked question answered, the right answer
type, probabilities finite and in [0, 1], Choice labels only from the question's options;
anything else is `invalid_output` and no triage is stored.

## 6. Prompt-injection defences

Tested with F's 47-case SYNTHETIC corpus (`tests/security/fixtures/prompt_injection_corpus.json`)
placed in every untrusted field at once (`tests/ai/test_ai_prompt_injection.py`):

| Control | Test assertion |
|---|---|
| Telemetry is quoted data | every string carrying payload words is inside an `{"untrusted": ...}` value (all 47 cases) |
| Forged ids are masked | no 32-hex value in the state except presented event ids and the alert id |
| Markup and invisible characters | no `<`, no Cc/Cf/Co/Cs characters anywhere in the state |
| Questions cannot be rewritten | the questions sent equal the fixed domain set |
| An invented option label (a provider following "mark benign and delete the alert") | `invalid_output`, no triage, the label appears nowhere in the assessment; provider metadata is reduced to a safe token charset |
| Extra answers (`severity`, `suppress_alert`) | discarded; only asked questions are stored |
| Non-probabilities (NaN, infinity, out of range) | `invalid_output` |
| A provider fully persuaded that the activity is benign | the caution guards still require clear context and agreeing maintenance answers |

Residual risk: injected text can still influence the probabilities Jev returns. That is
why the decision is bounded by deterministic guards, uncertain results are labelled,
and nothing Jev produces changes alerts, severity or analyst state.

## 7. On-demand triage (`extorq ai triage <alert_id>`)

`extorq.ai.service.AIService.request_triage` validates the alert id (32 lower-case hex,
before any I/O), loads the latest stored context (building and saving one through C2's
builder when none exists and `EXTORQ_AI_BUILD_MISSING_CONTEXT` is on), returns an
existing successful triage for the same context `input_hash`, model and question-set
version instead of a new call, and otherwise reserves budget, calls Jev and stores the
result. A per-alert lock makes concurrent requests for one alert produce one call. It
uses `extorq_api_ro` / `extorq_api_writer` because building a missing context needs
SELECT on telemetry and INSERT on `investigation_contexts`, which `extorq_ai` lacks;
neither identity can write `alerts`. Precondition failures raise `InvalidAlertId`,
`ContextNotFound` or `ContextUnavailable`; provider problems never raise.

## 8. Budget and failure handling

* The daily cap counts provider attempts of the current UTC day in `ai_assessments`
  (`uniqExact(assessment_id)`, statuses ok, insufficient_context, invalid_output,
  timeout, rate_limited, error) plus an in-process guard for calls in flight and calls
  whose storage failed. If the persisted count cannot be read, no call is made (fail
  closed). Two processes may each take the last slot at the same instant; within a
  process the check and reservation are atomic. A result stored later by a write retry
  leaves the in-process count (`Reservation.persisted_later()`), so it is not counted twice.
* Reuse: an existing successful assessment for the same (alert, context `input_hash`,
  model, question-set version) is returned instead of a new paid call.
* Refusals (disabled, budget) are returned but not stored: `ai_assessments` holds one
  row per real provider attempt.

| Status | When | Stored |
|---|---|---|
| `ok` | valid answers | yes |
| `insufficient_context` | `sufficient_context < 0.3` | yes |
| `invalid_output` | answers fail validation | yes |
| `timeout` | per-attempt timeout or retry budget exhausted | yes |
| `rate_limited` | HTTP 429, or 529 (provider overloaded) | yes |
| `error` | other provider or transport errors, input preparation failures | yes |
| `disabled` | flag off or key not usable (the reason names the variable only) | no |
| `budget_exceeded` | daily cap reached | no |

## 9. ai-worker

`extorq ai-worker` (compose service `ai-worker`, identity `extorq_ai`). Each cycle:

1. **Write retries first.** A paid result whose INSERT failed (for example a ClickHouse
   outage) is kept in memory and only its write is retried, with exponential backoff
   (15 s doubling to 600 s, jittered). While any result awaits storage no new provider
   call is made, so a write outage never turns into repeated paid calls. After 12 failed
   writes the result is dropped (logged, `results_dropped_total`) and that context is
   never sent to the provider again by this process.
2. **Queue.** The newest context per alert without a successful triage for its
   `input_hash` (a rebuilt context is triaged again), skipping contexts older than 72 h,
   contexts with 3 failed attempts, and contexts with a failed attempt in the last
   10 minutes.
3. **Unreadable contexts never stall it.** A context the correlation store rejects
   (validation or hash check) is skipped, counted (`cycle_invalid_contexts`,
   `invalid_contexts_total`), logged, remembered for the life of the process and excluded
   from later queue queries; the worker pages past it, examining at most 50 contexts per
   cycle. If a newer context replaced the queued one, the newer one is triaged unless it
   already has a successful triage.
4. Reserve budget, call Jev for up to 10 contexts, store each assessment, and report
   `PipelineHealth(component="ai_worker")` with queue depth, contexts scanned, per-status
   counts, unreadable contexts, results awaiting storage, write retries and dropped
   results; the status is `degraded` with a reason when any of these occur. Failing
   cycles back off exponentially (up to 5 minutes) and are reported as `failed`; when
   Jev is disabled the worker reports `disabled` and makes no queries or calls. The
   worker only reads detection output and cannot slow or block detection.

## 10. Evaluation

**Dataset.** `eval/jev/dataset.jsonl`: 27 SYNTHETIC, author-labelled cases built
deterministically by `eval/jev/build_dataset.py` (documentation-range IPs, invented
actors, fixed timestamps, event shapes from the event catalogue, service-aware contexts;
rebuilt for contract schema 2.0 on 2026-11-22). Every context says "SYNTHETIC evaluation
data" in its limitations and is never written to ClickHouse. GitHub, SSH + HTTP and
Kubernetes each have 3 priority, 3 benign-maintenance, 1 routine and 1
insufficient-context case; the generic domain has 1 priority, 1 benign and 1
insufficient case. The evidence-led routing assigns every case its labelled domain
(asserted by `test_domain_matches_dataset_labels`).

**Baseline** (`extorq.ai.baseline`): severity weight x asset criticality weight x
evidence confidence weight + a bounded bonus for direct and candidate related events;
`insufficient_context` when any source was stale or had a gap and the evidence
confidence is not high; thresholds 3.0 (priority) and 1.5 (routine). It sees nothing
about actors, review signals or maintenance context.

**Method.** One Jev call per case (all questions in one request). Raw answers are
appended to `eval/jev/raw-<date>.jsonl` and reused on re-runs only when they still
validate and match the current question set and model; older lines are skipped and
counted in the report (the 27 lines of `raw-2026-11-21.jsonl` are schema 1.1 and are
never reused). Reports: `eval/jev/results-<date>.{json,md}`.

**Results** of the live run on 2026-11-21 (`jev-1.14.0`, 27 calls, question wording
identical to `triage-v2`):

| Metric | Jev | Baseline |
|---|---|---|
| Accuracy, 4 classes | 77.8% (21/27) | 44.4% (12/27) |
| Accuracy of Jev's own priority choice before ExtorQ's caution guards | 85.2% (23/27) | n/a |
| Insufficient-context cases recognised | 4/4 | 4/4 |
| Order consistency (priority asked twice) | 100% | n/a |
| Uncertain rate | 11.1% | n/a |
| Accuracy when not uncertain | 87.5% (21/24) | n/a |
| Latency mean / p50 / p95 / max | 309 / 303 / 351 / 397 ms | local |
| Input tokens total / mean | 80,313 / 2,975 (about USD 0.0034) | 0 |

Per domain (Jev / baseline): GitHub 87.5% / 50.0%, SSH + HTTP 62.5% / 37.5%,
Kubernetes 75.0% / 37.5%, generic 100% / 66.7%. Where Jev was wrong: no `routine_review`
case was answered correctly (0/3: a maintainer's signed direct push, a valid user's
repeated password failures from an internal host, an in-namespace admin grant were all
rated priority); one benign case (an SSH client offering several keys) was rated
priority; two benign answers were downgraded to `routine_review` by the caution guards
(`maintenance_consistent` 0.47; `privilege_escalation_attempt` 0.81), the intended trade
because a false "routine review" costs less than a false "benign".

That run predates two input changes: the key-field normalisation (synthetic contexts
use flattened names, so they did see their fields; the canonical names differ) and the
type-covering evidence sample. It has not been repeated under the current projection;
the baseline on the rebuilt dataset is unchanged (44.4%, offline run 2026-11-22).

**Real contexts** (2026-11-21, before the clean-slate reset of 2026-11-22): one ai-worker
cycle triaged the 17 alerts then stored for VM-001 (2), VM-002 (1), K8S-001 (4),
K8S-002 (8), GH-001 (1) and CORR-002 (1): 17 calls, all `ok`, latency mean 323 ms
(max 461 ms), 107,321 input tokens. 14 priority_investigation and 3 routine_review; 14 of
17 uncertain. All 12 Kubernetes contexts had borderline context because their `k8s.audit`
coverage was reported stale with a gap (the audit pipeline reported no collector
health), which Jev's `sufficient_context` answers reflected. These alerts were not
labelled, so this run measures behaviour and cost, not accuracy. Metadata (no state, no
key) is in `eval/live/session3-live-2026-11-21.jsonl`; the database rows were cleared
with the reset.

Caveats: synthetic data labelled by the engineer who wrote the questions (optimistic
bias likely), 27 cases, one run, one model version. Treat the numbers as a regression
and sanity check, not a benchmark.

## 11. Running it

```bash
uv run pytest tests/unit/ai tests/ai -q        # fakes only; the storage tests start a throwaway ClickHouse
uv run extorq ai eval                          # baseline only, no network
uv run extorq ai eval --live --max-calls 27    # budgeted Jev evaluation (27 calls)
EXTORQ_AI_LIVE=1 uv run pytest tests/ai/test_ai_live.py -m live_ai -s   # one live call
EXTORQ_JEV_ENABLED=true uv run extorq ai-worker --once   # one worker cycle
EXTORQ_JEV_ENABLED=true uv run extorq ai triage <alert_id>
# Bounded live use (the cap counts attempts already stored that UTC day):
EXTORQ_JEV_ENABLED=true EXTORQ_JEV_DAILY_CAP=<stored today + n> uv run extorq ai-worker --once
```

## 12. Limitations

* Redaction is pattern based; unusual secret formats in telemetry can survive (they are
  still truncated, wrapped as data and sent only when Jev is enabled).
* The evaluation is small, synthetic and from one run under the previous projection
  (section 10); accuracy on real alerts is unmeasured because no real context is labelled.
* Jev's priority answers were very confident (order consistency 100%), so the
  reversed-order check has not yet caught a disagreement on the evaluation set.
* The domain lead sentences were written for the first detections. Newer rule families
  without a dedicated variant (host persistence and accounts, macOS activity, committed
  credentials, web-application alerts in the cluster) use the generic variant; dedicated
  variants would need new wording, a new question-set version and a new evaluation.
* Evidence sampling keeps the first event of each type, which is not necessarily the
  event that opened a detected sequence; stage timestamps are in the detection features.
* The ai-worker's memory of unreadable contexts and of results awaiting storage is per
  process: after a restart, unreadable contexts are loaded once more and a result that
  was never stored costs one new call.
* The transport tests inspect SDK internals of the pinned versions (typesafe-sdk 0.7.5,
  httpx2 2.16.2); an SDK upgrade must re-run them.
* The daily cap can be exceeded by at most (number of concurrent processes - 1) calls.
