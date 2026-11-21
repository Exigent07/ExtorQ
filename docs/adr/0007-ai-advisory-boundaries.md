# ADR 0007: AI boundaries: Jev advisory triage, Gemini on-demand summaries, no authority

Status: accepted, implemented (`backend/src/extorq/ai/`). Date: 2026-11-21.

## Context
AI can help analysts read evidence, but telemetry is attacker-controlled
(prompt injection), model output can be wrong, and sending data to third
parties has confidentiality costs. Detection must work with both providers
unavailable.

## Decision
* Jev (TypeSafe) performs advisory triage in the `ai-worker`; Gemini (Google)
  writes summaries only when an analyst requests one (`POST
  /api/v1/alerts/{id}/summary`, analyst role).
* Both are disabled by default (`EXTORQ_JEV_ENABLED`, `EXTORQ_GEMINI_ENABLED`),
  have daily call caps, timeouts and bounded retries.
* Input is an allow-listed projection of the hashed `InvestigationContext`,
  cleaned (control and format characters removed, secrets redacted, evidence-id
  shapes masked, markup neutralised, per-field limits).
* Output is cleaned again; every cited evidence id is checked against the
  bundle and unknown ids are shown as unverified.
* Results are written only to `ai_assessments` (ClickHouse identity
  `extorq_ai` cannot write alerts) and are labelled advisory. AI never changes
  severity, state or alerts and has no tools.

## Consequences
* Detection, correlation and the console work without AI.
* Injected text can still bias advisory wording; it cannot change authoritative
  data.
* When enabled, sanitised lab telemetry leaves the host (threat model T09).

## Alternatives considered
* AI-generated detections or automated response: rejected (non-deterministic
  authority over evidence).
* Local models only: better confidentiality, weaker quality on this hardware.
