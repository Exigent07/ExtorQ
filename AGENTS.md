# AGENTS.md — ExtorQ Engineering Guide (canonical)

This is the canonical guide for AI agents and human engineers working on ExtorQ.
`CLAUDE.md` only imports this file. Scoped guides live next to components
(`backend/AGENTS.md`, `collectors/AGENTS.md`, `rules/AGENTS.md`, `frontend/AGENTS.md`,
`infra/kind/AGENTS.md`). Build-time ownership and interfaces: `docs/team/PLAN.md`.

## What ExtorQ is

A security telemetry, detection, correlation and investigation platform (a
"mini SIEM") monitoring four asset classes: a **macOS host**, an **Ubuntu VM**, a
**Kind Kubernetes cluster** (control plane + workloads) and **GitHub repositories**.

Core principle: **deterministic collection and detection establish the evidence;
AI assists interpretation and is never authoritative.**

Pipeline: collection/scanning → authenticated ingestion → durable SQLite spool →
ClickHouse → versioned SQL detections → correlation → InvestigationContext →
optional AI enrichment (Jev triage, Gemini summary) → analyst console + Grafana.

### Goals
Real telemetry from all four assets; reliable, restart-safe storage; five working
detections (VM-001, VM-002, K8S-001, K8S-002, GH-001) driven by genuine scenario
telemetry; security posture findings tied to actual scans; evidence-traceable
alerts; honest health/staleness signals; a polished analyst console.

### Non-goals
EDR-grade process/network telemetry; autonomous response or remediation; AI
detections; multi-tenant SaaS; exactly-once delivery; claiming org audit-log or
enterprise-only GitHub features without access.

## Repository layout

| Path | Contents |
|---|---|
| `backend/src/extorq/contracts` | Versioned Pydantic contracts, event catalog, identities (**single source of truth**) |
| `backend/src/extorq/{common,storage,ingest,pipeline}` | config/logging/redaction, ClickHouse access, gateway, spool writer |
| `backend/src/extorq/{detection,correlation}` | rule engine, alert identity, context builder |
| `backend/src/extorq/ai` | Jev triage, Gemini summaries, budgets, evaluation |
| `backend/src/extorq/api` | analyst read API |
| `collectors/src/extorq_collectors` | collector SDK + macOS, Linux (SSH), Kubernetes, GitHub collectors |
| `scanners/` | Trivy, Gitleaks, Semgrep integrations |
| `rules/` | detection rules (YAML metadata + SQL) and their test fixtures |
| `simulations/` | safe, reversible attack scenarios for lab assets |
| `infra/` | compose, ClickHouse, Grafana, Kind, VM, TLS |
| `frontend/` | Next.js + shadcn/ui console |
| `tests/` | unit, integration, failure, security, rules, AI tests |
| `docs/` | architecture, data model, threat model, runbooks, ADRs |
| `var/` | **local runtime state and secrets — gitignored, never commit** |

## Security invariants (non-negotiable)

1. **Never print, log, commit or transmit secrets.** `.env` holds `JEV_API_KEY` and
   `GEMINI_API_KEY`: do not overwrite, rename, delete, cat or echo it. Generated
   secrets live in `var/secrets/` (0600). Startup checks name missing settings,
   never values. Tokens, passwords, Authorization headers and API keys must be
   redacted from logs, errors, fixtures, docs, screenshots and AI prompts.
2. **All telemetry is untrusted input.** Log lines, commit messages, HTTP paths,
   user agents, Kubernetes object fields and workflow YAML may be attacker-controlled.
   Validate, bound, sanitise; never render as HTML; never let it become instructions
   to an LLM; never interpolate it into SQL or shell commands.
3. **Least privilege everywhere.** Scoped ClickHouse users per service; read-only
   identities for analysts/Grafana; collectors read-only; no secrets RBAC in
   Kubernetes; the VM collector account can only run a fixed allow-list of
   read-only commands.
4. **Authoritative data is deterministic.** Only the detector writes alerts. AI
   writes only `ai_assessments`, cannot change severity, suppress, delete or
   remediate anything.
5. **No exposure.** Services bind to 127.0.0.1 or internal Docker networks.
   ClickHouse is never exposed to an untrusted network. No unauthenticated
   access to telemetry. Browser code never sees DB or API credentials.
6. **Unknown stays unknown.** Never invent telemetry fields or fabricate metrics,
   detections or test results. Demonstrations use real scenario telemetry.
7. **No dangerous capabilities.** Never disable SIP or host security controls,
   never build "unstoppable" agents, never run attacks outside lab assets.

## Actions requiring explicit human authorization
Pushing to any remote; creating/modifying GitHub repositories or settings;
deleting volumes/databases containing collected data; touching clusters/VMs not
created by ExtorQ (e.g. `motorq-security`); disabling security controls; raising
AI usage limits; sending data to any new third-party service.

## Development conventions

* Python 3.12 via `uv` (`uv run …`); ruff + mypy; pytest markers
  `integration | lab | live_ai | failure` (excluded by default).
* Contracts change only through `docs/team/interface-changes/` → lead review.
  Breaking identity changes bump the namespace version, never edit in place.
* ClickHouse: server-side parameters (`{name:Type}`) only; duplicate-safe queries
  (`uniqExact(event_id)`, `argMax`, `FINAL`); remember sorting keys are not unique.
* Every network call: timeout + bounded retries with jittered backoff.
* Subprocesses: argument lists, no `shell=True`, validated arguments.
* Structured JSON logging through `extorq.common.logging`.
* Docs describe implemented behaviour only; label future work **planned**.
* Never claim a test passed without running it; record exact commands + results.

## Common commands (Makefile is the entry point)

`make bootstrap` (secrets, TLS, deps) · `make up` / `make down` · `make migrate` ·
`make vm-up` · `make kind-up` · `make collectors` · `make scan` ·
`make sim-<scenario>` · `make test` · `make test-integration` · `make lint` ·
`make typecheck`. See `README.md` and `docs/deployment.md`.

## Keeping docs and architecture in sync
Any change to a contract, table, port, privilege, rule or trust boundary updates
the matching doc in the same change (`docs/data-model.md`, `docs/threat-model.md`,
`docs/detection-catalog.md`, `docs/telemetry-sources.md`, `docs/security.md`).
