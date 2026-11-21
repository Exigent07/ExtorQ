# ExtorQ Task Board

Maintained by the lead. Agents report progress in `docs/team/status/<agent>.md`;
the lead reconciles here. Status: `todo` · `doing` · `blocked` · `done` (implemented)
· `verified` (implemented **and** checked with recorded commands).

## Phase 0 — Foundation baseline (lead)

| # | Task | Owner | Status | Acceptance |
|---|---|---|---|---|
| 0.1 | Environment inventory (tools, Docker, kind, QEMU, gh) | Lead | verified | recorded in final report |
| 0.2 | Verify Jev + Gemini official docs/SDKs | Lead | verified | typesafe-sdk 0.7.5 `system_one` signature; google-genai 3.6.1 `response_json_schema` |
| 0.3 | Contracts v1.0 + event catalog + identities | Lead | verified | smoke test: validation, naive-time rejection, extra-field rejection, catalog checks |
| 0.4 | ClickHouse schema 0001 | Lead | verified | applied on clickhouse-server 26.8.42.13; views tested |
| 0.5 | Team plan, ownership, interfaces | Lead | done | `docs/team/PLAN.md` |

## Phase 1–2 — Build (parallel)

| # | Task | Owner | Status | Depends | Acceptance |
|---|---|---|---|---|---|
| A.1 | bootstrap: secrets, TLS CA/certs, producers registry | A | todo | 0.3 | `make bootstrap` idempotent; files 0600; nothing secret printed |
| A.2 | ClickHouse config, RBAC (0002), migration runner | A | todo | 0.4 | users scoped per PLAN §4.4; `default` has no network access; permission tests pass |
| A.3 | Ingest gateway (auth, authz, limits, validation, redaction, quarantine, OTLP JSON) | A | todo | A.1 | unauthorized → 401/403 + ingest_audit row; malformed → quarantine; 202 only after durable commit |
| A.4 | SQLite spool + writer (batched, bounded retries, dead letter, health) | A | todo | A.3 | events survive gateway restart and ClickHouse outage; duplicates collapse |
| A.5 | Collector SDK (outbox, checkpoints, sender, runner, health, sim-record) | A | todo | A.3 | atomic outbox+checkpoint; buffered while gateway down; per-collector failure isolation |
| A.6 | compose stack, Makefile, CI, first vertical slice | A | todo | A.1–A.4 | event inserted via HTTPS appears in ClickHouse; `STACK READY` in status/A.md |
| B1.1 | Ubuntu VM via QEMU/HVF + cloud-init (users, sshd hardening, auditd, nginx, lab app, dispatch) | B1 | todo | — | `make vm-up` reproducible; collector key restricted to dispatch allow-list |
| B1.2 | Linux SSH collector (journald cursor, auditd offsets, inventory diff, posture) | B1 | todo | A.5 | real VM events in ClickHouse; restart resumes from checkpoint |
| B1.3 | macOS native collector (unified log, launchd, posture, inventory) | B1 | todo | A.5 | real host data in ClickHouse; gaps reported in health |
| B1.4 | VM-001, VM-002, HTTP probe simulations (+cleanup) | B1 | todo | B1.1 | genuine telemetry; reversible |
| B2.1 | Kind `extorq-lab` with audit policy + PSA namespaces | B2 | todo | — | audit log file populated; privileged pod denied in restricted ns |
| B2.2 | OTel Collector DaemonSet → gateway OTLP (container + audit logs), least privilege | B2 | todo | A.3 | pod logs + audit events in ClickHouse; persistent queue |
| B2.3 | K8s inventory/posture collector (read-only SA) | B2 | todo | A.5 | inventory diff events + posture findings tied to scan runs |
| B2.4 | K8S-001, K8S-002 simulations (+cleanup) + lab workloads | B2 | todo | B2.1 | genuine audit evidence |
| C1.1 | GitHub collector (pagination, rate limits, ETags, checkpoints, gaps) + workflow analyzer | C1 | todo | A.5 | commits/workflow runs/settings ingested; unavailable features recorded as gaps |
| C1.2 | Scanners: Trivy, Gitleaks (redacted), Semgrep → ScanRun + findings; posture checks | C1 | todo | A.5 | findings associated with scan runs; failed scans never resolve findings |
| C1.3 | `v_findings_current` lifecycle view (0003) + tests | C1 | todo | 0.4 | partial/failed scans keep findings open/unverified |
| C1.4 | Lab repo content + GH-001 simulation (push only after lead go-ahead) | C1 | todo | user approval | genuine GitHub telemetry |
| C2.1 | Rule format, registry, validator, rule test harness (ephemeral ClickHouse) | C2 | todo | 0.4 | positive + negative fixtures per rule |
| C2.2 | Detection engine + detector service (windows, late events, identities, dedup, rule_runs) | C2 | todo | A.2 | duplicate submissions do not inflate alerts; failures visible |
| C2.3 | Rules VM-001, VM-002, K8S-001, K8S-002, GH-001 (+HTTP-001, CORR-001, MAC-001, K8S-APP-001 if time) | C2 | todo | C2.1 | each rule has FP/FN documentation |
| C2.4 | Correlation + InvestigationContext builder (direct/candidate/unestablished, coverage, gaps) | C2 | todo | C2.2 | uncertainty preserved; stable input hash |
| D.1 | Analyst API (auth, roles, parameterised queries) | D | todo | A.2 | all endpoints return real data; viewer cannot mutate |
| D.2 | Next.js + shadcn console (Overview, Assets, Detections, Investigation, Health) | D | todo | D.1 | no fabricated metrics; stale/missing states visible |
| D.3 | Grafana provisioning + dashboards (official ClickHouse plugin) | D | todo | A.2 | dashboards render real data with read-only user |
| E.1 | Jev triage provider (typed questions, insufficient-context logic, validation, audit) | E | todo | 0.3 | timeout never blocks detection; output versioned |
| E.2 | Gemini summary provider (structured output, evidence-id verification, injection defence) | E | todo | 0.3 | hallucinated ids never shown as verified |
| E.3 | Budgets/flags, ai-worker, AIService for API | E | todo | E.1–E.2 | bounded usage; graceful failure |
| E.4 | Labelled evaluation set + Jev vs deterministic comparison | E | todo | E.1 | results recorded honestly |
| F.1 | Threat model, security architecture, privilege audit | F | todo | 0.5 | covers all threats in brief §13 |
| F.2 | Docs set + ADRs + README/AGENTS.md | F | todo | builds | accurate to implemented behaviour |

## Phase 3+ — Integration, scenarios, review, final verification
Scheduled by the lead after the build phase (see final report).
