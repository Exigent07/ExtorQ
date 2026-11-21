# Testing

Owner: agent F. Strategy for every test layer and a results log that contains
**only results that were actually produced**, with the exact command, date and
outcome. "Not yet run" means exactly that. Owners record their own runs in
`docs/team/status/<agent>.md`; this page collects them as they are verified.

## 1. Strategy

| Layer | Location | Runs without the stack | Purpose | Owner |
|---|---|---|---|---|
| Unit | `tests/unit/<area>/` | yes | parsers from real, scrubbed fixtures; normalisation; contracts; API with fakes at the repository boundary | per area |
| Rules | `tests/rules/`, `rules/<platform>/tests/<ID>/*.jsonl` | needs Docker (ephemeral ClickHouse `extorq-c2-*`) | every rule has positive and negative fixtures; engine properties (idempotent re-runs, late evidence, dedup) | C2 |
| Integration | `tests/integration/` (marker `integration`) | no: compose stack | gateway 401/403 + `ingest_audit`, end-to-end ingest, API SQL against ClickHouse, live RBAC | A, D1, F |
| Lab | marker `lab` | no: VM, kind, GitHub | collectors against real lab assets | B1, B2, B3, C1 |
| Failure | `tests/failure/` (marker `failure`, serial, platform owner only) | no | gateway restart, ClickHouse outage, spool replay, writer dead letters | A (planned) |
| AI | `tests/ai/`, `eval/` (live calls only with marker `live_ai` and a granted budget) | yes, except `live_ai` | prompt-injection defences, evidence-id verification, evaluation harness | E |
| Security | `tests/security/` | yes (Docker for gitleaks; live RBAC is `integration`) | invariants from AGENTS.md section 3 | F |

Defaults: `uv run pytest -q` (`make test`) runs everything except the
`integration`, `lab`, `live_ai` and `failure` markers (`pyproject.toml`).
Select a marker explicitly, for example
`uv run pytest -m integration tests/security -q`. CI
(`.github/workflows/ci.yml`) runs ruff, mypy, the default pytest selection, the
frontend lint/typecheck/build, gitleaks over the full history and Trivy
filesystem scans.

Fixture policy: fixtures come from real tool output, scrubbed of secrets and
personal data; synthetic fixtures are labelled synthetic in their file name or
content; no fixture contains a secret-shaped value (enforced by gitleaks).
Unit tests never call external services; AI unit tests never call providers.

## 2. Security test suite (`tests/security/`)

| File | What it enforces |
|---|---|
| `test_security_repo_hygiene.py` | `.env`, `var/`, keys, tokens, kubeconfigs are gitignored and not committable; `.dockerignore` excludes secrets |
| `test_security_secret_scan.py` | gitleaks (pinned image, `--redact`, network-less container) over committable files and git history, with a positive control |
| `test_security_python_static.py` | no shell execution, no SQL built from dynamic strings (AST), no `eval`/unsafe deserialisation, TLS verification never disabled; reviewed exceptions need an owner pragma |
| `test_security_frontend_static.py` | no raw-HTML sinks, no browser credentials, no secret `NEXT_PUBLIC_*`; ESLint config bans `dangerouslySetInnerHTML` |
| `test_security_containers.py` | loopback-only ports, ClickHouse unpublished except the debug profile, internal data network, non-root and hardened services, pinned images, AI keys only where needed |
| `test_security_ci.py` | least-privilege workflow permissions, SHA-pinned actions, no script injection (skips until workflows exist) |
| `test_security_lab_boundaries.py` | Kubernetes RBAC without secrets or write verbs, workload hardening, audit policy, kind and QEMU bind loopback |
| `test_security_rule_sql.py` | rule SQL is a single parameterised read-only statement over allowed tables |
| `test_security_api_authz.py` | every analyst API route requires the principal; mutations require `analyst` |
| `test_security_prompt_injection_corpus.py` | 47-case synthetic injection corpus (`tests/security/fixtures/`, reusable by E) and the gateway sanitiser contract |
| `test_security_ingest_redaction.py` | runtime-generated canary secrets in every free-text field of all nine record kinds never reach the spool payload or quarantine excerpts |
| `test_security_service_adapters.py` | adapters declare `never_collects` with per-category minimums; planned adapters stay silent and never "monitored"; ports never identify products; discovery needs evidence; lab log formats do not log query strings, bodies, cookies or Authorization |
| `test_security_adapter_canaries.py` | implemented HTTP adapters (nginx access/error, Apache, lab portal) strip secrets in query strings and Referer values from emitted events |
| `test_security_service_identity_binding.py` | correctly derived service records are accepted; records carrying another asset's `service_id` or an underived `instance_id` must be rejected (`xfail` until F-19/F-IC-6 lands) |
| `test_security_clickhouse_rbac_live.py` (`integration`) | each ClickHouse identity is denied outside PLAN 4.4 (zero-row probes only) |

## 3. Results log

| Date (IST) | Suite | Command | Result | Recorded by |
|---|---|---|---|---|
| 2026-11-21 20:09 | security (static + Docker) | `uv run pytest tests/security -q` | 268 passed, 1 skipped (no CI workflows yet), 3 warnings naming owner-pending pragmas | F |
| 2026-11-21 20:17 | security, live RBAC | `uv run pytest tests/security/test_security_clickhouse_rbac_live.py -m integration -q` | 32 passed | F |
| 2026-11-21 20:35 | security (final run of the session) | `uv run pytest tests/security -q` | 294 passed, 2 xfailed (F-19 identity binding, owner A), 32 deselected (integration), 1 warning | F |
| 2026-11-21 20:35 | security, live RBAC (re-run) | `uv run pytest tests/security/test_security_clickhouse_rbac_live.py -m integration -q` | 32 passed | F |
| 2026-11-21 20:28 | security (after other agents' changes; scanner precision fixes) | `uv run pytest tests/security -q` | 293 passed, 32 deselected (integration), 1 warning (posture-lab workload intentionally weak) | F |
| 2026-11-21 20:24 | security, adapter canaries | `uv run pytest tests/security/test_security_adapter_canaries.py -q` | 4 passed (nginx access/error, Apache access, lab portal) | F |
| 2026-11-21 | unit (all areas) | `uv run pytest -q` | not yet run by F in this session; see owners' status files | n/a |
| 2026-11-21 | rules | `uv run extorq rules test` | not yet run by F; see C2 status | n/a |
| 2026-11-21 | integration (gateway, API) | `uv run pytest -m integration -q` | not yet run by F; see A and D1 status | n/a |
| 2026-11-21 | failure injection | `uv run pytest -m failure -q` | not yet run (suite not present) | n/a |
| 2026-11-21 | lab (VM, kind, GitHub) | `uv run pytest -m lab -q` | not yet run by F | n/a |
| 2026-11-21 | AI evaluation | see `eval/` and E status | not yet run by F | n/a |

## 4. Scenario verification (planned)

Each demo scenario (VM-001, VM-002, K8S-001, K8S-002, GH-001, and CORR-002 when
built) is verified end to end: run the simulation, wait for collection, then
check that the expected rule fired on genuine telemetry and that the alert's
evidence carries the `extorq-sim-<run_id>` marker. Tooling: `simulations/lib`
(C2, in progress). Results will be added to the log above with the run ids.
