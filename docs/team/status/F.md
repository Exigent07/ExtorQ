# Agent F status (Security assurance, QA, documentation)

Last update: 2026-11-21 20:36 IST (build session 2; review pass 2 done; docs reconciled)

## Done
- **Service model documentation (session 2 priority 1):** `docs/architecture.md` section 5
  (hierarchy, identities, kinds, discovery evidence, honesty rules, coverage decision table,
  adapter interface + registry, implemented vs planned adapters, data minimisation,
  Kubernetes levels, storage, correlation, UI drill-down, per-agent status);
  `docs/threat-model.md` T21 (adapter data minimisation), T22 (port mis-attribution and
  misleading coverage), T23 (discovery spoofing), T24 (correlation/hierarchy confusion), service
  records in T12; `AGENTS.md` rewritten (incl. section 7.2 "Add a service adapter", implemented vs
  planned); `docs/known-limitations.md` (planned adapters FTP, PostgreSQL, MySQL, DNS, Redis; Apache
  parser-only; attribution limits ...).
- **Docs baseline + ADRs:** `README.md`, `docs/security.md` (privilege audit), `docs/deployment.md`,
  `docs/operations.md`, `docs/testing.md`, `docs/telemetry-sources.md`, `docs/demo-runbook.md`
  (draft), ADRs 0001-0010 + `docs/adr/README.md` (0010 = service model and adapter registry).
- **Security tests (all F-owned, `tests/security/`):** new `test_security_ingest_redaction.py`,
  `test_security_service_adapters.py`, `test_security_adapter_canaries.py`,
  `test_security_service_identity_binding.py` (F-19 xfail), `test_security_clickhouse_rbac_live.py`
  (integration); SQL scan precision (loop variables over
  module constants) + owner-pragma baseline keyed by function; shell check limited to process calls
  (or literal `shell=True`); frontend scan skips ESLint config and asserts it bans raw HTML;
  gitleaks allowlist entries for public fingerprints / hex labels (narrow, documented).
- **Review pass 2** (table below).

## Session log (IST, from file timestamps)
- 19:58 baseline: `uv run pytest tests/security -q` -> 1 failed (dynamic SQL in C2 harness, F-04,
  F-05), 201 passed, 1 skipped.
- 20:05-20:20 architecture (service model), redaction/adapter tests (suite green 20:09, 268 passed),
  live RBAC probe (20:17, 32 passed), threat model T21-T24, AGENTS.md, known limitations, ADRs,
  security.md, README, deployment, operations, testing, telemetry index, demo runbook.
- 20:20-20:33 review pass 2 (canary tests 20:24); owners fixed F-04/F-05/F-16 (pragmas), F-10, F-14
  meanwhile; suite green again 20:28 (293 passed) after scanner precision fixes; docs reconciled.
- 20:35 final run: 294 passed, 2 xfailed (F-19), live RBAC 32 passed.

## Verified (commands and observed results)
| Claim | Command | Result |
|---|---|---|
| Security suite green (final) | `uv run pytest tests/security -q` (20:35) | 294 passed, 2 xfailed (F-19 identity binding, owner A), 32 deselected (integration), 1 warning (posture-lab hardening tier intentionally skipped) |
| Live RBAC re-run | `uv run pytest tests/security/test_security_clickhouse_rbac_live.py -m integration -q` (20:35) | 32 passed |
| All relative links/anchors in README, AGENTS.md, docs/*.md, docs/adr/*.md resolve | python link checker (GitHub slug rules) | all links ok |
| Security code lint clean | `uv run ruff check tests/security && uv run ruff format --check tests/security` | all checks passed; 18 files already formatted (20:35) |
| Live ClickHouse RBAC = PLAN 4.4 | `uv run pytest tests/security/test_security_clickhouse_rbac_live.py -m integration -q` (20:17) | 32 passed (default user refused 194; ai/api_writer cannot INSERT alerts; rules_ro cannot read alerts/system.users, SET, url(); grafana cannot read events.raw/payload/quarantine excerpt; allowed paths work; zero-row INSERTs only) |
| Gateway redacts every free-text field of all 9 record kinds (incl. service, service_instance) | `uv run pytest tests/security/test_security_ingest_redaction.py -q` | 13 passed; positive control: canary in non-redacted `service_instance.process_name` detected |
| All 16 registered adapters meet data-minimisation and honesty invariants | `uv run pytest tests/security/test_security_service_adapters.py -q` | all passed (B1: apache, auditd, nginx, ssh, systemd, webapp-json; B2: k8s-audit, k8s-container-log, k8s-events; B3: macos-sshd, macos-screensharing; planned: dns, ftp, mysql, postgresql, redis) |
| B1 HTTP adapters strip query/Referer secrets (nginx access, nginx error, apache access, lab portal) | `uv run pytest tests/security/test_security_adapter_canaries.py -q` | 4 passed; positive control: canary in kept user agent detected in `raw` and `http.user_agent` |
| F-02/F-03 fixed: Cf/Co/Cs and TAG chars stripped, U+2028/2029 -> space | python probe `sanitize_untrusted(...)` | output categories only Ll/Lu/Zs |
| F-06 partly fixed | python probe `redact_text` on synthetic CLI forms | redacted: `-p<secret>` (mysql), `--password <x>`, `sshpass -p`, Authorization `Token/ApiKey/Basic` with realistic tokens; NOT redacted: `--requirepass <x>`, `redis-cli -a <x>`, `curl -u user:pass`, `PGPASSWORD=<x>` prefix |
| F-19 cross-asset service binding gap | python probe `prepare_batch` (producer allowed only `linux:lab-vm-01`) | Service with macOS ssh `service_id` and an instance attached to it: both ACCEPTED; API `SERVICE_GET_SQL` selects by `service_id` only (`ORDER BY last_seen DESC LIMIT 1`) |
| gitleaks allowlists stay narrow | gitleaks probe (pinned image, `--network none`) | identical synthetic `api_key` line detected outside E's file, allowed only inside it |
| Documented ops queries are valid | 4 queries from `docs/operations.md` as `extorq_api_ro` | all executed (4, 0, 0, 2 rows) |

## Not verified
- B1 cgroup-based socket attribution (`ss -e --cgroup`) on the live VM (code read only).
- macOS and Kubernetes discovery against live assets (code read only).
- Rotation (`bootstrap.py --rotate`), failure-injection behaviour, Grafana provisioning at runtime.
- Unit/rule/integration suites of other agents (not run by F this session; see their status files).

## Review findings
Severity: High / Medium / Low / Info. "Status" reflects re-checks on 2026-11-21 20:30 IST.

| ID | Severity | Component | File:line | Issue | Recommendation | Status |
|---|---|---|---|---|---|---|
| F-01 | Medium | topology | PLAN 4.2; `infra/vm/vm.sh`; kind via `host.docker.internal` | Lab assets reach host loopback (VM as 10.0.2.2, pods via host.docker.internal), so gateway/API/console/Grafana/(debug) ClickHouse are reachable from attackable assets. | Keep every published service authenticated (true); debug profile off in demos; consider QEMU `restrict=on` after provisioning. | open (by design, documented T18) |
| F-02 | Low | A redaction | `backend/src/extorq/common/redaction.py` | Tag chars, U+2028/2029, soft hyphen survived sanitisation. | Strip Cf; map Zl/Zp. | **resolved** (verified probe) |
| F-03 | Low | A redaction | same | Literal bidi/zero-width chars in source (Trojan Source). | Use escapes/category names. | **resolved** (category names) |
| F-04 | Info | A migrate | `backend/src/extorq/storage/migrate.py` `Migrator.sync_passwords` | f-string `ALTER USER` (reviewed safe). | Add `sql-reviewed` pragma. | **resolved** (pragma present; scan green) |
| F-05 | Info | A spool | `backend/src/extorq/pipeline/spool.py` `Spool.pragma` | `PRAGMA {name}` (reviewed safe). | Add pragma. | **resolved** |
| F-06 | Low | A redaction | `redaction.py` `_RULES` | CLI secrets not redacted. A added Authorization schemes, `--password x`, mysql `-p`, sshpass. Residual: `--requirepass x`, `redis-cli -a x`, `curl -u user:pass`, `PGPASSWORD=x`. | Add these forms (relevant once Redis/PostgreSQL adapters exist); keep F-17 as primary control. | partly resolved |
| F-07 | Info | lead | `contracts/common.py` | NaN/Infinity accepted. | `allow_inf_nan=False`. | **resolved** (F-IC-1 merged) |
| F-08 | Info | lead | `.gitignore` | keys/kubeconfigs outside var/ committable. | F-IC-2. | **resolved** |
| F-09 | Low | host | `.env` (metadata only) | mode 0644 (world-readable); holds AI keys. Re-checked with `stat`, content never read. | `chmod 600 .env` (user/operator). | open |
| F-10 | Low | B2 | `infra/kind/manifests/40-posture-lab.yaml` | weak posture pod mounted node `/var/log`. | Narrow hostPath. | **resolved** (dedicated `/var/log/extorq-posture-lab`) |
| F-11 | Info | B2 | `00-namespaces.yaml` | `extorq-restricted` enforces PSA baseline. | Say "baseline" in demo. | open (doc) |
| F-12 | Info | D1 | `api/auth.py` | service-token holder can assert any user/role. | Token only in frontend; rotate. | accepted |
| F-13 | Info | D2 | `frontend/src/lib/server/session.ts` | stateless 8 h sessions. | Accept for lab. | accepted |
| F-14 | Low | C1 | `config/collectors/github.yaml` | broad `gh auth token` fallback (enabled in the committed config earlier this session). | fine-grained read-only PAT file. | **resolved** (`gh_cli_token_fallback: false`) |
| F-15 | Resolved | D2 | `components/ui/chart.tsx` | `dangerouslySetInnerHTML`. | replaced. | resolved |
| F-16 | Info | C2 | `backend/src/extorq/detection/harness.py` `EphemeralClickHouse._create_users` | `CREATE USER ... BY '{pw}'` f-string in throwaway-container harness (passwords `secrets.token_urlsafe`). | Pragma. | **resolved** (pragma present) |
| F-17 | Medium | B1 | `infra/vm/files/extorq-collect-dispatch` `collect_processes`; `collectors/src/extorq_collectors/linux/inventory.py:221`; `linux/service_records.py:174` | The dispatcher returns the first 256 chars of EVERY process's argv (`/proc/<pid>/cmdline` is world-readable) and the collector now stores them, pattern-redacted, in every process `InventoryItem` and in `ServiceInstance.attributes.args` (ClickHouse `inventory_items` is readable by api_ro and grafana). Redaction misses `--requirepass x`, `redis-cli -a x`, `curl -u user:pass`, `PGPASSWORD=x` (F-06), so credentials passed on command lines can be stored: indiscriminate collection of a secret-bearing field (user requirement 8). | Drop `args` from process inventory items; keep argv[0]/executable only; if a service instance needs arguments, allow-list the flags per adapter (e.g. nginx `-c <path>`) and redact on the VM before transfer. | open |
| F-19 | Medium | A (gateway), D1 (API) | `backend/src/extorq/ingest/processing.py`; `backend/src/extorq/api/repository.py` `SERVICE_GET_SQL`, `SERVICE_INSTANCES_SQL`, `SERVICE_EVENT_SOURCES_SQL`, `SERVICE_AUTH_*` | Service ids are client-supplied and computable; the gateway does not recompute them, and the API reads services, instances and events by `service_id` alone. A producer authorised for asset X can publish a service row (asset X) carrying asset Y's `service_id`, attach instances, or tag events with it; `GET /services/{id}` may then show X's forged row (`ORDER BY last_seen DESC LIMIT 1`) and X's instances/events under Y's service (gateway part verified by probe). | A: quarantine `service` records whose `service_id != service_id(asset_id, kind, key)` and instances whose `instance_id != instance_id(service_id, kind, key)`. D1: resolve the service row by id, then filter instances/events by `service_id` AND asset scope (`asset_id = svc.asset_id OR startsWith(asset_id, svc.asset_id || '/node/')`); prefer the row whose recomputed id matches. | open |
| F-20 | Info | B1, B3 | `linux/discovery.py`, `macos/services.py` | Coverage/attribution of look-alike instances and forwarded ports. B1 binds processes and sockets to units via kernel cgroups (user.slice excluded); B3 attributes ports to the owning pid (QEMU/Docker backend own forwarded ports). | Label forwarder-owned endpoints (e.g. `attributes.port_forwarder=true`) so the Mac's QEMU/Docker services are not read as sshd/nginx; compute `monitored` from the unit the adapter reads. | mostly addressed |
| F-21 | Low | B1, B3 | discovery | Masquerading (`/tmp/sshd`) and churn. B1's cgroup model keeps user processes out of host services; listeners stay "unattributed". | Surface unattributed listeners in the UI; flag process-only services with unexpected paths; bound `service.*` churn per cycle. | open (low) |
| F-22 | Info | E | `tests/unit/ai/test_ai_sanitize.py` | Committed secret-shaped synthetic sample (`api_key: '...'`) trips gitleaks. | Generate at runtime; then F removes the scoped allowlist entry in `tests/security/gitleaks.toml`. | open (allowlisted, scoped to file + line shape) |
| F-23 | Low | B1 | `collectors/src/extorq_collectors/linux/http.py` | nginx error log quotes request lines with query strings. | Strip queries. | **resolved** (verified by canary test) |
| F-24 | Low | B3 | `tests/fixtures/macos/services/launchctl_print_gui.txt` | 2760-line dump of the operator's GUI launchd session committed as a fixture: personal software inventory (privacy); one 64-hex label tripped gitleaks (false positive, allowlisted narrowly). | Trim to the lines the tests need and anonymise third-party labels. | open |

Positive controls confirmed in pass 2 (code read unless "verified"): CI least privilege
(`contents: read`, SHA-pinned actions, `persist-credentials: false`, gitleaks with a
vacuous-scan guard, Trivy fs) (verified by `test_security_ci.py`); compose AI flags default off;
`make down` keeps volumes; gateway quarantines `service_instance` without `asset_id` and per-record
exceptions; producers registry adds service kinds only for host and k8s inventory producers; D2
ESLint bans `dangerouslySetInnerHTML` (verified), every console page calls `requireSession()`,
mutating server actions re-authorise the role; D1 service routes validate 32-hex ids and are
authenticated (verified by `test_security_api_authz.py`); E projects services as names, kinds,
coverage and aliases only (no ids, endpoints, config paths, versions); B1 discovery uses
kernel-attested cgroups for unit attribution and never assumes processes are network services;
B2 Kubernetes records hash sections instead of storing specs; C1 GitHub fallback off.

## Proposals / interface changes
- `docs/team/interface-changes/F.md`: F-IC-1, F-IC-2 merged by the lead; F-IC-3 (docstring
  references), F-IC-4 (identity separator, informational), F-IC-5 (pragma markers) unchanged.

## Blockers
- none

## Next
- Docs reconciled at 20:33 with what landed (Makefile, CI, Grafana, correlation/CORR-002, B1 cgroup
  attribution, B2/B3 discovery, F-10/F-14 fixed). Re-check when owners land: F-19 (A, D1; the two
  xfail tests flip to XPASS), F-17 (B1), F-24 (B3), F-22 (E; then remove the scoped gitleaks
  allowlist entry), `scripts/demo_check.py` and `frontend/Dockerfile` (A, D2), Kubernetes
  simulations (B2), `docs/telemetry/{linux,kubernetes}.md` (B1, B2).
- Finalise `docs/demo-runbook.md` after end-to-end scenario verification.
