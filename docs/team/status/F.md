# Agent F status (Security assurance, QA, documentation)

Last update: 2026-11-22 02:09 IST (build session 3 complete for F: final runbook, testing results,
F-19 markers, F-22 check, consistency audit, security suite). Session 3 progress is logged in
"Session 3" below; the session 2 record follows unchanged.

## Session 3 (2026-11-22, IST; times before 01:48 are approximate, later ones from `date`)
- ~01:36 started; read PLAN (sections 10, 11), AGENTS.md, all status files, owned docs.
- ~01:39 baseline `uv run pytest tests/security -q -rxXs` -> 294 passed, 2 xpassed (F-19), 32
  deselected, 2 warnings (api/ai-worker rootfs writable; posture-lab deliberately weak), 8.91 s.
- ~01:42 F-19 markers removed in `tests/security/test_security_service_identity_binding.py`; the
  negative cases now also assert that the record is quarantined with a reason starting
  `identity_mismatch` (not denied, not failing for another reason);
  `uv run pytest tests/security/test_security_service_identity_binding.py -q` -> 3 passed.
- ~01:42 F-22 check: `tests/unit/ai/test_ai_sanitize.py:75` still holds the literal `api_key`
  sample; E lists F-22 as session-3 item 4 (not done yet) -> allowlist entry kept for now.
- ~01:43 read-only facts for the runbook (debug proxy, `extorq_api_ro`): `make demo-check` (core
  platform ready, migrations 0001-0006, collectors linux/macos/k8s-inventory STALE since
  2026-11-21 ~15:20 UTC, no `frontend` or `ai-worker` container running); alert ids, severities,
  confidences and features of every verified run; GitHub collector health gaps (branch
  protection/rules/rulesets 403 "Upgrade to GitHub Pro", token_source gh_cli with breadth warning).
- ~01:44 unauthenticated probes: gateway `/healthz` 200, `POST /v1/ingest` without token 401, API
  `/api/v1/alerts` without token 401, Grafana API 401, console 127.0.0.1:3000 not listening,
  127.0.0.1:8123 not listening.
- ~01:46 full security suite: 1 failed (gitleaks: new secret-shaped literal in A's in-progress
  `tests/unit/platform/test_platform_gateway.py:414`), 295 passed. 01:48 re-run of
  `tests/security/test_security_secret_scan.py` -> 3 passed: A had already changed the literal to
  be built at runtime (file mtime 01:47:57). No finding raised.
- 01:48 `docs/demo-runbook.md` rewritten as the final runbook (verified reference runs with alert
  ids, pre-flight, minute-by-minute script, fallbacks, cleanup).
- 01:48 `uv run pytest tests/security -q -rxXs` -> 296 passed, 32 deselected, 2 warnings.
- 01:49 `uv run pytest tests/security/test_security_clickhouse_rbac_live.py -m integration -q` -> 32 passed.
- 01:50 `docs/testing.md` rewritten with real results only (lead 1738 passed / mypy clean; owners'
  latest recorded runs; F runs; failure tests; AI live record; scenario table with alert ids;
  explicit not-verified list incl. untracked macOS fixtures used by tests/unit/macos).
- 01:51-01:54 consistency audit, part 1 (README, deployment, operations, runbook, security):
  `make -n` for every documented target: up-full, vm-up, kind-up, collectors, demo-check, sim-*,
  test-security, test-failure, up-debug, ps exist; **`up-demo` and `collectors-start` do not exist**
  (A plans them in session 3). `make sim-gh-001` without `ARGS="--repo ..."` dies (`--repo is
  required`); `make sim-cleanup SCENARIO=gh-001 RUN_ID=x` runs the script without `--repo` -> fails
  (reported to A/C1). CLI help checked: `extorq` (migrate, gateway, writer, version, detector,
  ai-worker, api, rules validate|test (pass-through `--only`), context build, ai triage|summary|eval),
  `extorq-collect` (run --only/--once/--config, status, flush, sim-record), `extorq-scan` (run,
  update, flush, list, validate), `bootstrap.py --rotate/--rotate-ca`, `vm.sh` and `kind.sh`
  subcommands incl. `kind.sh kubeconfig`. `docker compose [--profile debug] stop clickhouse-debug` OK
  (`--dry-run`). Operations queries: 5/5 execute as `extorq_api_ro` (13, 4, 22, 3, 15 rows). Runbook
  Explore queries execute as `extorq_grafana`; `SELECT raw FROM extorq.events` refused.
  security.md vs compose/0002/0004/0005/0006: identities, profiles, quotas, TTLs, ports match; fixed
  api/ai-worker read-only claim (compose: `read_only: false`), added kind API server port, the
  extorq-selftest producer, 0006, gh CLI token (PLAN 11), F-06 resolved, F-19 gateway part done,
  retention 90 d (deployed: `/v1/status` limits.event_retention_days 90 at 01:54).
  README: status, extra rules, all sim targets, GH-001 needs --repo, stale 'being added' removed.
- 01:55-01:57 consistency audit, part 2: `docs/known-limitations.md` (S7 F-06 resolved; C3 NAT incl.
  kind gateways; C4 no EDR on macOS; C6 polling; C7 GitHub free-plan gaps observed on the private
  repo; C8 gh CLI token breadth (approved, PLAN 11); C9 24 h inventory token; P9 90-day retention at
  the gateway; P10 writable rootfs api/ai-worker; D5 Gemini quota/latency; D6 synthetic Jev eval;
  D7 SimulationRun keyed by run_id), `docs/telemetry-sources.md` (GitHub token, plan gaps, per-source
  docs present), `AGENTS.md` (component guides present, migrations 0005/0006, commands),
  `docs/architecture.md` (stale 'in progress' statuses, extra rules, catch-up, drill-down API),
  `docs/threat-model.md` (F-19 gateway done/API open, F-06 resolved, gh CLI token, verification
  rows for integration and failure tests, open items, change log), ADR 0006 (2026-11-22 update).
- 01:58 `docs/team/interface-changes/F.md`: F-IC-7 (GH-001 make targets need --repo; A, C1), F-IC-8
  (one run id per scenario in the CORR-002 recipe; C2), F-IC-9 (commit minimised macOS fixtures;
  B3), table of doc mismatches in others' files (A data-flow 400 d, C1 github.md 400 d, E
  ai-integrations E-IC-1 note, C2 attack-scenarios GH-001 --repo and CORR-002 run id).
- 01:59 **F-22 resolved**: E builds the sample at runtime (no `api_key` literal left in
  `tests/unit/ai/test_ai_sanitize.py`). The working-tree allowlist entry was removed; history is
  immutable, so it was replaced by a history-only entry (`commits = [4ee5baa...]` AND the path).
  `uv run pytest tests/security/test_security_secret_scan.py -q` -> 3 passed. Controls (pinned
  gitleaks, hardened container, scratch driver): history without any F-22 entry -> 1 finding
  (`test_ai_sanitize.py:75`, commit 4ee5baa); history with the new entry -> 0; old literal
  re-introduced in a working-tree copy of the same path -> 1 finding (not hidden). No leftover
  `extorq-f-gitleaks-*` containers.
- 02:00 A landed `make up-demo`, `collectors-start|stop|status` (`scripts/collectors_ctl.py`), started
  the background collectors and the compose `frontend` + `ai-worker`; runbook pre-flight and
  outage segment rewritten to use them (`make collectors-stop` at 7:45, `make collectors-start`
  at 12:30; staleness is 3 x interval per source); README, AGENTS.md, deployment, operations updated.
- 02:01 D2's smoke (`node scripts/smoke.mjs --base http://127.0.0.1:3000`, script as of 02:00) against
  the compose console: 98 passed, 5 failed; all 5 failing checks are new in D2's uncommitted script
  (K8s node workloads view/links, detections rule/asset filters) and the image (built 01:56)
  predates D2's latest changes. Ran it twice; right after, `make demo-check` -> NOT READY: API 503,
  ClickHouse unreachable: `extorq_api_ro` quota exceeded (`queries = 1374/1200` per minute). 02:02
  `make demo-check` -> **DEMO READY: all checks passed** (WARN proxy running, token ~18.1 h left).
- 02:03 `uv run pytest tests/security -q -rxXs` -> 296 passed, 32 deselected, 2 warnings; ruff check
  + format --check on tests/security clean (18 files).
- 02:05 B3 minimised the macOS fixtures (`launchctl_print_gui.txt` 123 KB -> 1.4 KB); no
  `EAAA[0-9A-F]{60}` string left in the tree (`grep -rlE`) or in git history (`git log --all -G`),
  so F removed the F-24 `square-access-token` allowlist entry from `tests/security/gitleaks.toml`;
  `uv run pytest tests/security/test_security_secret_scan.py -q` -> 3 passed (02:05).
- 02:05 security.md: quotas (api 1200/min, grafana 600/min), exact scanner/simulation asset patterns
  (match `bootstrap.py` PRODUCERS), compose console row; ADR 0009 rootfs exception (api/ai-worker).
- 02:07 read-only read-back of `extorq.ai_assessments` (`extorq_api_ro`): E's session-3 live calls
  stored 17 Jev `triage-v2` assessments (all ok, 284-461 ms) and the first Gemini `summary-v3`
  summaries of real alerts: GH-001 e7063925 (22.9 s, 17/17 evidence ids verified, 0 rejected) and
  CORR-002 b46da380 (25.9 s, 64/64, 0 rejected). Runbook AI segment, known limitations D5/D6 and
  testing.md 3.6 updated with these records.

## Session 3 summary (current)

### Done
- `docs/demo-runbook.md` final: verified reference runs (run ids, alert ids, severity/confidence),
  stored AI records, pre-flight with A's targets (`up-full`/`up-demo`, `vm-up`, `kind-up`,
  `collectors-start`, `demo-check`), minute-by-minute script (architecture, four assets, five
  scenarios with exact commands and what to show in console/Grafana/ClickHouse, CORR-002 and NAT,
  Jev and Gemini, collector outage and ClickHouse outage story, security boundaries,
  limitations), validated Grafana Explore SQL, fallbacks, cleanup.
- `docs/testing.md`: real results only (lead, owners, F), scenario table, explicit not-verified list.
- `tests/security/test_security_service_identity_binding.py`: F-19 xfail markers removed, reason
  asserted. `tests/security/gitleaks.toml`: F-22 working-tree entry replaced by a history-only
  commit+path entry; obsolete F-24 EAAA entry removed.
- Consistency audit and fixes: README, AGENTS.md, architecture, threat model, security,
  deployment, operations, known limitations, telemetry index, ADR 0006, ADR 0009. Mismatches in
  others' files: `docs/team/interface-changes/F.md` (F-IC-7..9 and the mismatch table).

### Verified (session 3)
| Claim | Command | Result |
|---|---|---|
| Security suite green | `uv run pytest tests/security -q -rxXs` (02:03, final run 02:08) | 296 passed, 32 deselected, 2 warnings (both times) |
| Live RBAC unchanged | `uv run pytest tests/security/test_security_clickhouse_rbac_live.py -m integration -q` (01:49, final run 02:08) | 32 passed (both times) |
| Security code lint/format | `uv run ruff check tests/security`; `uv run ruff format --check tests/security` (02:03) | all checks passed; 18 files formatted |
| Secret scan after allowlist changes | `uv run pytest tests/security/test_security_secret_scan.py -q` (01:59, 02:05) | 3 passed; F-22 negative controls as logged above |
| Every documented make target exists | `make -n <target>` for all targets in README/AGENTS/deployment/operations/runbook | all exist (since ~02:00 incl. `up-demo`, `collectors-start/stop/status`); GH-001 targets need `ARGS="--repo ..."` (F-25) |
| CLI subcommands exist | `--help` of `extorq`, `extorq rules/context/ai/detector/ai-worker`, `extorq-collect run`, `extorq-scan`, `bootstrap.py`, `collectors_ctl.py`; `vm.sh`/`kind.sh` dispatch tables | all documented subcommands present |
| security.md matches compose and migrations | read `compose.yaml`, `0002`, `0004`, `0005`, `0006`, `bootstrap.py` PRODUCERS | identities, profiles, quotas, TTLs, ports, producers match after fixes (api/ai-worker rootfs, kind API port, selftest producer, quotas) |
| Documented queries run | operations queries as `extorq_api_ro`; runbook queries as `extorq_grafana` | 5/5 and 3/3 executed; `SELECT raw` refused for `extorq_grafana` |
| All doc links resolve | scratchpad link checker over README, AGENTS.md, docs/*.md, docs/adr/*.md | 30 files, 0 problems |
| Unauthenticated access refused | curl probes (01:44, 02:04) | ingest 401, API 401, Grafana 401, console 303 to /login with CSP/XFO/nosniff/no-referrer; 8123 not listening |
| Gateway retention limit deployed | `/v1/status` via demo_check's client (01:54) | `event_retention_days: 90`, `max_future_seconds: 86400` |
| Demo readiness | `make demo-check` (02:02) | DEMO READY: all checks passed (WARN debug proxy up, token ~18.1 h) |
| Compose console | `node scripts/smoke.mjs --base http://127.0.0.1:3000` (02:01) | 98 passed, 5 failed (new D2 checks vs older image) |
| F-06 residual forms | python probe of `redact_text` (8 synthetic forms) | all redacted |

### Not verified (by F this session)
- Full repository suite and mypy (lead's 1738 passed / clean cited, not re-run by F).
- Failure tests (A only), rotation, CI on GitHub, live simulations (not re-run; lead verified).
- The demo-day path itself: fresh simulations at T+0, latency to alerts, `make up-demo` with AI on.
- D2's smoke against the final rebuilt console image.

### Blockers
- none

### Next (owners)
- D1: F-19 API part (asset-scoped instance/event joins). B1: F-17. A/C1: F-25. C2: F-26 (doc).
  B3 + lead: commit minimised macOS fixtures (F-27). Operator: `chmod 600 .env` (F-09),
  `infra/kind/kind.sh token` on demo day. D2: re-run smoke after the final image rebuild.

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
Severity: High / Medium / Low / Info. "Status" reflects re-checks on 2026-11-21 20:30 IST, updated
2026-11-22 (session 3) where stated.

| ID | Severity | Component | File:line | Issue | Recommendation | Status |
|---|---|---|---|---|---|---|
| F-01 | Medium | topology | PLAN 4.2; `infra/vm/vm.sh`; kind via `host.docker.internal` | Lab assets reach host loopback (VM as 10.0.2.2, pods via host.docker.internal), so gateway/API/console/Grafana/(debug) ClickHouse are reachable from attackable assets. | Keep every published service authenticated (true); debug profile off in demos; consider QEMU `restrict=on` after provisioning. | open (by design, documented T18) |
| F-02 | Low | A redaction | `backend/src/extorq/common/redaction.py` | Tag chars, U+2028/2029, soft hyphen survived sanitisation. | Strip Cf; map Zl/Zp. | **resolved** (verified probe) |
| F-03 | Low | A redaction | same | Literal bidi/zero-width chars in source (Trojan Source). | Use escapes/category names. | **resolved** (category names) |
| F-04 | Info | A migrate | `backend/src/extorq/storage/migrate.py` `Migrator.sync_passwords` | f-string `ALTER USER` (reviewed safe). | Add `sql-reviewed` pragma. | **resolved** (pragma present; scan green) |
| F-05 | Info | A spool | `backend/src/extorq/pipeline/spool.py` `Spool.pragma` | `PRAGMA {name}` (reviewed safe). | Add pragma. | **resolved** |
| F-06 | Low | A redaction | `redaction.py` `_RULES` | CLI secrets not redacted. A added Authorization schemes, `--password x`, mysql `-p`, sshpass. Residual: `--requirepass x`, `redis-cli -a x`, `curl -u user:pass`, `PGPASSWORD=x`. | Add these forms (relevant once Redis/PostgreSQL adapters exist); keep F-17 as primary control. | **resolved** (re-checked 2026-11-22: all residual forms redacted by `redact_text`, F probe) |
| F-07 | Info | lead | `contracts/common.py` | NaN/Infinity accepted. | `allow_inf_nan=False`. | **resolved** (F-IC-1 merged) |
| F-08 | Info | lead | `.gitignore` | keys/kubeconfigs outside var/ committable. | F-IC-2. | **resolved** |
| F-09 | Low | host | `.env` (metadata only) | mode 0644 (world-readable); holds AI keys. Re-checked with `stat`, content never read. | `chmod 600 .env` (user/operator). | open (re-checked 2026-11-22 with `stat`: still `-rw-r--r--`) |
| F-10 | Low | B2 | `infra/kind/manifests/40-posture-lab.yaml` | weak posture pod mounted node `/var/log`. | Narrow hostPath. | **resolved** (dedicated `/var/log/extorq-posture-lab`) |
| F-11 | Info | B2 | `00-namespaces.yaml` | `extorq-restricted` enforces PSA baseline. | Say "baseline" in demo. | open (doc) |
| F-12 | Info | D1 | `api/auth.py` | service-token holder can assert any user/role. | Token only in frontend; rotate. | accepted |
| F-13 | Info | D2 | `frontend/src/lib/server/session.ts` | stateless 8 h sessions. | Accept for lab. | accepted |
| F-14 | Low | C1 | `config/collectors/github.yaml` | broad `gh auth token` fallback (enabled in the committed config earlier this session). | fine-grained read-only PAT file. | **accepted risk** (2026-11-22: the lead enabled `gh_cli_token_fallback: true` with the user's explicit approval, PLAN 11; collector health reports `token_source=gh_cli` and the scopes `repo`, `workflow`; documented in security.md, known limitations C8, ADR 0006) |
| F-15 | Resolved | D2 | `components/ui/chart.tsx` | `dangerouslySetInnerHTML`. | replaced. | resolved |
| F-16 | Info | C2 | `backend/src/extorq/detection/harness.py` `EphemeralClickHouse._create_users` | `CREATE USER ... BY '{pw}'` f-string in throwaway-container harness (passwords `secrets.token_urlsafe`). | Pragma. | **resolved** (pragma present) |
| F-17 | Medium | B1 | `infra/vm/files/extorq-collect-dispatch` `collect_processes`; `collectors/src/extorq_collectors/linux/inventory.py:221`; `linux/service_records.py:174` | The dispatcher returns the first 256 chars of EVERY process's argv (`/proc/<pid>/cmdline` is world-readable) and the collector now stores them, pattern-redacted, in every process `InventoryItem` and in `ServiceInstance.attributes.args` (ClickHouse `inventory_items` is readable by api_ro and grafana). Redaction misses `--requirepass x`, `redis-cli -a x`, `curl -u user:pass`, `PGPASSWORD=x` (F-06), so credentials passed on command lines can be stored: indiscriminate collection of a secret-bearing field (user requirement 8). | Drop `args` from process inventory items; keep argv[0]/executable only; if a service instance needs arguments, allow-list the flags per adapter (e.g. nginx `-c <path>`) and redact on the VM before transfer. | open (2026-11-22: `inventory.py:265` and `service_records.py:178` still store redacted args; impact reduced by F-06) |
| F-19 | Medium | A (gateway), D1 (API) | `backend/src/extorq/ingest/processing.py`; `backend/src/extorq/api/repository.py` `SERVICE_GET_SQL`, `SERVICE_INSTANCES_SQL`, `SERVICE_EVENT_SOURCES_SQL`, `SERVICE_AUTH_*` | Service ids are client-supplied and computable; the gateway does not recompute them, and the API reads services, instances and events by `service_id` alone. A producer authorised for asset X can publish a service row (asset X) carrying asset Y's `service_id`, attach instances, or tag events with it; `GET /services/{id}` may then show X's forged row (`ORDER BY last_seen DESC LIMIT 1`) and X's instances/events under Y's service (gateway part verified by probe). | A: quarantine `service` records whose `service_id != service_id(asset_id, kind, key)` and instances whose `instance_id != instance_id(service_id, kind, key)`. D1: resolve the service row by id, then filter instances/events by `service_id` AND asset scope (`asset_id = svc.asset_id OR startsWith(asset_id, svc.asset_id || '/node/')`); prefer the row whose recomputed id matches. | **gateway part resolved** (A: `identity_mismatch` quarantine; F's 2 tests now hard and assert the reason, 2026-11-22); **API part open** (D1: `SERVICE_INSTANCES_SQL` and event queries still filter by `service_id` only); C2 consumer-side check implemented |
| F-20 | Info | B1, B3 | `linux/discovery.py`, `macos/services.py` | Coverage/attribution of look-alike instances and forwarded ports. B1 binds processes and sockets to units via kernel cgroups (user.slice excluded); B3 attributes ports to the owning pid (QEMU/Docker backend own forwarded ports). | Label forwarder-owned endpoints (e.g. `attributes.port_forwarder=true`) so the Mac's QEMU/Docker services are not read as sshd/nginx; compute `monitored` from the unit the adapter reads. | mostly addressed |
| F-21 | Low | B1, B3 | discovery | Masquerading (`/tmp/sshd`) and churn. B1's cgroup model keeps user processes out of host services; listeners stay "unattributed". | Surface unattributed listeners in the UI; flag process-only services with unexpected paths; bound `service.*` churn per cycle. | open (low) |
| F-22 | Info | E | `tests/unit/ai/test_ai_sanitize.py` | Committed secret-shaped synthetic sample (`api_key: '...'`) trips gitleaks. | Generate at runtime; then F removes the scoped allowlist entry in `tests/security/gitleaks.toml`. | **resolved** (2026-11-22 01:59: E builds the sample at runtime; F replaced the working-tree allowlist entry by a history-only entry for commit 4ee5baa AND the path; negative controls pass) |
| F-23 | Low | B1 | `collectors/src/extorq_collectors/linux/http.py` | nginx error log quotes request lines with query strings. | Strip queries. | **resolved** (verified by canary test) |
| F-24 | Low | B3 | `tests/fixtures/macos/services/launchctl_print_gui.txt` | 2760-line dump of the operator's GUI launchd session committed as a fixture: personal software inventory (privacy); one 64-hex label tripped gitleaks (false positive, allowlisted narrowly). | Trim to the lines the tests need and anonymise third-party labels. | **resolved in the working tree** (2026-11-22: B3 minimised the fixtures, file never committed; F removed the EAAA allowlist entry, scan green 02:05); commit of the minimised fixtures pending (F-27) |
| F-25 | Low | A (Makefile), C1 (script) | `Makefile` `sim-gh-001`, `sim-cleanup`; `simulations/github/gh_001_workflow_permissions.sh` | `make sim-gh-001` without `ARGS` dies (`--repo is required`), and `make sim-cleanup SCENARIO=gh-001 RUN_ID=<id>` runs the script without `--repo`, so the documented generic cleanup can never revert GH-001 (verified with `make -n`). | Pass `--repo $(GH_REPO)` (default from `config/collectors/github.yaml`) in the Makefile, or let the script default `--repo` from that config. Docs now use `make sim-gh-001 ARGS="--repo Exigent07/extorq-lab ..."`. | open |
| F-26 | Info | C2 (docs), lead (schema) | `0001_core_tables.sql` `simulation_runs` (`ReplacingMergeTree(row_version) ORDER BY run_id`); `docs/attack-scenarios.md` CORR-002 recipe | Reusing one run id for HTTP-001, VM-001 and VM-002 (the CORR-002 recipe) keeps only the latest scenario's SimulationRun after merges / with `FINAL`. Alerts are unaffected. | Use one run id per scenario in the recipe (the demo runbook does), or key by `(run_id, scenario_id)` in a future migration. | open (documented: known limitations D7) |
| F-27 | Low | B3 (lead commits) | `tests/unit/macos/*` read `tests/fixtures/macos/services/*`, `launchd/apple/`, `inventory/dscl_users_*` | These fixtures are untracked (PLAN 11 data minimisation), so a clean checkout, and therefore CI, cannot pass `tests/unit/macos` until minimised fixtures are committed. | Commit the minimised fixtures together with the tests. | open |
| F-28 | Info | A, D2 | `compose.yaml` `frontend`, `ai-worker` | At 2026-11-22 ~01:44 IST no `frontend` or `ai-worker` container was running (console 127.0.0.1:3000 not listening); the compose console has never been verified end to end. | A's session-3 task 5 (`make up-full` incl. frontend and ai-worker); then D2's `scripts/smoke.mjs --base http://127.0.0.1:3000` (runbook pre-flight step 12). | mostly resolved (A started `frontend` and `ai-worker` ~01:56; `make demo-check` DEMO READY 02:02; D2's newest smoke 98/103 against the older image: re-run after D2's final rebuild) |
| F-29 | Info | D1 (API), A (quota) | `0002_rbac.sql` `extorq_api_quota` (1200 queries/min for `extorq_api_ro`); console page loads | Two consecutive console smoke runs (~200 page loads) exhausted the API identity's per-minute quota (`queries = 1374/1200`, 2026-11-22 ~02:01 IST): the API answered 503 and `make demo-check` failed until the minute ended. The quota works as designed (load shedding), but the console issues many queries per page. | Do not run smoke/tests/demo-check while presenting (runbook 2.2); consider caching or batching hot API queries (D1). | open (documented) |

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
