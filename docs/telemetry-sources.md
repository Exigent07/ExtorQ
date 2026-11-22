# Telemetry Sources

Owner: agent F (index). Per-source detail is owned by the collector owners in
`docs/telemetry/` (section 3); this index summarises every source from the code
(last checked 2026-11-22). Event types and their allowed source types are fixed
in `backend/src/extorq/contracts/catalog.py`.

Every value below is collected only when the source genuinely provides it;
unknown fields stay `NULL`. All content is treated as attacker-controlled.

## 1. Summary

| Asset | Source type | Method | Privileges | Key event types and fields | Known gaps |
|---|---|---|---|---|---|
| Ubuntu VM | `linux.journald` | SSH pull, dispatcher `journal <cursor> <n>` (cursor checkpoint) | `extorq-collector` in `systemd-journal` | `auth.ssh.*` (actor, src_ip, src_port, method), `auth.sudo.*`, `auth.pam.failure`, `system.service.state_changed`, `system.systemd.daemon_reload`; sender verified with `_SYSTEMD_UNIT`/`_EXE`/`_UID` | polling latency; journald rate limiting; root can forge or delete logs |
| Ubuntu VM | `linux.nginx` | nginx JSON access log (path without query string) and error log, both via journald | as above | `http.request` (route, status, user agent, request id), `http.server.error` | every Mac-originated client appears as `10.0.2.2` (QEMU NAT) |
| Ubuntu VM | `linux.app` | lab portal JSON lines via journald | as above | `app.auth.login_failed`/`succeeded`, `app.authz.denied` (user, src_ip, route, reason) | lab application only |
| Ubuntu VM | `linux.apache` | Apache access/error parsers | n/a | `http.request`, `http.server.error` | **not deployed in the lab** (parsers only) |
| Ubuntu VM | `linux.auditd` | dispatcher `audit <inode> <offset> <max>` over `/var/log/audit` | group `adm` | `file.audit.watch` (keys `extorq_systemd`, `extorq_sshd`, `extorq_sudoers`, `extorq_identity`, `extorq_cron`), `process.audit.exec` (`extorq_root_exec`), `audit.config.changed` | rotation past the offset becomes a gap event |
| Ubuntu VM | `linux.inventory` | dispatcher `inventory` (units, processes, listeners, users, cron, sensitive files) and `packages` (dpkg) | unprivileged | `persistence.systemd.unit_*`, `package.*`, `network.listener.*`, `account.user.*`, `config.file.changed`, `service.*`, services and instances (unit attribution via kernel cgroups) | owner pids of root's listeners unknown; redacted argument prefixes of every process stored (F-17) |
| Ubuntu VM | `linux.posture` | dispatcher `posture` (sshd configuration, apt periodic, sysctls, auditd state, pending security updates) | unprivileged | posture findings, `config.security_setting.changed` | checks needing root report unknown |
| macOS host | `macos.unified_log` | `/usr/bin/log show` with fixed predicates | operator user, no Full Disk Access | `auth.local.failure`, `auth.sudo.*`, `security.gatekeeper.event`, `security.xprotect.event`; sshd and Screen Sharing adapters; the sshd adapter emits `auth.ssh.*` like the Linux parser (catalog B3-IC-1, adapter updated by B3 in build session 3, unit-tested only); Remote Login and Screen Sharing are off on the lab Mac, so both services are shown unmonitored | no Endpoint Security (EDR) events; TCC-protected data invisible |
| macOS host | `macos.launchd` | launchd plist directories, diffed | operator user | `persistence.launchd.item_*` | none known beyond read permissions |
| macOS host | `macos.inventory` | `ps`, `netstat` (fallback `lsof`), `system_profiler` | operator user | `network.listener.*`, `account.user.*`, `service.*`, inventory items | root listeners invisible in `lsof` mode; arguments off by default |
| macOS host | `macos.posture` | `csrutil`, `fdesetup`, `spctl`, `socketfilterfw`, software update, remote login, admin group | operator user | posture findings | checks that cannot run report `error`, never `pass` |
| kind cluster | `k8s.audit` | OTel filelog on the API server audit log (policy `infra/kind/audit-policy.yaml`: Metadata only for secrets, configmaps and token requests; request and response bodies for RBAC writes; request bodies for Pod writes and exec/attach/port-forward) | OTel DaemonSet (UID 0, read-only mount) | `k8s.api.request` (verb, resource, user, response code, PSA violation, request summary) | single control-plane node; audit policy defines visibility |
| kind cluster | `k8s.container_log` | OTel filelog on `/var/log/pods` + `k8sattributes` | OTel service account (`get/list/watch` pods, namespaces, nodes, replicasets) | `k8s.container.log`; lab portal lines as `http.request`/`app.*`; Pod uid, container id, namespace, node, workload | logs only as written by the containers |
| kind cluster | `k8s.api_inventory`, `k8s.events`, `k8s.posture` | read-only API collector, short-lived token | `extorq-inventory` (`get/list/watch`, no secrets or configmaps) | `k8s.resource.*` (with `risk_flags`), `k8s.event.observed`, node assets, workload and Service services, Pod/container instances, posture findings | events older than the API server's event TTL are lost while the collector is down |
| GitHub repo | `github.api`, `github.posture` | REST polling every 120 s, ETags, rate limits, checkpoints | committed configuration: `gh` CLI token fallback (approved for the lab, PLAN 11; scopes `repo`, `workflow` reported as a health warning); preferred: fine-grained read-only token file | `github.commit.observed`, `github.workflow.modified` (write-all, added write scopes, dangerous triggers, untrusted checkout), `github.workflow_run.observed`, `github.repo.settings_changed`, `github.branch_protection.changed` | polling latency; on the private free-plan lab repository branch protection, rules and rulesets answer 403 and code/secret scanning are unavailable (coverage gaps, known limitations C7); enterprise-only features not collected |
| Lab assets | `scanner.trivy`, `scanner.gitleaks`, `scanner.semgrep` | pinned scanner images, scans with `--network none`, Linux package SBOM | `scanner-runner` producer | `ScanRun` + `PostureFinding` (vulnerability, secret (redacted), code), lifecycle via `v_findings_current` | Semgrep image is linux/amd64 only (emulated); failed or partial scans never resolve findings |
| ExtorQ | `extorq.pipeline`, `extorq.simulation` | gateway, writer, collectors, simulation scripts | n/a | `extorq.collector.gap_detected`, health records, `SimulationRun` | n/a |

## 2. Service attribution (schema 1.1)

Events carry `service` (`ServiceRef`) only when an adapter can genuinely
attribute them: sshd journald lines to the ssh service, nginx lines to nginx,
lab portal lines to the lab application, systemd lifecycle lines to the unit,
container logs to their workload. Discovery evidence and coverage states are
described in [architecture section 5](architecture.md#5-service-model-schema-11).

## 3. Per-source documents

| Document | Owner |
|---|---|
| [docs/telemetry/linux.md](telemetry/linux.md) | B1 |
| [docs/telemetry/kubernetes.md](telemetry/kubernetes.md) | B2 |
| [docs/telemetry/macos.md](telemetry/macos.md) | B3 |
| [docs/telemetry/github.md](telemetry/github.md) | C1 |
| [docs/telemetry/scanners.md](telemetry/scanners.md) | C3 |

Related platform documents: [data model](data-model.md) and
[data flow](data-flow.md) (A), [collector SDK](collectors.md) (A),
[AI integrations](ai-integrations.md) (E), [analyst API](api/README.md) (D1).
