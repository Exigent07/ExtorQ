# Known Limitations

Owner: agent F. **Living list**, updated as components land (last update
2026-11-21 evening, during build session 2). Each entry says what is limited,
why, and what would remove the limitation. Security findings with owners are
tracked in [`docs/team/status/F.md`](team/status/F.md) (`F-nn`); threats in
[`docs/threat-model.md`](threat-model.md) (`Tnn`).

## 1. Service-aware monitoring

| # | Limitation | Why | Way forward |
|---|---|---|---|
| S1 | **Planned adapters collect nothing**: FTP (vsftpd, ProFTPD, Pure-FTPd), PostgreSQL, MySQL/MariaDB, DNS (BIND, Unbound, dnsmasq, systemd-resolved) and Redis are recognised during discovery and shown as `adapter_support = planned`, `monitoring_status = unmonitored`. | Extension points only (`collectors/src/extorq_collectors/services/planned.py`); scope kept to the mandatory adapters for the demo. | Implement per [AGENTS.md 7.2](../AGENTS.md#72-add-a-service-adapter) with catalog event types and tests. |
| S2 | **Apache adapter is parser-only**: parsers are tested on documented log formats, but Apache is not deployed in the lab, so there is no live Apache telemetry. | Lab runs nginx (PLAN 10.2). | Deploy Apache in the VM if Apache coverage must be demonstrated. |
| S3 | **Port owner processes are often unknown.** On the VM the unprivileged collector cannot see the owning pid of root's listeners (`ss -p`), but the kernel reports each socket's cgroup (`ss -e --cgroup`), so sockets created inside a systemd unit are attributed to that unit (`confirmed`); sockets outside any service unit stay unattributed. On macOS, `netstat` reports the last pid and `lsof` sees only the operator's processes; on macOS 27 the kernel withholds the socket table from processes with an ad-hoc-signed ancestor (the uv-managed Python), forcing the `lsof` fallback, so root daemons' listeners can be invisible. | Least privilege by design (no root collection). | A narrowly scoped privileged helper; not planned for the demo. |
| S4 | **Executable paths of other users' processes are not visible on the VM** (`/proc/<pid>/exe` needs ptrace access); discovery relies on kernel-attested cgroup membership (unit), `comm`, uid and start time. A user's look-alike process (for example one named `sshd`) stays in `user.slice` and never becomes a host service, but root can place processes in any unit. | Unprivileged collection. | F-21: surface unattributed listeners and process-only services with unexpected paths. |
| S5 | **Forwarded ports belong to the forwarder.** On the Mac, `127.0.0.1:2222`/`8088` are owned by QEMU and the compose ports by Docker Desktop's backend; macOS discovery attributes them to those processes, not to sshd or nginx. | Port forwarding. | F-20: label forwarder-owned endpoints explicitly in the console. |
| S6 | **Coverage is judged per service (unit), not per instance.** On the VM a second instance outside the unit is not part of the service, and journald adapters trust only lines whose `_SYSTEMD_UNIT`/`_EXE`/UID match; on macOS coverage follows the owning launchd job. Freshness is per adapter source. | Coverage is computed from adapter source freshness. | n/a for the demo. |
| S7 | **Process command lines from the VM are stored.** The dispatcher returns the first 256 characters of each process's arguments (Linux exposes `/proc/<pid>/cmdline` to every user) and the collector stores them, pattern-redacted, in process inventory items and service instances. Redaction catches `key=value`, header, `--password <x>` and mysql `-p<x>` forms but not `--requirepass <x>`, `redis-cli -a <x>`, `curl -u user:pass` or `PGPASSWORD=<x>` (F-06, F-17). | Process evidence for discovery. | F-17 (B1): keep only argv[0]/executable; F-06 (A): add the remaining redaction forms. |
| S8 | **Kubernetes audit events stay cluster-level.** They are attributed to a workload service only when the audit record itself names the object. | Audit records describe API requests, not workloads. | None needed; shown as cluster events. |
| S9 | **kind nodes are containers**, so the "node" asset (`k8s:extorq-lab/node/<name>`) is a Docker container on Docker Desktop's Linux VM, not a separate machine. | kind design. | Use a multi-node cluster or real nodes outside the lab. |
| S10 | **Service and instance rows expire after 30 days** (`0004_services.sql` TTL); events keep their own `service_id` for 90 days. | Bounded storage on a laptop. | Raise the TTL if longer history is needed. |
| S11 | **Discovery reflects what the asset reports.** A compromised asset can hide or fake its own services (T23). | No remote attestation. | Out of scope for the lab. |

## 2. Collection

| # | Limitation | Why | Way forward |
|---|---|---|---|
| C1 | Linux collection is **agentless pull**: detection latency is at least the collector interval, and lines journald drops under rate limiting are never seen. | ADR 0003. | A compiled agent with streaming (future path in ADR 0003). |
| C2 | Root on the VM can forge, delete or withhold its own logs before collection (T01). | No attestation, no remote log forwarding from the VM. | Remote syslog/forwarding to a host the VM cannot modify. |
| C3 | **NAT hides origins**: every connection from the Mac reaches the VM as `10.0.2.2` (QEMU user-mode networking). VM-001 lowers confidence for shared NAT addresses; correlation treats NAT-IP matches as unestablished. | QEMU user-mode networking. | Bridged or vmnet networking. |
| C4 | The macOS collector runs as the operator user without Full Disk Access, Endpoint Security or configuration profiles: no ESF events, no TCC-protected data, unified log visibility limited to what an unprivileged user can read. | ADR 0004 (safety of the host). | A signed system extension with the Endpoint Security entitlement (not planned). |
| C5 | The OTel DaemonSet runs as UID 0 (read-only mounts, all capabilities dropped) because the API server audit log is root-owned 0600. | kind file ownership. | Change the audit log group on the node. |
| C6 | GitHub is **polled** (default interval 120 s), not pushed: latency is at least the interval; API rate limits apply; organisation audit logs and enterprise-only features are not collected. | ADR 0006 (no inbound endpoint). | Webhooks through a relay if latency matters. |
| C7 | The GitHub collector needs a token; the optional GitHub CLI fallback (`gh_cli_token_fallback`, off by default) would use an OAuth token with much broader scopes than read-only (F-14, resolved in the committed configuration). | Convenience option. | Keep the fallback off; use a fine-grained read-only token file. |

## 3. Platform

| # | Limitation | Why | Way forward |
|---|---|---|---|
| P1 | Single host, no high availability; Docker Desktop's VM (about 7.75 GiB) is shared by ClickHouse (3 GiB limit), kind and the services. | Lab on one laptop. | n/a for the demo. |
| P2 | **At-least-once** delivery, not exactly-once; duplicates collapse through deterministic identities and `ReplacingMergeTree`, so latest-state reads must use the views or `FINAL`. | ADR 0008. | n/a (by design). |
| P3 | No per-producer rate limit at the gateway (size, record and batch limits only). | Not built. | Token-bucket per producer. |
| P4 | Producer tokens are bearer tokens; a stolen token allows forgery within that producer's scope; records are not signed (T02, T04). | Simplicity. | Per-collector client certificates or signed batches. |
| P5 | Console sessions are stateless JWS cookies valid for 8 hours; logout does not revoke a copied token; two shared accounts (`analyst`, `viewer`) mean audit trails name a role, not a person (F-13). | Lab simplicity. | Server-side session store; per-person accounts or SSO. |
| P6 | The console is plain HTTP on loopback; lab assets can reach host loopback services (F-01, T18). | Docker Desktop and QEMU networking. | QEMU `restrict=on` after provisioning; keep the debug profile off. |
| P7 | CI (`.github/workflows/ci.yml`) runs lint, type checks, unit and security tests, the frontend build, gitleaks and Trivy filesystem scans; tests that need the live stack, lab assets or failure injection are not part of CI. | Hosted runners have no lab. | Self-hosted runner with the lab, if ever needed. |
| P8 | Container images are pinned by digest but signatures and provenance are not verified; ExtorQ's own images are not scanned yet (T15). | Not built. | cosign verification; scan the backend and frontend images with Trivy. |

## 4. Detection, correlation and AI

| # | Limitation | Why | Way forward |
|---|---|---|---|
| D1 | Every rule documents its false positives and blind spots in its YAML (for example VM-001 misses low-and-slow and distributed guessing). | Threshold rules. | Additional rules; see `rules/**.yaml`. |
| D2 | Correlation never proves causation; sequences are reported with relationship type and confidence (T24). CORR-002 (HTTP probing -> SSH failures -> systemd change on one host) is implemented with status `experimental`. | PLAN 10.1 rule 5. | Mature CORR-002 with more lab runs. |
| D3 | Clock skew between assets shifts windows; timestamps are taken from each source as reported. | No time synchronisation authority. | NTP discipline on lab assets. |
| D4 | AI providers are off unless enabled; when enabled, sanitised lab telemetry (user names, IPs, host and repository names, commit messages) is sent to TypeSafe (Jev) and Google (Gemini). Redaction is pattern-based. AI output is advisory only. | ADR 0007. | Local models if data must not leave the host. |

## 5. Documentation and testing

* Test results are recorded only after real runs ([testing.md](testing.md));
  "not yet run" means exactly that.
* Component documents owned by other agents are linked from
  [telemetry-sources.md](telemetry-sources.md) and
  [architecture.md](architecture.md#10-related-documents) as they land;
  `docs/telemetry/linux.md`, `docs/telemetry/kubernetes.md`,
  `docs/detection-catalog.md` and `docs/correlation.md` were not present at
  the last update.
