# Known Limitations

Owner: agent F. **Living list**, updated as components land (last update
2026-11-22, build session 3, before the demo on 2026-11-23). Each entry says what is limited,
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
| S7 | **Process command lines from the VM are stored.** The dispatcher returns the first 256 characters of each process's arguments (Linux exposes `/proc/<pid>/cmdline` to every user) and the collector stores them, pattern-redacted, in process inventory items and service instances. Redaction now also covers `--requirepass <x>`, `redis-cli -a <x>`, `curl -u user:pass`, `PGPASSWORD=<x>` and `MYSQL_PWD=<x>` (F-06 resolved, verified 2026-11-22), but pattern redaction cannot recognise every secret a program accepts on its command line (F-17). | Process evidence for discovery. | F-17 (B1): keep only argv[0]/executable, or allow-list flags per adapter. |
| S8 | **Kubernetes audit events stay cluster-level.** They are attributed to a workload service only when the audit record itself names the object. | Audit records describe API requests, not workloads. | None needed; shown as cluster events. |
| S9 | **kind nodes are containers**, so the "node" asset (`k8s:extorq-lab/node/<name>`) is a Docker container on Docker Desktop's Linux VM, not a separate machine. | kind design. | Use a multi-node cluster or real nodes outside the lab. |
| S10 | **Service and instance rows expire after 30 days** (`0004_services.sql` TTL); events keep their own `service_id` for 90 days. | Bounded storage on a laptop. | Raise the TTL if longer history is needed. |
| S11 | **Discovery reflects what the asset reports.** A compromised asset can hide or fake its own services (T23). | No remote attestation. | Out of scope for the lab. |

## 2. Collection

| # | Limitation | Why | Way forward |
|---|---|---|---|
| C1 | Linux collection is **agentless pull**: detection latency is at least the collector interval, and lines journald drops under rate limiting are never seen. | ADR 0003. | A compiled agent with streaming (future path in ADR 0003). |
| C2 | Root on the VM can forge, delete or withhold its own logs before collection (T01). | No attestation, no remote log forwarding from the VM. | Remote syslog/forwarding to a host the VM cannot modify. |
| C3 | **NAT hides origins**: every connection from the Mac reaches the VM as `10.0.2.2` (QEMU user-mode networking), NodePort traffic reaches pods from the kind network gateways (`172.18.0.1`, `10.244.0.1`). Rules lower confidence for these shared addresses (`params.shared_nat_ips`: VM-001, HTTP-001 and APP-001 medium, CORR-002 low) and correlation records NAT-only IP matches as unestablished. In the verified CORR-002 alert the SSH stage also contained the lab operator's own failed key attempts from the same address. | QEMU user-mode networking, Docker networking. | Bridged or vmnet networking; source identity from the application layer. |
| C4 | **No EDR telemetry on macOS.** The collector runs as the operator user without Full Disk Access, Endpoint Security or configuration profiles: no ESF process, file or network events, no TCC-protected data, unified log visibility limited to what an unprivileged user can read, and `netstat` withholds the socket table from the uv-managed Python on macOS 27 (S3). ExtorQ sees launchd persistence, inventory, posture and selected unified-log events, not an EDR-grade activity stream. | ADR 0004 (safety of the host). | A signed system extension with the Endpoint Security entitlement (not planned). |
| C5 | The OTel DaemonSet runs as UID 0 (read-only mounts, all capabilities dropped) because the API server audit log is root-owned 0600. | kind file ownership. | Change the audit log group on the node. |
| C6 | GitHub is **polled** (interval 120 s), not pushed: latency is at least the interval plus the rule interval; API rate limits apply; states shorter than one interval are seen only through commit history. | ADR 0006 (no inbound endpoint). | Webhooks through a relay if latency matters. |
| C7 | **GitHub plan gaps on the private lab repository** (observed in the collector's health and scan coverage, 2026-11-21): branch protection, branch rules and rulesets answer `HTTP 403: Upgrade to GitHub Pro or make this repository public`; code scanning alerts are unavailable (not enabled); secret scanning is disabled (private repositories need GitHub Secret Protection); `security_and_analysis` and Dependabot security-update status are not visible to the token; organisation audit logs need Enterprise Cloud. These checks are reported as coverage gaps, never as "no findings" or "protection off". | Free plan, private repository, token visibility. | A paid plan or a public lab repository; an admin-visible token for the settings checks. |
| C8 | **Broad GitHub token.** The committed configuration uses the GitHub CLI token fallback (`gh_cli_token_fallback: true`), approved by the user for the lab on 2026-11-22 (PLAN 11). Its OAuth scopes (`repo`, `workflow`, per the collector's health warning) allow writing to the user's repositories although the collector only reads (F-14, accepted for the lab). | No fine-grained read-only token was available for the demo. | A fine-grained, read-only, single-repository token file (`token_file` / `EXTORQ_GITHUB_TOKEN_FILE`) and the fallback switched off. |
| C9 | The Kubernetes inventory token is short-lived (24 hours by default): after expiry the `k8s-inventory` collector fails with 401 and K8S-002 loses its state evidence (audit only, confidence medium) until `infra/kind/kind.sh token` is run again. | Least privilege (TokenRequest, no long-lived Secret). | Automatic renewal by the collector. |

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
| P9 | **Retention bounds what can be ingested.** Events older than the `events` TTL (90 days) are quarantined at the gateway (`older_than_retention`, deployed in build session 3) instead of being accepted and expired; a backfill of older history (for example old commits of a GitHub repository) is visible only as quarantine rows. Service and instance rows expire after 30 days (S10). | Bounded storage on a laptop. | Longer TTLs if longer history is needed. |
| P10 | `api` and `ai-worker` run with a writable root filesystem because compose materialises `environment:`-sourced secrets (the AI keys) into `/run/secrets`; their code stays root-owned and they run as uid 10001. | Compose limitation with `.env`-sourced secrets. | File-based secrets for the AI keys (outside `.env`). |

## 4. Detection, correlation and AI

| # | Limitation | Why | Way forward |
|---|---|---|---|
| D1 | Every rule documents its false positives and blind spots in its YAML (for example VM-001 misses low-and-slow and distributed guessing). | Threshold rules. | Additional rules; see `rules/**.yaml`. |
| D2 | Correlation never proves causation; sequences are reported with relationship type and confidence (T24). CORR-002 (HTTP probing -> SSH failures -> systemd change on one host) is implemented with status `experimental`. | PLAN 10.1 rule 5. | Mature CORR-002 with more lab runs. |
| D3 | Clock skew between assets shifts windows; timestamps are taken from each source as reported. | No time synchronisation authority. | NTP discipline on lab assets. |
| D4 | AI providers are off unless enabled; when enabled, sanitised lab telemetry (user names, IPs, host and repository names, commit messages) is sent to TypeSafe (Jev) and Google (Gemini). Redaction is pattern-based. AI output is advisory only. | ADR 0007. | Local models if data must not leave the host. |
| D5 | **Gemini quota and latency.** Summaries depend on the key's provider quota (a 429 is stored as `rate_limited` and not retried by default) and on ExtorQ's own caps (50 attempts per UTC day, 120 s per-alert cooldown). Observed latency: 23 s and 52 s on synthetic contexts, 22.9 s and 25.9 s on the two real alerts summarised so far (GH-001, CORR-002, 2026-11-21 20:35 UTC; every cited evidence id verified); the console waits up to 90 s. | Paid external API, thinking model. | Pre-generate summaries before a demonstration (done for GH-001 and CORR-002); a local model. |
| D6 | **Jev evaluation is small and synthetic**: 27 labelled synthetic cases, one run, labels written by the same engineer who wrote the questions (77.8% versus a 44.4% baseline). Real alerts have been triaged (17 with question set `triage-v2` after E fixed a projection that had dropped the evidence key fields of real contexts), but they are not labelled, so accuracy on real data is unmeasured. | Time; no labelled real data. | Label real lab contexts and repeat runs to measure variance. |
| D7 | `SimulationRun` records are keyed by `run_id` alone (`ReplacingMergeTree ORDER BY run_id`): reusing one run id for several scenarios, as the CORR-002 recipe in `docs/attack-scenarios.md` suggests, keeps only the latest scenario's record. Alerts are unaffected (they carry run ids from the telemetry). | Schema choice in 0001. | Key by `(run_id, scenario_id)` or use one run id per scenario (the demo runbook does). |

## 5. Documentation and testing

* Test results are recorded only after real runs ([testing.md](testing.md));
  "not yet run" means exactly that.
* Component documents owned by other agents are linked from
  [telemetry-sources.md](telemetry-sources.md) and
  [architecture.md](architecture.md#10-related-documents).
* What has not been verified end to end (CI on GitHub, the compose console and
  AI worker containers, Gemini on real data, rotation, live gap events and
  more) is listed in [testing.md section 5](testing.md#5-not-verified).
