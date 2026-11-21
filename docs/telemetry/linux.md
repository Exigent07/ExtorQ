# Linux telemetry (lab VM `linux:lab-vm-01`)

Owner: B1. Implemented and verified on 2026-11-21 against the running lab VM
(Ubuntu 24.04.5 LTS arm64, kernel 6.8.0-147, OpenSSH 9.6p1, nginx 1.24, auditd 3.1.2,
systemd 255). Everything below describes implemented behaviour; items marked
**planned** are not implemented.

## 1. Architecture

```
Mac (host)                                           lab-vm-01 (QEMU + HVF, user-mode net)
extorq-collect run                                   sshd :22  <- hostfwd 127.0.0.1:2222
  LinuxSSHCollector ──ssh (pinned host key)──────▶   Match User extorq-collector
    SSHDispatchClient                                  ForceCommand /usr/local/sbin/extorq-collect-dispatch
    (argv only, ControlMaster)                         (python3 -I, fixed allow-list, read-only)
       │  journal / audit / inventory / packages / posture   ├─ journalctl -o json (filtered fields)
       ▼                                                     ├─ /var/log/audit/audit.log (by offset)
  parsers + service adapters                                 ├─ /proc, ss -e --cgroup, unit files
       ▼                                                     └─ dpkg-query, sysctl, config files
  ctx.emit(records, checkpoints)  (SDK outbox, SQLite, atomic)
       ▼
  ingest gateway (HTTPS, producer linux-ssh-lab-vm-01) ──▶ ClickHouse
```

Collection is **agentless and pull-based**: nothing ExtorQ-specific runs permanently in
the VM, and the VM never needs to reach the Mac. The collector account can only run the
dispatch boundary's allow-list.

* Collector: `extorq_collectors.linux.collector:LinuxSSHCollector`, configured in
  `config/collectors/linux.yaml` (no secrets; SSH host/port can point at another host
  with the same boundary installed).
* Run: `uv run extorq-collect run --only linux-ssh-lab-vm-01` (continuous) or `--once`.
* Producer `linux-ssh-lab-vm-01`, source types `linux.*`, asset `linux:lab-vm-01`
  (asset type `linux_host`).

## 2. Privileges and the dispatch boundary

| Item | Setting |
|---|---|
| Account | `extorq-collector`: no password (locked), no sudo, groups `adm` (audit log, `/var/log/nginx`) and `systemd-journal` (all journals), home root-owned |
| Key | ed25519 `var/vm/keys/extorq-collector` (0600, Mac side); authorized key root-owned in `/etc/ssh/authorized_keys/extorq-collector` (0644, outside the home: the account cannot change it) |
| sshd `Match User extorq-collector` | `ForceCommand /usr/local/sbin/extorq-collect-dispatch`, `PermitTTY no`, `DisableForwarding yes`, `AllowTcpForwarding no`, `AllowStreamLocalForwarding no`, `X11Forwarding no`, `AllowAgentForwarding no`, `PermitTunnel no`, `PermitListen none`, `PermitOpen none`, `PermitUserRC no`, `MaxSessions 4` |
| Global sshd | publickey only (`AuthenticationMethods publickey`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`), `PermitRootLogin no`, `MaxAuthTries 3`, `LogLevel VERBOSE`, `AllowUsers extorq-admin extorq-collector` |
| Host key pinning | the VM's ed25519 host key is generated on the Mac and injected by cloud-init; `var/vm/known_hosts` is used with `StrictHostKeyChecking=yes`, `GlobalKnownHostsFile=/dev/null`, `UpdateHostKeys=no` |
| Client | system `/usr/bin/ssh` with an argument list, `-F /dev/null` (the operator's ssh config is ignored), `IdentitiesOnly`, `IdentityAgent=none`, `BatchMode`, no forwarding, `ControlMaster`/`ControlPersist 300` in `var/run/ssh` (0700), hard timeouts, bounded stdout/stderr, bounded jittered retries; host-key and authentication failures are never retried |
| PAM | `pam_motd` is skipped for the collector account (it would run `/etc/update-motd.d/*` as root on every collector login, ~40 audited execs per connection) |

### 2.1 Dispatch grammar (protocol 1, dispatcher 1.1.0)

`$SSH_ORIGINAL_COMMAND` is parsed strictly (printable ASCII tokens separated by exactly
one space, at most 512 characters). Anything else prints `denied`, exits 77 and writes a
journald line `denied command: command_word=<word|?> length=<n> sha256=<16 hex> reason=...`
(the command itself is never logged; the collector turns these lines into
`system.log.notable` with `action=dispatch.denied`, `attributes.boundary_violation=true`).

| Command | Output |
|---|---|
| `version` | JSON: dispatcher version, protocol, commands, limits, hostname, user |
| `journal <cursor\|-> <1..5000>` | NDJSON of journald entries with ONLY `__CURSOR, __REALTIME_TIMESTAMP, _BOOT_ID, _HOSTNAME, SYSLOG_IDENTIFIER, _SYSTEMD_UNIT, _PID, _UID, _COMM, _EXE, _TRANSPORT, PRIORITY, MESSAGE`, then a trailer `{"_extorq":{"type":"journal_end", "cursor_exact":..., "truncated":..., ...}}`. Without a cursor: `--since -2h`. With a cursor: inclusive seek; `cursor_exact=false` means the checkpoint entry no longer exists |
| `audit <inode\|-> <offset> <4096..1048576>` | one JSON header (`inode`, `start_offset`, `next_offset`, `gap`, `gap_reason`, `more`, `file`) + raw complete lines of `/var/log/audit/audit.log` (or the rotated file still holding the checkpoint) |
| `inventory` | JSON: host facts (incl. `btime`, `clk_tck`, `boot_id`), unit files (sha256, ExecStart, Description, allow-listed directives `Type, User, Group, DynamicUser, Service, ListenStream, ListenDatagram, WantedBy`; never `Environment=`), `*.wants` links, listeners (`ss -H -tulpn -e --cgroup`: uid, inode, cgroup; process only for own sockets), processes (pid, ppid, uid, user, comm, args ≤256, start ticks, cgroup), users + privileged group members, cron and sensitive-file hashes (`readable=false` for root-only files), configuration references `configs.sshd` (files read, Port, ListenAddress, LogLevel) and `configs.nginx` (directive values per context; includes followed only below `/etc/nginx`) |
| `packages` | JSON `extorq.linux.packages.v1` (os-release + dpkg name/version/arch/source); consumed by C3 (`docs/team/interface-changes/B1.md` §2) |
| `posture` | JSON checks: sshd settings from config files, apt periodic, unattended-upgrades, auditd, AppArmor, ufw, sysctls, reboot-required, pending `-security` updates (`apt list --upgradable`), `access()` probe of credential files, uid-0 accounts |

No shell, fixed argv per subprocess, minimal environment, per-subprocess timeouts, a
180 s watchdog, `O_NOFOLLOW` file reads, output size limits. Private keys are never
opened. Unit test: `tests/unit/linux/test_linux_dispatcher.py` (loads the deployed file).

## 3. Sources, events and fields

All events: `asset_id=linux:lab-vm-01`, `collection_method=ssh_pull`,
`source.collector_id=linux-ssh-lab-vm-01`, `provenance.raw_sha256` of the original line,
redacted/sanitised `message` and `raw`. `event_id = identity.event_id(source_type,
asset_id, native_key)` with native keys: journald `__CURSOR`; audit
`<node>:<serial>:<sec.ms>:<record type>`; snapshot diffs `<item key>:<change>:<content sha256>`.

### 3.1 journald (`linux.journald`, plus `linux.nginx` / `linux.app` lines)

Claimed identities are checked against journald's trusted fields (`_UID`, `_EXE`,
`_SYSTEMD_UNIT`, `_PID` are attested by the kernel / journald, `SYSLOG_IDENTIFIER` is not).
A contradiction produces `system.log.notable` with
`attributes.forged_identity_suspected=true` and no service reference; a missing trusted
field gives `attributes.source_verified=false`.

| Lines (real formats on lab-vm-01) | Event | Key fields |
|---|---|---|
| `Invalid user X from IP port P` | `auth.ssh.invalid_user` | actor.name, network.src_ip/src_port, attributes.invalid_user |
| `Failed <method> for [invalid user] X from IP port P ssh2[: TYPE SHA256:…]` | `auth.ssh.login_failed` | attributes.auth_method, key_type, key_fingerprint, invalid_user |
| `Accepted <method> for X from IP port P ssh2: TYPE SHA256:…` | `auth.ssh.login_succeeded` | as above |
| `Connection closed/reset by [invalid\|authenticating user X] IP port P [preauth]`, `Disconnected from … [preauth]` | `auth.ssh.preauth_closed` | attributes.close_kind, invalid_user, authenticating_user |
| `error: maximum authentication attempts exceeded …`, `Disconnecting … Too many authentication failures [preauth]` | `auth.ssh.max_auth_exceeded` | attributes.signal |
| `pam_unix(sshd:session): session opened/closed for user X` | `system.log.notable`, action `ssh.session_opened/closed` | actor.name, attributes.session_uid |
| `pam_unix(<svc>:auth): authentication failure; …` (sshd, su, …) | `auth.pam.failure` | attributes.pam_service, ruser, tty, network.src_ip (rhost) |
| `FAILED SU (to T) U on tty` | `system.log.notable`, action `su.failed` | actor.name, attributes.run_as |
| sudo `U : PWD=… ; USER=… ; COMMAND=…` / `U : <reason> ; …` (also with leading spaces) | `auth.sudo.command` / `auth.sudo.failure` | process.command_line (redacted), attributes.run_as, tty, cwd, reason |
| useradd/userdel/usermod/passwd/… | `system.log.notable`, action `account.<tool>` | attributes.account |
| systemd PID 1 `Started/Stopped/Reloaded/Finished/Failed to … U`, `U: Deactivated successfully`, `U: Failed with result`, restart scheduled | `system.service.state_changed` | resource.name, attributes.state, attributes.subject… |
| PID 1 `Reloading requested from client PID N ('comm') (unit U)...` | `system.systemd.daemon_reload` | attributes.requested_by_pid/comm/unit |
| `nginx_access` JSON (`$uri`, never `$request_uri`) | `http.request` (`linux.nginx`) | http.method/route/status_code/request_id/user_agent/duration_ms/bytes_sent, network.src_ip |
| `nginx_error` (`YYYY/MM/DD hh:mm:ss [level] pid#tid: *conn text, client: …, request: "…"`) | `http.server.error` (`linux.nginx`) | attributes.error_class, log_level, http.route (query stripped from route, message and raw) |
| `lab-portal` JSON (`lab-portal.log.v1`) | `app.auth.login_failed/succeeded`, `app.authz.denied`, `http.request` (`linux.app`) | actor.name, attributes.reason, http.request_id (only when propagated by nginx) |
| `extorq-collect-dispatch` denial | `system.log.notable`, action `dispatch.denied` | attributes.boundary_violation, first_token, command_sha256_prefix |

Not turned into events (context only): `Connection from …`, `Postponed publickey`,
`Starting session`, post-auth `Disconnected from user`, sudo session lines, systemd
`Starting…/Stopping…`, per-user managers. **OpenSSH 9.6 writes no `Failed publickey` line
for non-existent users** (verified on the VM): attacks on invalid names appear as
`invalid_user` + `preauth_closed` (+ `max_auth_exceeded`).

### 3.2 auditd (`linux.auditd`)

Rules (`infra/vm/files/audit/extorq.rules`): watches `-p wa` with keys `extorq_systemd`
(`/etc/systemd/system`, `/usr/lib/systemd/system`), `extorq_sshd`, `extorq_sudoers`,
`extorq_identity` (`/etc/passwd`, `/etc/shadow`), `extorq_cron`, and `execve`/`execveat`
with `euid=0`, `auid>=1000`, `auid!=unset` (`extorq_root_exec`). Log format ENRICHED,
`log_group=adm`, rotation 5 × 8 MB.

| Records | Event | Key fields |
|---|---|---|
| SYSCALL+CWD+PATH+PROCTITLE with an `extorq_*` watch key | `file.audit.watch` | resource.path (absolute), attributes.audit_key, syscall, nametype, audit_serial, actor (auid/AUID), process (pid, exe, redacted proctitle) |
| SYSCALL+EXECVE+… with `extorq_root_exec` | `process.audit.exec` | process.command_line (EXECVE args joined, redacted), actor.id/name (auid), attributes.euid |
| `CONFIG_CHANGE` (rule add/remove, `op=set`), `DAEMON_END/ABORT/CONFIG` | `audit.config.changed` | attributes.audit_op, audit_key, affects_extorq_rule, setting/previous/current value |

Records are grouped by `msg=audit(<sec>.<ms>:<serial>)`; a syscall event is complete when
its PROCTITLE arrived. An incomplete event at the end of a chunk is held back and re-read
on the next poll (deterministic ids make re-reads idempotent).

### 3.3 Inventory diffs (`linux.inventory`, every 60 s; packages hourly)

| Snapshot | Events (first snapshot = baseline: no events) |
|---|---|
| unit files and drop-ins (path → sha256, ExecStart, …) | `persistence.systemd.unit_created/modified/deleted` (resource.path/name, attributes.sha256, previous_sha256, exec_start, vendor_unit, subject_service_id) |
| `*.wants` / `*.requires` links | `persistence.systemd.unit_enabled` (attributes.wanted_by) |
| listeners (`proto:addr:port` → cgroup, unit, socket uid) | `network.listener.opened/closed` (network.dst_ip/dst_port, attributes.unit, owner_attribution) |
| accounts | `account.user.created/deleted` (actor.name, attributes.uid, shell, interactive_shell) |
| cron files | `persistence.cron.changed` |
| sensitive files (hash, or size/mtime when unreadable) | `config.file.changed` (`/etc/group` carries `privileged_members_added/removed` for sudo, adm, …) |
| dpkg packages | `package.installed/removed/upgraded` |

`InventoryItem`s: changed items and tombstones every diff, a complete snapshot (incl.
processes) at baseline and every 6 h.

### 3.4 Posture (`linux.posture`, scanner `extorq-posture-linux`, every 15 min)

One `ScanRun` per posture read with a fixed scope (25 checks: sshd, updates, auditd,
apparmor, ufw, sysctl, reboot, accounts, file_access); a `PostureFinding` per failed check
with a stable `finding_id(asset, scanner, check_id, resource)`; skipped checks make the scan
`partial` (resolves nothing). sshd values come from the configuration files (first value
wins, OpenSSH 9.6 defaults when unset, labelled in the evidence). Findings attributable to
a discovered service carry `service_id` (sshd checks → ssh, auditd → auditd,
unattended-upgrades → unattended-upgrades). Monitored settings that change between scans
produce `config.security_setting.changed`. On 2026-11-21 the lab VM had 6 genuine
findings: pending security updates (33 packages), ufw disabled, IPv4/IPv6 ICMP redirects
accepted, redirects sent, `fs.suid_dumpable=2`.

## 4. Services (contract 1.1, PLAN §10)

### 4.1 Discovery (`extorq_collectors.linux.discovery`)

| Evidence | Source |
|---|---|
| `process` | `/proc/<pid>/cgroup` puts the process in `/system.slice/<unit>` (or `/init.scope` = PID 1) |
| `listening_socket` | `ss -e --cgroup`: the kernel reports the cgroup of the process that created each socket (no root needed) |
| `systemd_unit` | effective unit file (systemd precedence `/etc` > `/run` > `/usr/local/lib` > `/usr/lib`); template instances map to `name@.service` |
| `configuration` | sshd (`files_read`, Port, LogLevel) and nginx (`listen`, `proxy_pass`, log destinations) |
| `adapter_config` | `adapters.webapp-json.apps` in `config/collectors/linux.yaml` |

A service is: a `.service` unit (or `init.scope`) with running processes, a unit owning a
listening socket (incl. socket activation: `ssh.socket` → `ssh.service`), an enabled unit
file in `/etc/systemd/system` or `/usr/local/lib/systemd/system`, a configured application,
or a previously discovered service whose unit file still exists (it then shows as not
running; it is `removed` only when its unit file disappears). User sessions and per-user
managers are never host services. Processes are never assumed to be network services.

Port attribution: **confirmed** only when the socket's cgroup names the service's unit or
its activating `.socket` unit (basis recorded); **inferred** from configuration or a unique
well-known port when the dispatcher reports no cgroup; otherwise the listener stays
**unattributed** (asset level, `InventoryItem` + `network.listener.*`). Relationships from
configuration plus socket evidence: nginx `upstream_services=[lab-portal.service]`,
lab-portal `fronted_by=[nginx.service]`.

Instances: the top-level processes of a unit (`instance_key = <boot_id>:<pid>:<start ticks>`,
`started_at = btime + start_ticks/clk_tck`); child processes (nginx workers) resolve to their
instance, so events from them carry `service.instance_id`. Vanished instances get
tombstones (`present=false`, `state=stopped`).

### 4.2 Adapters (`extorq_collectors.linux.adapters`)

| adapter | support | matches | telemetry | never collects |
|---|---|---|---|---|
| `ssh` | implemented | `ssh.service`, `sshd.service`, `ssh.socket`, exe `sshd` | journald `sshd` (auth + session) | passwords/KI responses, keys, session contents |
| `nginx` | implemented | `nginx.service`, exe `nginx` | journald `nginx_access` (JSON) + `nginx_error` | query strings, bodies, Authorization/Cookie, Referer queries |
| `apache` | implemented, **not deployed in the lab** (tested on the formats documented at httpd.apache.org) | `apache2.service`, `httpd.service` | journald `apache_access` (Common/Combined) + `apache2`/`httpd`/`apache_error` | query strings, bodies, Referer, Authorization |
| `webapp-json` | implemented | configured apps (`lab-portal.service`), schema `lab-portal.log.v1` | journald `<app identifier>` | passwords, session tokens, bodies |
| `systemd` | implemented | `init.scope` (PID 1) | journald PID 1 lifecycle + inventory unit diffs | `Environment=`/`EnvironmentFile=`, unit contents beyond the allow-list |
| `auditd` | implemented | `auditd.service` | audit log | file contents, non-ExtorQ audit records |
| `ftp`, `postgresql`, `mysql`, `dns`, `redis` | **planned** (shared registry) | vsftpd/ProFTPD, postgres, mysqld, named/unbound/dnsmasq/systemd-resolved, redis-server | none | see `extorq_collectors.services.planned` |

Events carry `service = {service_id, name, instance_id, adapter_id}` of the PRODUCING
service; the unit an event is about (lifecycle, persistence, listener, setting) is in
`resource.name` and `attributes.subject_service_id` when that unit is a discovered service.

### 4.3 Coverage

`classify_coverage` with the freshness of the adapter's collection channel (journal,
audit, inventory read through the boundary in this cycle), not the event volume: an idle
sshd whose journal is read successfully is `monitored`. Adapter prerequisites visible in
configuration downgrade to `degraded` with a note (nginx logs not routed to journald,
sshd `LogLevel` below INFO). Disabled adapters: `unmonitored`, and their records are not
collected at all. On 2026-11-21: 21 services; ssh, nginx, lab-portal, systemd, auditd
`implemented/monitored`; systemd-resolved `planned/unmonitored` (dns); 15 others
`none/unmonitored`.

## 5. Checkpoints, gaps, restart safety

* `journal.cursor`, `audit.inode` + `audit.offset` are committed by `ctx.emit` in the same
  SQLite transaction as the records they cover (SDK outbox); inventory/service snapshots
  likewise. A failed step discards its staged snapshots (`ctx.discard_staged()`).
* Lost journald cursor (`cursor_exact=false`) → `extorq.collector.gap_detected`
  (`linux.journald`, `gap_reason=journal_cursor_not_found`); audit file rotated past the
  checkpoint or truncated → gap (`linux.auditd`, `rotated_past_offset` / `file_truncated`).
* First run reads the last 2 h of journald and the whole current audit log.
* Verified restart (2026-11-21): stop with SIGTERM, restart → journald resumed after the
  checkpoint, 0 event ids re-ingested, `uniqExact(event_id) = count()`.

## 6. Known gaps and caveats

* **SLIRP NAT**: QEMU user-mode networking makes every connection from the Mac appear
  from `10.0.2.2` (sshd, nginx, lab-portal). `network.src_ip` reports what the source logged;
  correlation treats `10.0.2.2` as non-identifying (C2-IC-4).
* **No process attribution for others' sockets without root**: `ss -p` shows owners only
  for the collector's own sockets; ExtorQ uses the socket cgroup instead and never guesses.
* **PID 1 is not audited**: the kernel command line has no `audit=1`, so processes started
  before auditd (notably systemd PID 1) have no audit context; unit enable/disable
  symlinks created by PID 1 over D-Bus produce no audit record (the inventory diff
  captures them). Unit files written by users/sudo are audited.
* **pam_motd** on operator logins produces ~40 `process.audit.exec` events per login
  (genuine root execs on behalf of the operator).
* Root-only files (`/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/`) are reported with
  `readable=false` (size/mtime only); sudoers.d contents cannot be listed.
* journald: persistent, default limits (10 % of the 15 GB disk, max 4 GiB); collection
  starts 2 h back on first run. auditd keeps 5 × 8 MB.
* nginx error-log `[info]` records (e.g. malformed request lines) are not routed (level
  `warn`); the access log still records the 400.
* SSH session start/end use `system.log.notable` until the catalog has dedicated types
  (proposal in `docs/team/interface-changes/B1.md`).

## 7. Simulations and verification

| Script | Scenario | Expected genuine telemetry |
|---|---|---|
| `simulations/http/http_probe.sh` | HTTP-001 | 11 `http.request` (nginx), 5 `app.auth.login_failed`, 1 `app.authz.denied` |
| `simulations/vm/vm_001_ssh_failed_auth.sh` | VM-001 | 9 `auth.ssh.invalid_user`, 8 `auth.ssh.preauth_closed`, 2 `auth.ssh.max_auth_exceeded` |
| `simulations/vm/vm_002_systemd_persistence.sh` | VM-002 | `persistence.systemd.unit_created` + `unit_enabled`, `service.discovered`, `file.audit.watch` (extorq_systemd), `process.audit.exec`, `auth.sudo.command` |

Each script records its SimulationRun (`uv run extorq-collect sim-record`), accepts
`--run-id` (reuse one id for the CORR-002 sequence HTTP-001 → VM-001 → VM-002) and
`--cleanup`. Verify with
`uv run python -m extorq_collectors.linux.verify --run-id <id>` or
`--asset linux:lab-vm-01 --since-minutes 30` (read-only `extorq_api_ro`, server-side
parameters, password read from its file). Unit tests: `uv run pytest tests/unit/linux -q`
(fixtures: real captures from the VM, `tests/fixtures/linux/README.md`).
