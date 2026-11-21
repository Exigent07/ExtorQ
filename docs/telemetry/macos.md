# macOS endpoint telemetry (collector `macos-workstation-01`)

Owner: B3. Code: `collectors/src/extorq_collectors/macos/`. Config:
`config/collectors/macos.yaml`. Tests: `tests/unit/macos/` (fixtures in
`tests/fixtures/macos/`). Simulation: `simulations/macos/mac_001_launchagent.sh`.

The collector is a native (non-containerised) process on the Apple Silicon host,
asset **`macos:workstation-01`**, producer **`macos-workstation-01`**. It runs as
the logged-in user through supported, read-only interfaces only:

* **no sudo, no root**, no Full Disk Access, no configuration profile, no
  Endpoint Security / Network Extension entitlement, no kernel extension;
* **no security control is weakened** (it never runs `launchctl load|bootstrap|
  enable|kickstart`, `defaults write`, `csrutil`/`spctl`/`socketfilterfw` setters:
  a read-only sub-command policy in `commands.py` refuses them even if a bug
  tried, see "Command execution");
* **standard tools do not provide EDR-grade telemetry.** Process execution,
  file activity and network flows are *not* collected (see "Collection gaps").

Run it with A's SDK runner (single cycle or continuously):

```
uv run extorq-collect run --only macos-workstation-01 --once
uv run extorq-collect run --only macos-workstation-01
```

Validated on macOS 27.0.1 (26A434), Mac16,8, Python 3.12 (uv-managed CPython).

## Sources and schedule

The runner calls the collector every 60 s; each source has its own interval and
runs when due. Each source commits its records, checkpoint and snapshots in its
own atomic `ctx.emit`. A failing source drops what it staged
(`ctx.discard_staged()`), is reported in health and never blocks the others; the
cycle is `failed` only when every due source failed. One instance per state
directory (`flock` on `var/collectors/macos-workstation-01/macos-collector.lock`)
so two processes can never emit the same change twice.

| Source | Interval | Source type | Records |
|---|---|---|---|
| `unified_log` | 60 s | `macos.unified_log` | auth / sudo / XProtect / Gatekeeper events, gap events |
| `launchd` | 60 s | `macos.launchd` | `persistence.launchd.item_{created,modified,deleted}`, `launch_item` inventory |
| `inventory` | 300 s | `macos.inventory` | listeners (+ `network.listener.{opened,closed}`), processes, local accounts (+ `account.user.{created,deleted}`), services (`Service`, `ServiceInstance`, `service.*`) |
| `posture` | 300 s | `macos.posture` | 2 `ScanRun`s (`configuration`, `exposure`) + `PostureFinding`s, `config.security_setting.changed` |
| `applications` | 3600 s | `macos.inventory` | `software` inventory (installed applications) |
| `asset` | 300 s | — | `Asset` record (sent when changed or every 900 s) |

All timestamps are UTC (`--timezone UTC` for `log show`; `ps lstart` local time is
converted). Event ids are deterministic (`identity.event_id`), so re-reads and
retries collapse at the gateway and in ClickHouse.

## Command execution (every subprocess)

`commands.run_command`: absolute path from a fixed allow-list (no `PATH` lookup;
`log` is also a zsh builtin, irrelevant because no shell is used), argument
list (never `shell=True`), argv validation (no NUL, bounded count/length), fixed
minimal environment (`PATH`, `LC_ALL=C`, `LANG=C`: no inherited secrets),
`stdin=/dev/null`, `cwd=/`, own process group (killed as a group on timeout),
hard wall-clock timeout, bounded stdout/stderr (exceeding stdout stops the
command and marks the result truncated, never "ok").

Read-only policy (`check_read_only_policy`), refused otherwise:

| Executable | Allowed |
|---|---|
| `/usr/bin/log` | `show` only |
| `/bin/launchctl` | `print <domain>[/<label>]`, `print-disabled <domain>` only |
| `/usr/bin/defaults` | `read`, `export` |
| `/usr/bin/dscl` | `. -read`, `. -search`, `. -list` |
| `/usr/sbin/sysctl` | `-n` with `hw.model`, `hw.machine`, `kern.osversion`, `kern.boottime` |
| `/usr/bin/fdesetup` | `status` |
| `/usr/bin/csrutil` | `status`, `authenticated-root status` |
| `/usr/libexec/ApplicationFirewall/socketfilterfw` | `--getglobalstate`, `--getstealthmode`, `--getallowsigned`, `--getblockall` |
| `/usr/sbin/spctl` | `--status` |
| `/usr/sbin/netstat`, `/usr/sbin/lsof`, `/bin/ps`, `/usr/bin/sw_vers`, `/usr/sbin/system_profiler` | read-only by nature |

In-process (no subprocess): `plistlib` for launchd plists, `os.scandir`/`os.open`
(`O_NOFOLLOW`, `O_NONBLOCK`, size cap) for plist files, and libproc
`proc_pidpath(3)` via `ctypes` for kernel-reported executable paths.

## 1. Unified logging (`macos.unified_log`)

Command: `/usr/bin/log show --style ndjson --no-pager --color none --timezone UTC
--start @<s> --end @<e> --predicate <P>`.

Incremental, bounded collection: checkpoint = window end (epoch seconds) + the
event ids seen in the last `overlap_seconds` (10 s re-read, de-duplicated by
event id), `settle_seconds` 5 (most recent seconds not read yet), at most
`max_window_seconds` 900 per cycle, `max_records_per_cycle` 5000,
`max_output_bytes` 32 MiB, timeout 120 s. A window cut by a limit advances only
to the last complete second (rest re-read next cycle); if no progress is possible
the window is skipped and an `extorq.collector.gap_detected` event is emitted.
History older than `max_backfill_seconds` (24 h) after an outage is skipped with a
gap event (reason, start, end, seconds). First run reads the last 15 minutes.
Measured: a 70 s window takes ~1.4 s, 900 s ~2.9 s, 24 h ~70 s.

Event identity (`unified_log.native_key`): `bootUUID:machTimestamp:threadID:traceID`;
content key (SHA-256 of timestamp, process, pid, subsystem, category, message)
only when those fields are missing.

The predicate is assembled from fixed fragments (`unified_log.PRODUCERS`);
configuration can only select producer *names*.

| Producer | Predicate | Event types | On the reference host (24 h window, 2026-11-21) |
|---|---|---|---|
| `sudo` | `process == "sudo"` | `auth.sudo.command`, `auth.sudo.failure`, `system.log.notable` | no sudo use in window; parser tested with labelled synthetic records |
| `sshd` | `process == "sshd" OR process == "sshd-session"` | `auth.local.failure` (failed password/publickey), `system.log.notable` (accepted, invalid user, other) | none: Remote Login is off (job not loaded) |
| `screensharing` | `process == "screensharingd"` | `auth.local.failure`, `system.log.notable` | none: Screen Sharing off |
| `opendirectory_auth` | opendirectoryd `auth` category, "Authentication failed for" | `auth.local.failure` | 6 records (real; user name is `<private>`, GeneratedUID public) |
| `authorization` | `com.apple.Authorization`, "Failed to authorize" | `auth.local.failure` (denied), `system.log.notable` (user cancelled, -60006) | none in window; synthetic-tested |
| `screen_lock` | loginwindow `authFailWithMessage:numFailedAttempts:` | `auth.local.failure` | captured earlier (fixture is real) |
| `xprotect` | XProtect Remediator results, scan start/finish, behaviour detection forwarding | `security.xprotect.event` | 172 records |
| `gatekeeper` | `com.apple.syspolicy.exec` GK scan/evaluate, prompts, approvals | `security.gatekeeper.event` | 290 records |

Fields: `event_time` (source timestamp, UTC), `observed_time`, `process.{pid,
name, executable, uid, command_line}` (sudo `COMMAND=` only, redacted),
`actor.{name,id}` (sudo user, sshd/screensharing user, opendirectoryd
GeneratedUID), `network.{src_ip,src_port}` (sshd, screensharing viewer), source
`severity_hint` from `messageType` (Fault high, Error medium, others info),
`attributes`: `producer, subsystem, log_category, message_type, sender_image`,
per producer `run_as, tty, cwd, reason, auth_service, auth_method, invalid_user,
right, client, status_code, plugin, status_message, threat_detected, team_id,
signing_id, bundle_id, path_hash, scan_result, prompt_type, approved`, and
`private_redaction=true` when the message contains `<private>`. `raw` is a
canonical excerpt of the ndjson record (selected keys), redacted and bounded;
`provenance.raw_sha256` is the SHA-256 of the original line.

Privacy and limits:

* `<private>`: unified logging replaces dynamic arguments the producer did not
  mark public. ExtorQ does not try to recover them (that needs a profile or
  root). Counted per run in health (`private_fields`).
* `resolve_generated_uid` (default on): an opendirectoryd failure carries the
  account's public GeneratedUID; the collector maps it to the account **short
  name** with `dscl . -search /Users GeneratedUID <uuid>` (UUID validated, cached).
  `RealName` is never read. `attributes.actor_name_source=dscl_generated_uid`.
* Unified logging is not an audit trail: retention is size-bounded and messages
  may be rate-limited; a gap in the log store itself is not detectable.
* Catalog note: `auth.ssh.*` types only allow `linux.journald`, so macOS sshd
  failures are `auth.local.failure` with `attributes.auth_service=sshd` (proposal
  B3-IC-1 in `docs/team/interface-changes/B3.md`).

## 2. LaunchAgents / LaunchDaemons (`macos.launchd`)

Scanned every 60 s (plain directory reads):

| Location | `attributes.scope` | kind |
|---|---|---|
| `~/Library/LaunchAgents` | `user` | agent |
| `/Library/LaunchAgents` | `system` | agent |
| `/Library/LaunchDaemons` | `system` | daemon |
| `/System/Library/Launch{Agents,Daemons}` | counted only (health) | sealed system volume (SIP) |

Each `*.plist` is opened with `O_NOFOLLOW|O_NONBLOCK` (symlinks recorded and the
target read; FIFOs/devices never read), size-capped at 1 MiB (larger files are
hashed only), hashed (SHA-256 of the file bytes) and parsed with `plistlib`
(XML/binary; hostile input yields `parse_error`, never an exception).

Kept keys: `Label`, `Program`/`ProgramArguments` (redacted, max 32),
`RunAtLoad`, `KeepAlive` (true/false/conditional), `StartInterval`,
`StartCalendarInterval` (presence), `WatchPaths` (count), `Disabled`,
`UserName`, `LimitLoadToSessionType`, `EnvironmentVariables` (**names only**:
values often hold credentials), `Sockets` (rendered `tcp:<node>:<service>`),
`MachServices` (count), `AssociatedBundleIdentifiers`, file `sha256`, `size`,
`file_mtime` (attacker-controllable: informational only), `mode`, `owner_uid`,
`world_writable`, `is_symlink`/`symlink_target`.

Diff (SDK snapshot `launchd.items`, keyed by path, fingerprint = sha256):

* first scan = baseline: inventory only, no events;
* `persistence.launchd.item_created` / `item_modified` (`attributes.previous_sha256`)
  / `item_deleted`; `resource.path`, `resource.name` (label), `attributes.scope`;
  `event_time` = observation time (mtime is not trusted);
* `attributes.allowlisted=true` when the label matches `launchd.allowlist`
  (fnmatch): the event is **still emitted**; detection decides;
* `service` (ServiceRef) = the launchd job the plist defines (label);
* simulation tag: the generic `extorq-sim-<run_id>` marker or the launchd label
  form `com.extorq.sim.<run_id>` (used by MAC-001);
* a directory that cannot be read keeps its previous items (unreadable is never
  reported as deleted); a file that becomes unreadable is reported as modified
  with `read_error`;
* `launch_item` inventory: changed items each run, full snapshot hourly,
  tombstones (`present=false`) for removed paths.

Not visible without root: what launchd has *approved/loaded* per the
Background Task Management database; loaded jobs are seen through `launchctl
print` instead (services, below).

## 3. Posture (`macos.posture`, scanner `extorq-posture-macos`)

Every 300 s, two `ScanRun`s with independent scopes (`configuration`,
`exposure`), so a partial exposure scan never blocks resolution of
configuration findings and vice versa. Finding ids are stable
(`identity.finding_id(asset, scanner, check_id, resource_key, qualifier)`).
Results: `pass`, `fail` (PostureFinding), `not_set` (preference absent: OS
default **not inferred**, no finding), `error` (command failed / unrecognised
output: the ScanRun becomes `partial`, so earlier findings are never resolved by
an incomplete scan).

| Check id | Command | Severity |
|---|---|---|
| `macos.filevault.enabled` | `fdesetup status` | high |
| `macos.sip.enabled` | `csrutil status` | high |
| `macos.ssv.authenticated_root` | `csrutil authenticated-root status` | high |
| `macos.firewall.enabled` | `socketfilterfw --getglobalstate` | medium |
| `macos.firewall.stealth_mode` | `socketfilterfw --getstealthmode` | low |
| `macos.gatekeeper.enabled` | `spctl --status` | high |
| `macos.softwareupdate.{automatic_check, critical_update_install, config_data_install, automatic_download, automatic_macos_install}` | `defaults export /Library/Preferences/com.apple.SoftwareUpdate -` | medium/low |
| `macos.softwareupdate.os_update_pending` | same (`FirstOfferDateDictionary`, undocumented keys, last background scan) | low (medium after 14 days) |
| `macos.softwareupdate.recommended_pending` | same (`RecommendedUpdates`) | low |
| `macos.appstore.auto_update` | `defaults export /Library/Preferences/com.apple.commerce -` | low |
| `macos.accounts.guest_enabled` | `defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled` (that key only: the domain also holds user names) | medium |
| `macos.accounts.admin_count` | `dscl . -read /Groups/admin GroupMembership` (root, _mbsetupuser excluded; max configurable) | medium |
| `macos.sharing.{remote_login, screen_sharing, remote_management, file_sharing_smb, airplay_receiver}` | derived from listening sockets (TCP 22, 5900, 3283, 445, ControlCenter 7000/5000 on non-loopback); `systemsetup` needs admin and is not used | medium/low |
| `macos.network.exposed_listener` | TCP listener on a wildcard/external address (one finding per listener) | low |
| OS version / model | `sw_vers`, `sysctl -n hw.model` | (asset attributes) |

On the reference host the **Application Firewall is disabled** and surfaces as a
genuine medium finding (`Firewall is disabled. (State = 0)`), as do stealth mode
off, AirPlay Receiver / rapportd listeners on `*`, a pending macOS 27.2.1 offer
and a pending Command Line Tools update.

Sharing findings carry `service_id` (Remote Login → `com.openssh.sshd`, Screen
Sharing → `com.apple.screensharing`, Remote Management →
`com.apple.RemoteDesktop.agent`, SMB → `com.apple.smbd`, AirPlay →
`com.apple.controlcenter`); exposed-listener findings carry the service that
owns the socket when attribution is confirmed.

Setting changes between posture snapshots (SDK snapshot `posture.settings`,
committed atomically with the events) → `config.security_setting.changed`
(`attributes.setting, previous_value, current_value, scan_run_id`; list
settings add `added`/`removed`). Unknown values (None) never produce a change.

## 4. Inventory (`macos.inventory`)

* **Listening sockets**: `netstat -anvW -p tcp|udp` (all sockets; the `process:pid`
  column is the kernel's *last* pid that used the socket, name truncated to 16
  chars; socket-activated services show `launchd:1`). **Observed on macOS 27:**
  netstat returns an *empty* table (exit 0, no header) for any descendant of an
  ad-hoc signed process, such as the uv-managed CPython running the collector
  (verified: same command from the shell or Apple's `/usr/bin/python3` returns
  the full table). The collector then falls back to `lsof -nP -iTCP -sTCP:LISTEN`
  / `-iUDP` (field output), which only sees **the current user's processes**:
  root-owned listeners (sshd, Screen Sharing, mDNSResponder) are invisible. This
  is reported as a gap and the dependent posture checks report `error` (never
  `pass`). Snapshots are keyed by method (`listeners.lsof` / `listeners.netstat`)
  so switching methods never fabricates opened/closed events. Diff →
  `network.listener.opened` (also when the owning process changed:
  `attributes.owner_changed`, `previous_processes`) / `network.listener.closed`
  with `network.{dst_ip,dst_port,protocol}`, `process.{name,pid,executable}`
  when unique, and `service` when the owner was observed and belongs to exactly
  one discovered service. `listener` inventory items.
* **Processes**: `ps -axww -o pid=,ppid=,uid=,user=,lstart=,comm=` plus the
  kernel-reported executable path from `proc_pidpath` (works unprivileged for
  user and root processes; `comm` is argv[0], which a process chooses itself).
  `attributes.executable_verified` says which one was used. **Full arguments are
  not collected by default** (`include_process_args: false`; when enabled they are
  redacted and truncated). Process inventory only (diff each run, full snapshot
  hourly): the catalog has no macOS process events and this is not exec telemetry.
* **Local accounts**: `dscl . -list /Users UniqueID` and `... UserShell` → `user`
  inventory (`uid`, `shell`, `system_account`, `login_shell`), diff →
  `account.user.created` / `account.user.deleted` (`actor.name`, `actor.id`=uid).
  `RealName` is never read.
* **Installed applications** (hourly): `system_profiler -json -detailLevel mini
  SPApplicationsDataType` → `software` items (`name, version, obtained_from,
  signer, signing_chain, signed, arch_kind, last_modified`), full snapshot each run
  plus tombstones. No macOS package events exist in the catalog.

## 5. Services (service-aware monitoring, PLAN §10)

Runs with every inventory cycle through B1's shared interface
(`extorq_collectors.services`). Evidence:

* launchd job **definitions**: the three plist directories above, plus the
  definitions of a fixed list of Apple sharing services on the sealed volume
  (read-only): Remote Login `com.openssh.sshd`, Screen Sharing
  `com.apple.screensharing`, File Sharing `com.apple.smbd`, Remote Management
  `com.apple.RemoteDesktop.agent`, FTP proxy `com.apple.ftp-proxy`, TFTP
  `com.apple.tftpd`, Apache `org.apache.httpd`, NFS `com.apple.nfsd`, CUPS
  `org.cups.cupsd`. These are **always reported, on or off**.
* **loaded jobs**: `launchctl print system` and `launchctl print gui/<uid>`
  (services + disabled-services blocks only; the `environment` block is never
  parsed or stored). `launchctl print system/<label>` exits 113 "Could not find
  service" when a job is not loaded. Apple's own ~900 jobs are **not** turned into
  services; third-party loaded jobs are (this also reveals SMAppService
  background items that have no plist in the scanned directories, e.g.
  `com.ollama.ollama`), and Apple jobs are when they own a listening socket.
  `application.*` LaunchServices entries (GUI app instances) are never services.
* **listening sockets** → owning pid → the launchd job whose process tree
  contains it (`HOST_SERVICE`, key = label) or, without a job, the process
  executable (`APPLICATION`, key = verified executable path).
* **processes**: a known server binary (`sshd, nginx, httpd, vsftpd, proftpd,
  postgres, mysqld, mariadbd, mongod, redis-server, named, unbound, dnsmasq,
  memcached, php-fpm, ...`) outside any job tree becomes an `APPLICATION` with
  `process` evidence only. Other processes are never assumed to be services.

Port attribution: **confirmed** only when lsof/netstat reported the owning pid
and it is the service's process (or a descendant of its launchd job, e.g.
`mysqld` under `mysqld_safe`); **inferred** for sockets launchd holds for a
loaded socket-activated job (`Sockets` in its definition; owner is launchd, not
the service), e.g. `com.apple.ftp-proxy` on `127.0.0.1:8021`/`[::1]:8021`;
a listener whose owner pid is unknown stays **unattributed** (counted in health).
Exposure from the bind address: loopback / private / any / unknown.

Product/version only from evidence: Homebrew paths name the formula
(`/opt/homebrew/opt/redis/...` → `redis`) and `Cellar/<formula>/<version>/` the
version, taken from the job definition or from the kernel-verified executable of a
running instance (e.g. `/opt/homebrew/Cellar/redis/8.10.1/bin/redis-server` →
`8.10.1`, `attributes.version_evidence`); nothing else is guessed. `attributes`
record `launchd_label,
launchd_domain, job_loaded, job_running, job_pid, override, service_state
(not_loaded | loaded_idle | running), definition_path, definition_sha256,
program, run_at_load, keep_alive, allowlisted, socket_listeners, sharing_enabled,
app_bundle, executable_verified, product_evidence, owns_listening_socket`.

Adapters (coverage):

| Adapter | Support | Binding | Coverage on the reference host |
|---|---|---|---|
| `macos-sshd` | implemented | unified-log producer `sshd` (processes `sshd`, `sshd-session`) for job `com.openssh.sshd` | **unmonitored**: Remote Login is off (job not loaded), reported honestly; monitored as soon as it is loaded and the log source is fresh (≤ 600 s), degraded when stale/failing |
| `macos-screensharing` | implemented | producer `screensharing` (`screensharingd`) for `com.apple.screensharing` | unmonitored: off |
| `redis`, `mysql`, `postgresql`, `ftp`, `dns` | planned (shared registry) | none (extension points) | e.g. `sh.brew.redis`, `sh.brew.mysql`: discovered, unmonitored |
| other platforms' implemented adapters (Linux nginx/apache/systemd/...) | not claimed on macOS | — | support `none`, `attributes.other_platform_adapter` names them |

The macOS adapters match only macOS launchd labels, so the shared registry never
hands them a Linux candidate. They never collect passwords, keys, session
contents, screen contents or keystrokes.

Records: one `Service` per discovered service every inventory cycle
(`first_seen` preserved), `ServiceInstance` per process (key `pid:start_epoch`,
`asset_id` set, parent instance for child processes), tombstones for services
(`present=false`, `service.removed`) and instances (`state=stopped`) that
disappear. Events (`macos.inventory`, with `service` ref): `service.discovered`
(first cycle: `attributes.baseline=true`), `service.removed`,
`service.exposure.changed` (`endpoints_added`, `endpoints_removed`,
`attribution`, `exposure`, `non_loopback_exposure`). Unified-log events of
`sshd`/`screensharingd` carry the service reference (`adapter_id`).

## 6. Health and explicit collection gaps

`CollectorHealth.details` (per cycle): `sources` (`<source>=ok|error|disabled`),
`source_last_success`, `source_errors`, per-source last-run statistics (window,
records, duplicates, private fields, listener method, processes, verified paths,
services by coverage, unattributed listeners, findings, applications), and
`gaps`:

* process execution telemetry (exec/fork/exit) requires an Endpoint Security
  entitlement: not collected; processes are periodic ps snapshots only;
* file creation/modification telemetry requires Endpoint Security or Full Disk
  Access: not collected (plists are polled every 60 s; a plist created and deleted
  between two scans is missed);
* network flow telemetry requires a Network Extension: not collected;
* Background Task Management database requires root: not collected; loaded jobs
  visible through `launchctl print` only;
* `<private>` fields redacted by unified logging; not recoverable without a
  profile or root;
* unified logging is not an audit trail (size-bounded retention, rate limiting);
* `/System/Library` launchd plists are counted, not diffed;
* TCC privacy database requires Full Disk Access: not collected;
* (dynamic) socket table withheld → lsof, current user's processes only;
* process arguments not collected (privacy default).

## 7. Asset record

`macos:workstation-01`, `asset_type=macos_host`, `name=workstation-01`,
attributes `os_name, os_version, os_build` (`sw_vers`), `model_identifier`
(`sysctl -n hw.model`), `architecture`, `collector`, `collector_version`.
**Not collected:** serial number, hardware UUID, the user's real name, the
hostname (only reported as `display_name`/`attributes.hostname` when explicitly
configured in `asset.hostname`).

## 8. Data minimisation summary

| Never collected | How it is enforced |
|---|---|
| Serial number, hardware UUID, real names | no `SPHardwareDataType`, no `RealName`, hostname only if configured |
| Environment variable values of launchd jobs / domains | plist: key names only; `launchctl` environment blocks skipped (fixtures blank them) |
| Process arguments | off by default; redacted + truncated when enabled |
| Secrets in sudo command lines, plist arguments, log messages | `redact_text` then `sanitize_untrusted` on every free-text field; `provenance.redaction_count` |
| `<private>` log arguments | never recovered |
| File contents | only SHA-256 of plist files; preference domains read key by key or exported (SoftwareUpdate, commerce: no personal data) |
| Data outside the host | the collector reads local state only; output goes to the ExtorQ gateway over TLS (pinned CA) with the producer token |

All collected text is untrusted (log messages, plist values, process names) and is
sanitised and bounded before it leaves the collector.

## 9. MAC-001 simulation

`simulations/macos/mac_001_launchagent.sh [--run-id ID] [--wait S|--no-wait]`
creates `~/Library/LaunchAgents/com.extorq.sim.<run_id>.plist` (Label
`com.extorq.sim.<run_id>`, ProgramArguments `[/usr/bin/true]`, RunAtLoad false;
`plutil -lint` checked, written atomically), records the SimulationRun with
`uv run extorq-collect sim-record --scenario MAC-001 --asset macos:workstation-01`,
and waits (read-only query as `extorq_api_ro`, `simulations/macos/wait_event.py`)
for `persistence.launchd.item_created`. It **never runs launchctl**; the job is
never loaded. macOS may show a **"Background Items Added"** notification: that is
expected. `--cleanup --run-id ID` deletes the file only if it is a regular file
carrying that label, verifies it is gone, records `cleaned_up` and waits for
`persistence.launchd.item_deleted`. Requires the collector to be running. No
detection rule for MAC-001 exists yet (C2's optional rule); the scenario is
verified on telemetry.

## 10. Verification

```
uv run pytest tests/unit/macos -q
uv run extorq-collect run --only macos-workstation-01 --once
uv run python simulations/macos/wait_event.py --event-type persistence.launchd.item_created \
    --path ~/Library/LaunchAgents/com.extorq.sim.<run_id>.plist --since <iso>
```

Recorded results: `docs/team/status/B3.md`.
