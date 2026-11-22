# macOS collector fixtures

Data minimisation (PLAN section 11, review finding F-24): these fixtures are the
**minimum the unit tests need**. They started as captures from the reference host
(macOS 27.0.1 build 26A434, Mac16,8, captured with the exact commands the collector
runs, as the logged-in user, without privileges) and were reduced in build session 3
from 6,753 to under 1,000 lines. Every third-party application, service, process,
launchd label and signing identity of that host was removed or replaced by a clearly
**synthetic placeholder**: `com.example.thirdparty.*`, `ExampleApp`, `Example Helper
(Plugin)`, `Example App (UI)`, `Example Store App`, team ids `EXAMPLE001`/`EXAMPLE002`,
`Example Corp`. What remains real is Apple's own software (part of every macOS
install) and the hypervisor of the monitored Ubuntu VM (`qemu-system-aarch64`).

Scrubbing that applies to every real line:

* the account short name is `testuser`; no real name, hostname, computer name or
  serial number is present;
* public IP addresses are documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
  `2001:db8::/32`);
* launchd `environment` blocks are removed (the collector never parses them);
* the opendirectoryd GeneratedUID is `A1B2C3D4-0000-4000-8000-000000000001`.

## Provenance per file

| File | Provenance |
|---|---|
| `unified_log/opendirectoryd_auth_failed.ndjson`, `loginwindow_screenlock_failed.ndjson`, `xprotect_*.ndjson`, `trailer_empty.ndjson` | real records (Apple producers only) |
| `unified_log/gatekeeper_evaluate.ndjson`, `gatekeeper_prompt_flow.ndjson` | real syspolicyd records; the third-party signing identity in each message (team id, signing id, bundle id) and the path hash are replaced by synthetic values (`EXAMPLE001`, `com.example.thirdparty.agent`, `00000000000000a1`, ...) |
| `unified_log/synthetic_auth_producers.ndjson` | **synthetic** (sudo, sshd, screensharingd, authd; every line carries `extorqSynthetic`): no such event existed in the retained log of the reference host |
| `unified_log/synthetic_sshd_auth.ndjson` | **synthetic** OpenSSH 10 messages (`sshd`, `sshd-session`, `sshd-auth`) for the `auth.ssh.*` mapping, incl. a hostile user name, a sender outside the sealed system volume and a detection-test user name (`extorq-test-*`, ordinary data since schema 2.0); every line carries `extorqSynthetic`. Remote Login is off on the reference host and stays off |
| `unified_log/synthetic_sudo_documented.ndjson` | **synthetic** sudo records in the formats of sudoers(5) "EVENT LOGGING" of the installed sudo 1.9.17p2 (`1`/`3 incorrect password attempt(s)` with `COMMAND=validate`, `a password is required`, `ENV=... COMMAND=`, `command not allowed`, and a sender outside `/usr/bin/sudo`); the reference host's whole unified-log archive (2026-10-23 to 2026-11-22) holds no sudo record, so none could be captured |
| `software/codesign_display_apple_platform.txt` | real `codesign -dv --verbose=2` output for `/System/Applications/Calculator.app` |
| `software/codesign_display_developer_id.txt` | real `codesign -dv --verbose=2` output for a Developer ID application in `/Applications`; executable path, identifier, leaf authority, team id and timestamp replaced by synthetic values (`ExampleApp`, `com.example.thirdparty.exampleapp`, `Example Developer (EXAMPLE001)`) |
| `software/codesign_display_adhoc.txt`, `software/codesign_verify_unsigned.txt`, `software/codesign_verify_tampered.txt` | real `codesign` output for minimal bundles built in a scratch folder (ad-hoc signed, unsigned, ad-hoc signed then modified); never placed in `/Applications`, never executed; the scratch path is replaced by an `/Applications` path |
| `launchd/apple/*.plist` | unmodified copies of Apple's job definitions in `/System/Library/LaunchDaemons` (public configuration) |
| `launchd/user_agents/*.plist`, `launchd/system_daemons/*.plist` | **synthetic** third-party jobs: Homebrew-layout program paths (`/opt/homebrew/opt/<formula>/...`) exercise product evidence and the planned `redis`/`mysql` adapters; one empty-dictionary plist (no `Label`); one privileged helper with a Unix socket |
| `services/launchctl_print_system.txt`, `services/launchctl_print_gui.txt` | real `launchctl print` output trimmed to a few Apple jobs, endpoint rows, an unmanaged-process block and the disabled-services block; the third-party rows (`com.example.thirdparty.*`, one `application.com.example.thirdparty.app.*` instance, the `ExampleHelper` unmanaged process name) are **synthetic** |
| `services/ps_services.txt` | real `ps` rows for Apple processes and the VM's `qemu-system-aarch64`; the third-party rows (pids 516, 902, 904, 905, 1068, 1094, 1095, 7310, 7800, 7801) are **synthetic**, consistent with the launchctl and lsof files |
| `services/lsof_tcp_services.txt`, `services/lsof_udp_services.txt` | real lsof field blocks for ControlCenter, identityservicesd and qemu; the other blocks are **synthetic** in the same field format |
| `services/launchctl_print_sshd_missing.txt` | real output of `launchctl print system/com.openssh.sshd` while Remote Login is off |
| `inventory/netstat_tcp.txt`, `inventory/netstat_udp.txt` | real rows for Apple processes and launchd-held sockets; rows for third-party processes are **synthetic**, built on real row formats with the process column replaced |
| `inventory/lsof_tcp_listen.txt` | real ControlCenter block (this capture includes the `u` uid field); the redis-server and example-backend blocks are **synthetic** |
| `inventory/system_profiler_apps.json` | four real Apple applications (TextEdit, Time Machine, Tips, Automator Application Stub); `ExampleApp` and `Example Store App` are **synthetic** (one per provenance class) |
| `inventory/dscl_users_uid.txt`, `inventory/dscl_users_shell.txt` | real rows for Apple system accounts, `root`, `daemon`, `nobody` and `testuser`; the `testuser` shell is **synthetic** (`/bin/zsh`) |
| `posture/*.txt`, `posture/commerce_export.plist` | real command output (Apple tools) |
| `posture/softwareupdate_export.plist` | real SoftwareUpdate preferences reduced to the keys the posture checks read |
| `posture/dscl_search_generateduid.txt` | real `dscl . -search /Users GeneratedUID` output (GUID and account scrubbed) |

## Consistency of the services snapshot

`services/*.txt` and `launchd/user_agents` describe one host state: launchd jobs
`com.example.thirdparty.{redis,mysql,php}` run as pids 904, 905 and 902; `mysqld`
(1068) is a child of the `mysqld_safe` shell (905); php-fpm workers 1094/1095 are
children of 902; the GUI application `ExampleApp` (7800) has a backend (7801, a TCP
listener without its own launchd job) and a helper whose name contains spaces (7310);
ControlCenter (656) owns the AirPlay Receiver listeners; qemu (95469) owns the
VM's forwarded ports with a bare argv[0] (unverified path). Tests pin exact counts
of this snapshot (13 services, 10 instances, 19 processes, 14 listeners).

Listener records of the MAC-003 shapes (a user's process listening on all interfaces vs on
loopback) are **synthetic** lsof field blocks built in `test_macos_inventory.py`: opening such
a listener on the reference Mac would be the live detection test itself.
