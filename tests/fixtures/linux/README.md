# Linux collector fixtures (owner B1)

Provenance: **real responses captured from the lab VM `lab-vm-01`** (Ubuntu 24.04.5 LTS arm64)
on 2026-11-21 between 14:28 and 14:44 UTC through the dispatch boundary
(`SSHDispatchClient(...).run_bytes("journal - 5000" | "audit ..." | "inventory" | "packages"
| "posture" | "version")`), while the activity below was genuinely performed on the VM.
No secrets: SSH key fingerprints and lab user names are public lab identifiers; no password
was ever typed into a logged field (the `su` attempt used a dummy string that does not appear
in any capture). Running `extorq.common.redaction.redact_text` over every file flags only
the dispatcher's own `first_token=<word>` field (a false positive on the field name, not a
secret; the dispatcher now writes `command_word=` and the parser accepts both).

| File | Content | Activity that produced it |
|---|---|---|
| `journal/sshd.ndjson` | every sshd line of VM-001 run `c7cbc976ecaf` + up to 2 lines per other sshd message template | `simulations/vm/vm_001_ssh_failed_auth.sh`, operator/collector logins, a throwaway key against `extorq-admin`, two TCP resets during key exchange |
| `journal/su_pam.ndjson` | `pam_unix(su:auth)` failure + `FAILED SU` | `su extorq-collector` with a wrong password (account is locked) |
| `journal/sudo.ndjson` | sudo command lines, `user NOT in sudoers` (real leading spaces), session lines | redeploy, VM-002 run `0e49c82d82bc`, `sudo -u nobody sudo -S true` |
| `journal/systemd_pid1.ndjson` | one line per PID-1 message template (start/stop/reload/deactivated/daemon reload) | normal operation, redeploy, VM-002 |
| `journal/systemd_user_manager.ndjson` | per-user manager lines (must be ignored) | operator/collector sessions |
| `journal/nginx.ndjson` | `nginx_access` JSON lines (HTTP-001 run `fff5113314b3`, health checks) and one `nginx_error` 413 line whose request carried `?probe=1` | `simulations/http/http_probe.sh`, a 20 kB POST |
| `journal/lab_portal.ndjson` | lab-portal JSON lines + startup diagnostic | HTTP-001 |
| `journal/accounts.ndjson` | useradd/userdel lines | `useradd --system extorq-sim-107bfaab09cf` / `userdel` |
| `journal/dispatch_denials.ndjson` | dispatcher denial lines | `cat /etc/shadow`, `journal - 99999`, a TTY request with the collector key |
| `journal/other.ndjson` | CRON / logind / dbus / timesyncd samples (not security events) | normal operation |
| `audit/vm002_create.log` | audit serials 4058-4130 (byte-exact) | VM-002 create: sudo, sh writing the unit, systemctl daemon-reload/enable |
| `audit/vm002_cleanup.log` | serials 4880-4905 | VM-002 cleanup (`rm` of the unit file) |
| `audit/useradd.log`, `audit/userdel.log` | identity watch hits | account create/delete above |
| `audit/augenrules_load.log` | `CONFIG_CHANGE` remove/add rule records | `augenrules --load` during `infra/vm/vm.sh redeploy` |
| `inventory/inventory_baseline.json` | full inventory (dispatcher 1.1.0) | after redeploy, before VM-002 |
| `inventory/inventory_vm002_created.json` | inventory with `extorq-sim-0e49c82d82bc.service` created and enabled | VM-002 |
| `inventory/inventory_user_added.json` | inventory with the throwaway system account | useradd |
| `inventory/inventory_vm002_removed.json` | inventory after VM-002 cleanup | VM-002 `--cleanup` |
| `dispatch/posture.json`, `dispatch/packages.json`, `dispatch/version.json` | complete documents | as captured |
| `dispatch/journal_response.ndjson` | a complete resumed `journal <cursor> 25` response with its trailer | as captured |
| `apache/documented_examples.txt` | **DOCUMENTED FORMAT EXAMPLES, not captured telemetry** (Apache is not deployed in the lab) | copied verbatim from https://httpd.apache.org/docs/2.4/logs.html |

Synthetic variations used by tests (always derived from a real record and labelled
`SYNTHETIC` in the test code): a forged sshd line (changed `_UID`/`_EXE`), a hostile user
name containing `from <ip> port <n>`, a user-session listener, a stripped-cgroup inventory
(older dispatcher output), a user added to `sudo`, a package upgrade/removal, a weakened
`PasswordAuthentication`, unavailable posture inputs, and the journald envelope around the
documented Apache lines.
