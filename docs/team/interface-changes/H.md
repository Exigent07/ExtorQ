# H interface changes and notes (Linux + macOS telemetry, schema 2.0 stage)

No contract, catalog, migration or dependency change is requested. Everything below is
emitted within the existing schema 2.0 catalog; it records attribute semantics that rule,
test and UI owners consume, and actions other owners need to take.

## H-IC-1 (rules owner): attribute semantics of the matrix inputs

| Rule | Event / source | Attributes and semantics |
|---|---|---|
| VM-003 | `account.user.created/deleted` (`linux.inventory`) | `actor.name`, `uid`, `gid`, `shell`, `groups`, `home`, `interactive_shell`. **systemd DynamicUser identities are never account events** (uid 61184-65519 AND named by a `DynamicUser=yes` unit; e.g. the web app `lab-portal`, uid 64881, which nss-systemd lists only while the service runs). Inventory items keep them with `dynamic_user=true`. A plain `useradd` in that uid range is still an event. Supporting evidence: `file.audit.watch` with `audit_key=extorq_identity` (writer `useradd`, paths `/etc/passwd`, `/etc/shadow`, often via rename). |
| VM-004 | `persistence.cron.changed` (`linux.inventory`) | `resource.path`, `attributes.change` = `added` / `modified` / `removed`, `sha256` (current content; **absent on `removed`**), `previous_sha256` (on `modified` and `removed`), `file_mode`, `owner_uid`. Alert on `added`/`modified`. Supporting: `file.audit.watch` `audit_key=extorq_cron` (only `/etc/cron.d` is audited). Contents are never collected. |
| VM-002 | `persistence.systemd.unit_deleted` | now carries `previous_sha256` and no `sha256` (was: the deleted file's hash in `sha256`). `unit_created`/`modified`/`enabled` unchanged. |
| VM-001 | `system.log.notable` `action=ssh.user_not_allowed` | `User root from <ip> not allowed because not listed in AllowUsers` (existing accounts refused by `AllowUsers`): now `network.src_ip` (was `attributes.src_ip`), `attributes.invalid_user=true`, `reason`. The burst itself is still `auth.ssh.invalid_user` / `preauth_closed` (`invalid_user=true`) / `max_auth_exceeded` with one `src_port` per connection. |
| (sudo, both OSes) | `auth.sudo.failure` | `failure_kind` = `authentication` (outcome `failure`; wrong password, "a password is required") or `policy` (outcome `denied`; "user NOT in sudoers", "command not allowed", ...). `failed_attempts` = N from `N incorrect password attempt(s)`; sudo writes ONE record per invocation with the total, so a burst rule should **sum** `failed_attempts`, not count events. `env_specified=true` when `ENV=` was given (values never kept). Linux sudo previously used outcome `denied` for every failure. |
| MAC-002 | `persistence.launchd.item_created/modified` (`macos.launchd`) | `program`, `program_arguments` (first 16, redacted), `program_arguments_count`, `program_exists`, `program_user_writable` (the program file or its folder is writable by the logged-in user; absent when unknown, e.g. relative paths), `run_at_load` (absent when the plist has no key), `scope`, `allowlisted`, `label`, `sha256`. Interpreter detection (sh/bash/zsh/python/osascript/...) and user-writable argument paths (`/tmp`, `/private/tmp`, `/Users/...`) are left to the rule. |
| MAC-003 | `network.listener.opened/closed` (`macos.inventory`) | now from a dedicated 60 s `listeners` source. `bind_address`, `exposure` in the contract's ServiceEndpoint vocabulary: **`any`** (all interfaces), `loopback`, `private`, `unknown` (not "all_interfaces"); `processes`, `pids`, `users`, `executables`, `process_attribution` (`lsof` under the uv runtime, which sees the current user's processes only), `listener_method`; `process.{name,pid}` when one owner. The same `bind_address`/`exposure` are now on Linux listener events. macOS listener items/events no longer carry `address`/`bind_scope` (renamed to `bind_address`/`exposure`). |
| MAC-004 | `auth.sudo.failure` (`macos.unified_log`) | as above; only records whose image path is `/usr/bin/sudo` are evidence (others: `system.log.notable`, `source_verified=false`). **Unverified on real records**: the reference Mac's whole log archive (2026-10-23..2026-11-22) has no sudo record; formats are sudoers(5) of the installed sudo 1.9.17p2. |
| MAC-005 | `software.installed/removed` (`macos.inventory`, new `software` source, 60 s) | `resource.path`, `resource.name`, `bundle_id`, `version`, `build_version`, `scope` (`system` = /Applications, `user` = ~/Applications), `signed` = `true` / `false` / `"unknown"` (string), `signature_valid` (absent for unsigned), `signature_type` (`unsigned`, `adhoc`, `apple_platform`, `app_store`, `developer_id`, `apple_development`, `other`), `signature_team_id` (absent for Apple platform and ad-hoc code), `signature_authority`, `signature_authorities`, `notarization_ticket`, `signature_error`, `replaced`/`previous_bundle_id`. Suggested MAC-005 condition: `signed = false OR signature_type = 'adhoc' OR signature_valid = false`; the Apple-app copy (negative control) yields `signed=true`, `signature_valid=true`, `signature_type=apple_platform`. |

## H-IC-2 (detection-test owner): timing and artefact notes

* macOS launchd, listeners and application folders are scanned every 60 s; unified log
  every 60 s (5 s settle). Keep a MAC-003 listener open for at least ~70 s so one
  listener scan sees it (both the positive and the loopback control).
* MAC-005: build the bundle outside `/Applications` and move it in with one rename. A new
  bundle is reported only after its entries were quiet for 30 s (inode change time), so
  expect `software.installed` 30-120 s after the move. Cleanup produces `software.removed`.
* MAC-004: three wrong passwords in ONE `sudo -S -v` invocation give one record with
  `failed_attempts=3`; three invocations with one wrong password each give three records
  with `failed_attempts=1`. `sudo -k` itself logs nothing.
* Linux: the VM-003 account must not be created with `DynamicUser` semantics (a plain
  `useradd` is fine at any uid); VM-004 must write `/etc/cron.d` (the only audited cron
  path).

## H-IC-3 (UI owner): renamed service and listener attributes

* Linux Service records: `attributes.adapter_deployed_in_lab` (bool) is replaced by
  `attributes.adapter_validation` = `live_telemetry` | `documented_formats` (no "lab"
  wording; only apache is `documented_formats`).
* Listener inventory items/events (macOS): `address` -> `bind_address`, `bind_scope` ->
  `exposure` (contract vocabulary). macOS posture `exposed_listener` findings: attribute
  `bind_scope` -> `exposure`.
* The Linux asset's `display_name` is `<PRETTY_NAME> (<hostname>)`, e.g.
  `Ubuntu 24.04.5 LTS (lab-vm-01)`: the hostname is the real one and stays. Asset
  `environment` is still the contract default (`lab`); hide it in the UI (PLAN 12.3).

## H-IC-4 (VERIFY stage / lead): actions before the clean-slate run

1. Restart the collector runner so it runs the schema 2.0 code (the background runner
   started at 12:33 local still runs pre-2.0 modules in memory).
2. Optional, and only BEFORE `make reset-data`: `infra/vm/vm.sh redeploy` to deploy the
   web app's new unit `Description=ExtorQ demo web application (behind nginx)` (the
   running VM still shows "ExtorQ lab portal ..." as `unit_description`). A redeploy
   restarts sshd/lab-portal, reloads nginx and audit rules and rewrites the unit file: done
   after the reset it would be genuine VM-002 input (unit modified). Nothing else in
   `infra/vm/` changed.

## H-IC-5 (P, optional): baseline policy

`extorq_collectors.sdk.baseline.POLICIES["extorq_collectors.macos"]` could add the KV
prefix `macos.software.` (per-bundle deferral counters). Not required: after a reset the
`software.bundles` snapshot is gone, the next scan is a baseline and the counters are
rewritten on the first scan.

## H-IC-6 (F / P): failing checks outside H paths seen while testing

* `tests/security/test_security_ingest_redaction.py` still builds a `simulation_run`
  canary record (kind removed in 2.0): 2 failures.
* `tests/security/test_security_python_static.py::test_no_sql_built_from_dynamic_strings`
  flags `backend/src/extorq/pipeline/spool.py:486` and `:501` (`.execute()` with dynamic SQL).
* `tests/security/test_security_api_authz.py::test_viewer_cannot_mutate` still posts to the
  removed `/alerts/{id}/summary` endpoint (404 instead of 403).
