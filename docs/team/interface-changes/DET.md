# DET interface notes (detection and correlation, schema 2.0)

Audience: H (Linux + macOS telemetry), KG (Kubernetes + GitHub telemetry), the lead.
Status: proposals and field expectations for the detection-test matrix (PLAN 12). Rules
rely on catalog key fields; everything marked *optional* only adds context or lowers
false positives, and every rule still works (fails closed: it alerts) when it is absent.

## DET-IC-1: what each new rule reads (please keep these names)

| Rule | Event type (source) | Fields read | Optional (context / FP reduction) |
|---|---|---|---|
| VM-003 | `account.user.created` (`linux.inventory`) | `actor.name`, `attributes.uid`, `attributes.shell`, `attributes.groups`, `attributes.baseline` (never alerted) | `attributes.interactive_shell`, `attributes.home`; corroboration: `file.audit.watch` with `attributes.audit_key = extorq_identity` (written path `/etc/passwd`, `success`, `syscall`) |
| VM-004 | `persistence.cron.changed` (`linux.inventory`) | `resource.path`, `attributes.change` (`added`/`modified`/`removed`), `attributes.sha256`, `attributes.baseline` | `attributes.previous_sha256`, `file_mode`, `owner_uid`; corroboration: `file.audit.watch` `audit_key = extorq_cron` |
| MAC-002 | `persistence.launchd.item_created/modified` (`macos.launchd`) | `resource.path`, `attributes.label`, `attributes.program`, `attributes.program_arguments`, `attributes.scope`, `attributes.kind`, `attributes.sha256` | `run_at_load`, `keep_alive` |
| MAC-003 | `network.listener.opened` (`macos.inventory`) | `network.dst_ip`, `network.dst_port`, `network.protocol` (column `net_protocol`), `process.name`, `process.executable` | `attributes.bind_scope`, `attributes.pids`, `attributes.users` |
| MAC-004 | `auth.sudo.failure` (`macos.unified_log`) | `actor.name`, `attributes.reason` (sudo's text, e.g. `3 incorrect password attempts`) | `attributes.failed_attempts` (int parsed by the collector; the rule parses the reason text when absent), `attributes.tty`; corroboration: `auth.local.failure` with `attributes.auth_service = opendirectoryd` for the same account |
| MAC-005 | `software.installed` (`macos.inventory`) | `resource.path`, `resource.name`, `attributes.bundle_id`, `attributes.version`, `attributes.signed` (`true`/`false`; `null` when undetermined: never alerted), `attributes.signature_team_id` | `attributes.signer` / `attributes.obtained_from` (context only) |
| K8S-003 | `k8s.api.request` (`k8s.audit`) | `kubernetes.verb` (`get` for WebSocket, `create` for SPDY), `kubernetes.resource = pods`, `kubernetes.subresource` (`exec`/`attach`), `kubernetes.response_code` (101 or 2xx), `kubernetes.user`, `kubernetes.namespace`, `kubernetes.object_name`, `kubernetes.audit_id` | `attributes.impersonated_user`; proposal below: `attributes.exec_command`, `attributes.exec_container`, `attributes.exec_tty`, `attributes.exec_stdin` |
| K8S-004 | `k8s.api.request` (`k8s.audit`) | `kubernetes.resource = secrets`, `kubernetes.verb` (`list`/`watch`), `kubernetes.namespace` (NULL = cluster-wide), `kubernetes.response_code`, `kubernetes.user` | `attributes.impersonated_user` |
| K8S-005 | `k8s.api.request` (`k8s.audit`) | pod `create` (or `patch`/`update` of `pods/ephemeralcontainers`), 2xx, `attributes.risk_flags`, `attributes.request_summary`, `attributes.dry_run`, `kubernetes.user`, `kubernetes.namespace`, `kubernetes.object_name` | corroboration: `k8s.resource.created/updated` (`k8s.api_inventory`) of the same named pod with `attributes.risk_flags` |
| GH-002/3/4 | `github.workflow.modified` (`github.api`) | `attributes.untrusted_checkout_added`, `dangerous_triggers_added`, `triggers_after`, `unpinned_actions_added` (list, `null` = not analysed), `script_injection_added` (list, `null` = not analysed), `analysis`, `parse_error_before/after`, `effective_permissions_unknown` | already produced by the analyser 1.1.0 |
| GH-005 | `github.secret.exposed` (`github.api`) | `github.repository`, `github.commit_sha`, `resource.path`, `attributes.pattern`, `attributes.line`, `attributes.redacted_match` | `github.ref`, `github.actor_login` |

## DET-IC-2 (KG): `github.secret.exposed` semantics GH-005 relies on

* `attributes.pattern` = the name of the matching rule in `extorq.common.redaction`
  (`private_key`, `github_token`, `aws_access_key`, `aws_secret_key`, `slack_token`,
  `google_api_key`, `gitlab_token`, `extorq_token`, `jwt`, `url_credentials`, `bearer`,
  `authorization_basic`, `authorization_header`, `cli_secret_flag`,
  `cli_password_short_flag`, `sshpass`, `redis_cli_password`, `curl_user_password`,
  `env_secret_assignment`, `secret_assignment`). GH-005 rates provider-specific formats
  `high` and generic key/value assignments `medium` (see docs/detection-catalog.md).
* Only ADDED lines of a commit; a revert/removal must not emit the event.
* GitHub expressions are not secrets: please do not emit for values that are an Actions
  expression (`token: ${{ secrets.X }}`, `password: ${{ inputs.p }}`), otherwise every
  workflow that passes a secret correctly would raise GH-005.
* One event per (commit, path, line, pattern); `event_time` = commit time.

## DET-IC-3 (KG): exec details on `pods/exec` and `pods/attach` audit events (done by KG)

KG's normaliser now reads them from the request URI: `attributes.exec_command` (redacted,
bounded), `attributes.exec_tty`, `attributes.exec_stdin` and the target container in
`kubernetes.container_name` (column `k8s_container`). K8S-003 reports them as features
(`commands`, `containers`, `tty`); detection does not depend on them.

## DET-IC-6 (T): rule overlaps the detection-test runner should expect

* GH-001 v2.0.0 is permission escalation only (write-all or a sensitive write scope added).
  It does NOT fire for the GH-002 positive (a pull_request_target workflow with an unsafe
  checkout) unless that workflow's token gains a sensitive write scope, for example when the
  repository default token permission is write. GH-002 owns the trigger + checkout pattern.
* MAC-002 positives also raise MAC-001 (same plist); CORR-002 positives also raise HTTP-001,
  VM-001 and VM-002. Running linux.http-001, linux.vm-001 and linux.vm-002 in that order
  within 30 minutes raises CORR-002 genuinely (that is its definition).
* GH-005 raises one alert per file and commit (an access key id and its secret in one file
  are one alert listing both patterns).
* VM-001: failed connections from the same address within five minutes of the burst extend
  the same alert (sliding window), so a negative control run right after the positive
  would be attributed to the positive's alert; T's phase gap already covers this.

## DET-IC-7 (H): software.installed attributes MAC-005 uses

`attributes.signed` (`true`/`false`; the string `"unknown"` never alerts) and
`attributes.signature_type` (`adhoc` alerts as well, because an ad-hoc signature carries no
identity). Thanks for `failed_attempts` on sudo failures: MAC-004 uses it before parsing the
reason text.

## DET-IC-4 (H, proposal): cron changes written by the package manager

VM-004 alerts on every added or modified cron file (package upgrades included). If the
inventory can add `attributes.package` (owning dpkg package of the path, or null) and
`attributes.package_verified` (`dpkg --verify` agrees with the shipped checksum), the rule
shows them as context. They will never suppress an alert on their own (an attacker with
root can also run dpkg), so this is low priority.

## DET-IC-5 (lead): rule-run inputs after migration 0008

Rule SQL no longer reads `events.simulation_run_id`/`scenario_id` and no rule returns
`simulation_run_ids`; the detector writes alerts without it (needs A's
`extorq.storage.rows.alert_to_row` for schema 2.0). The rule harness applies 0006 and 0008
so the rule tests run on the post-0008 schema.
