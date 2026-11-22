# Agent B (session 3: B2 + B3) interface notes and proposals

Owner: agent B. Nothing here edits lead-owned or other agents' files; each item names who
would act (PLAN section 8). Earlier items: `B2.md` (B2-IC-*), `B3.md` (B3-IC-*).

## B-IC-1 VM-001 does not read macOS sshd events (owner: C2) - PROPOSED

Since B3-IC-1 the macOS collector emits `auth.ssh.{login_failed, invalid_user, preauth_closed,
max_auth_exceeded, login_succeeded}` from `macos.unified_log` with the same fields as Linux
(`actor.name`, `network.src_ip`, `network.src_port`, `attributes.auth_method`,
`attributes.invalid_user`, key type/fingerprint), bound to the Remote Login service
(`com.openssh.sshd`, adapter `macos-sshd`). `rules/linux/VM-001.sql` selects
`source_type = 'linux.journald'`, so an SSH brute force against the Mac would be stored but
not detected. Proposal: `source_type IN ('linux.journald', 'macos.unified_log')` (or a
MAC-002 twin rule). Remote Login is off on the reference host, so nothing is missed today.
Records from a process merely *named* sshd outside the sealed system volume are never
`auth.ssh.*` (they are `system.log.notable` with `attributes.source_verified = false`).

## B-IC-2 Git history still holds the original macOS captures (owner: lead) - DECISION NEEDED

The working tree's `tests/fixtures/macos/` is minimised (PLAN 11 / F-24: 6,753 -> 904 lines,
third-party entries synthetic; provenance in its README). Commits 1fad4b9, 4ee5baa and
0b88fe5 still contain the 41 original fixture files (installed applications, launchd
labels, processes of the personal Mac; 5 distinct third-party identifier prefixes by the
F-24 grep) and the session-2 text of `docs/team/status/B3.md`. No remote is configured.
If the history may ever be pushed, rewrite it first (e.g. `git filter-repo` on those paths)
or squash before publishing. Agent B did not touch git.

## B-IC-3 Host-specific label allowlist in the committed collector config (owner: lead) - FYI

`config/collectors/macos.yaml` `launchd.allowlist` names label patterns of software
installed on the reference host (Homebrew services, a container runtime, a browser
updater). It is deployment configuration, not test data, and MAC-001 uses
`attributes.allowlisted` to suppress alerts, so agent B did not change it the day before
the demo. Options: keep (patterns are generic vendor prefixes), or move host-specific
patterns to an uncommitted override file (would need SDK/config-loader support from A).

## B-IC-4 Unscheduled pod instances carry the cluster asset (A-IC-2 implemented; FYI A, D1, D2, C2)

Pod/container ServiceInstances of pods the scheduler has not bound yet now carry
`asset_id = "k8s:extorq-lab"` (cluster), `node_name = null`,
`attributes.asset_scope = "cluster"`, `attributes.scheduled = false`; once scheduled the same
`instance_id` is re-emitted on `k8s:extorq-lab/node/<node>`. Consumers grouping instances
by node asset should treat cluster-scoped instances as "not placed yet". Verified live: 0
quarantined k8s records (`docs/team/status/B2.md`).

## B-IC-5 `extorq_api_ro` quota exhaustion observed (owner: A / D1) - FYI

At 2026-11-21 20:31:xxZ a read-only query as `extorq_api_ro` failed with
`QUOTA_EXCEEDED: queries = 1435/1200` for the 60 s interval, caused by other clients of that
user (agent B had issued one query). Both the compose API (8000) and a dev API (8100) use
this identity; if the console or a poller shares it during the demo, API reads can fail for
up to a minute. Worth a check before the demo (separate identity for tooling, or a lower
poll rate).
