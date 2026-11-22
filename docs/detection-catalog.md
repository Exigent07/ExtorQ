# Detection catalog

Owner: C2. Source of truth: `rules/<domain>/<ID>.yaml` + `.sql` (this page summarises
them; the YAML carries the full false-positive and blind-spot lists). Engine semantics
(windows, identity, late events, health): `docs/detection-engine.md`. Correlation of
alerts with other telemetry: `docs/correlation.md`.

Confidence is a statement about **evidence completeness**, not about maliciousness. No
rule filters out simulation-tagged telemetry. Every rule is tested on an ephemeral
ClickHouse with positive and negative fixtures (`uv run pytest tests/rules -q`).

| Rule | Title | Severity | Status | Dedup | ATT&CK |
|---|---|---|---|---|---|
| VM-001 | Burst of failed SSH authentication from one source | medium | stable | window_bucket 300 s | T1110, T1110.001, T1110.003 |
| VM-002 | New or modified systemd unit (persistence) (v1.2.0) | high | stable | event | T1543.002 |
| K8S-001 | Privileged pod denied by Pod Security admission | medium | stable | event | T1610, T1611 |
| K8S-002 | Risky RBAC grant in Kubernetes (v1.1.0) | high | stable | event | T1098, T1078.004 |
| GH-001 | GitHub Actions workflow privilege escalation (v1.1.0) | high | stable | event | T1195.002, T1098 |
| HTTP-001 | Web probing from one source | low | experimental | window_bucket 300 s | T1595.003 |
| MAC-001 | New or modified macOS LaunchAgent/LaunchDaemon | medium | experimental | event | T1543.001, T1543.004 |
| APP-001 | Burst of failed web application logins | medium | experimental | window_bucket 300 s | T1110.001, T1110.003 |
| CORR-002 | Ordered HTTP probing, SSH failures and systemd persistence on one host (v1.2.0) | high | experimental | window_bucket 1800 s | T1595.003, T1110, T1543.002 |

Shared NAT/gateway addresses used by the rules (`params.shared_nat_ips`) and by
correlation: `10.0.2.2` (QEMU SLIRP gateway of the lab VM), `172.18.0.1` (Docker `kind`
network gateway), `10.244.0.1` (kind pod-network gateway for NodePort traffic),
`127.0.0.1`, `::1`. A source that is one of them is real but not attributable to one
origin.

Rule versions apply to new evaluations; stored alerts keep the evidence, summary and
features their version wrote (evidence is append-only, `docs/detection-engine.md` section
3). `uv run python -m extorq.detection.dryrun --rule <ID> --start <UTC> --end <UTC>` shows
what the current version produces over any stored window, read-only.

---

## VM-001 Burst of failed SSH authentication from one source

* **Purpose:** password/key guessing against sshd on a Linux host.
* **Telemetry:** `auth.ssh.login_failed`, `auth.ssh.invalid_user`, `auth.ssh.preauth_closed`,
  `auth.ssh.max_auth_exceeded` from `linux.journald` (sshd lines parsed by the Linux
  collector; `network.src_ip`, `network.src_port`, `actor.name`).
* **Logic:** sliding window per (asset, src_ip). An event is a crossing when the trailing
  300 s hold >= 5 distinct `(src_ip, src_port)` connections, or >= 10 `Failed <method>`
  attempts (several passwords per connection). One row per (asset, src_ip, 5-min bucket of
  the crossing); the engine merges rows of one continuous burst into one alert. Evidence:
  every failure line of that source from first crossing - 300 s to the last crossing.
* **Confidence:** high when >= 5 distinct connections from a non-NAT source; medium when
  the source is a shared NAT address or only the failed-attempt threshold was met.
* **False positives:** misconfigured automation with a wrong key; several users behind one
  NAT; scanners/health checks.
* **Blind spots:** low-and-slow or distributed guessing; successes (shown by correlation);
  journald rate limiting; attempts blocked before sshd.
* **Tests:** burst from an external address (high), burst crossing a bucket boundary (one
  alert), burst through 10.0.2.2 with simulation tag (medium), two connections x 6
  passwords (medium); negatives: below threshold, slow guessing, distributed sources,
  successful logins.
* **Verified live:** B1's VM-001 runs `bace7dc4a3d2` and `c7cbc976ecaf` (the latter
  ingested 26 minutes late, found by the catch-up) -> alerts confidence medium (10.0.2.2).

## VM-002 New or modified systemd unit (persistence)

* **Purpose:** systemd persistence (new service unit, changed unit, newly enabled unit).
* **Telemetry:** `persistence.systemd.unit_created|unit_modified|unit_enabled`
  (`linux.inventory` snapshot diff: `resource.path`, `resource.name`, `attributes.sha256`,
  `previous_sha256`, `exec_start`, `vendor_unit`, `wanted_by`); optional
  `file.audit.watch` with `attributes.audit_key = extorq_systemd` (`linux.auditd`).
* **Logic:** unit created/modified outside `params.allowlist_paths`, not part of a baseline
  snapshot (`attributes.baseline` true is ignored). Supporting evidence: enable events for
  the same unit name, and auditd watch hits that **create or modify** exactly the same path
  (v1.2.0): successful hits whose syscall is in `params.change_syscalls` (open/openat/creat/
  truncate, rename/link/symlink into the directory, chmod/chown family) and whose written
  path (the CREATE/NORMAL path item, or the CREATE item of a rename such as
  `mv /tmp/x.service /etc/systemd/system/`) is the unit path. It is an allowlist: deletions
  (`unlinkat` by a cleanup), failed attempts, xattr/timestamp changes and unknown or numeric
  syscall values corroborate nothing (v1.1.0 used a deletion denylist and therefore let
  `fsetxattr` or a failed `openat` raise confidence to high). A unit that is only enabled (no
  content change in the window) yields its own row.
* **Identity:** (asset, unit path, content sha256); enable-only rows (asset, unit,
  `enabled:<wanted_by>`).
* **Confidence:** high when the auditd watch corroborates the inventory diff on the exact
  path; medium otherwise (inventory only, or enable only).
* **False positives:** package installs/upgrades shipping units; configuration management.
* **Blind spots:** units created and removed between snapshots (auditd still records the
  write); other persistence mechanisms; path-based allow-listing.
* **Tests:** created + auditd openat + enabled with simulation tag (high); modified with only
  non-corroborating hits on the path (unlinkat by rm, failed openat, fsetxattr, numeric
  syscall: medium, `audit_corroborated` false); renamed into place (renameat CREATE item:
  high); enabled only (medium); negative: baseline snapshot, other audit keys, deleted unit,
  cron change. Same fixture under v1.1.0: high (overstated) -> v1.2.0: medium.
* **Verified live:** B1's VM-002 run `b7a712bc786d` -> alert confidence high (auditd
  openat + inventory unit_created on the same path).

## K8S-001 Privileged pod denied by Pod Security admission

* **Purpose:** someone tried to run a privileged / host-namespace workload where Pod
  Security forbids it (the control worked; who tried, where, with what).
* **Telemetry:** `k8s.api.request` (`k8s.audit`): verb `create` on `pods` (or
  `patch|update` on `pods/ephemeralcontainers`), response 403, with
  `attributes.pod_security_violation` (set by the normaliser only for 403 + "violates
  PodSecurity"), `attributes.risk_flags`, `attributes.dry_run`.
* **Logic:** a PSA violation whose risk flags include privileged, host_pid/network/ipc,
  host_path(_root) or dangerous_capabilities, or whose violation text names those
  controls. A 403 from another admission plugin never matches.
* **Identity:** one alert per audit id (PLAN 5.3); group (cluster, namespace, user).
* **Confidence:** high when the request summary's risk flags and the violation text agree;
  medium when only one is available (e.g. audit level Metadata).
* **False positives:** legitimate node agents deployed into a too-strict namespace;
  server-side dry runs (flagged `dry_run`); controller retries (one alert per audit id).
* **Blind spots:** privileged pods admitted in permissive/exempt namespaces; other PSA
  controls; audit pipeline outages.
* **Tests (records captured from the real kind cluster, normalised by B2's code):**
  privileged/hostPID pod (high), dry run, ephemeral debug container (high), simulation
  rename; negatives: mirror pod refused by another admission plugin, unrelated 401/403s.
* **Verified live:** B2's run `bcfcb726ff01` -> alert confidence high.

## K8S-002 Risky RBAC grant in Kubernetes

* **Purpose:** privilege escalation or backdoor access through RBAC.
* **Telemetry:** `k8s.api.request` (`k8s.audit`, successful create/update/patch of roles,
  clusterroles, rolebindings, clusterrolebindings, `attributes.risk_flags`,
  `request_summary`) and optional `k8s.resource.created|updated` (`k8s.api_inventory`,
  same risk vocabulary).
* **Logic:** risky flags only (`cluster_admin`, wildcards, escalate/bind/impersonate,
  secrets access, pods/exec, non-resource wildcards, bindings to anonymous /
  unauthenticated / authenticated / all or default service accounts). Excludes the role
  aggregation controller and the API server's bootstrap reconciliation, inventory baseline
  rows and `system:*` objects seen only in inventory, annotation-only writes (v1.1.0, see
  below) and the documented kubeadm bootstrap creates (v1.1.0, see below).
* **Annotation-only writes (B2-IC-7):** B2's normaliser marks a patch/update whose body
  touches only `metadata` (`attributes.metadata_only_change`,
  `metadata_fields_changed`). When every changed field is in
  `params.ignorable_metadata_fields` (`[annotations]`) the write is ignored: annotations do
  not change what a role or binding grants. Labels stay in scope on purpose: they drive
  ClusterRole aggregation (`aggregate-to-*`), so a label-only patch can grant privileges
  (tested). A write without the marker (older normaliser) is evaluated normally.
* **kubeadm bootstrap exception (decision, v1.1.0).** Every kubeadm cluster creates two
  risky bindings at birth: `kubeadm:cluster-admins` (Group `kubeadm:cluster-admins` ->
  `cluster-admin`) and `kube-public/kubeadm:bootstrap-signer-clusterinfo` (`system:anonymous`
  may read the public `cluster-info` ConfigMap for node bootstrap). A create is not alerted
  only when **all** of these hold:
  1. the verb is `create` and the requesting user is a bootstrap identity
     (`params.bootstrap_users`: `kubernetes-super-admin`, kubeadm >= 1.29's `super-admin.conf`,
     and `kubernetes-admin`, its `admin.conf`);
  2. the object signature `kind|namespace|name|roleRef|sorted subjects` equals one of
     `params.bootstrap_objects` exactly: the documented name **and** the documented grant;
  3. the request lies within `[birth - 60 s, birth + 600 s]` of the cluster's birth, which is
     the API server's own successful creation of the `kube-system` namespace (user
     `system:apiserver`, response 201). That record exists once per etcd lifetime and cannot
     be produced by a client credential. If ExtorQ did not observe the birth (attached to an
     existing cluster, audit gap), the exception never applies.
  An inventory (state) row of the same object is excepted only as the view of such an
  excepted create. Everything else alerts: later writes to these objects, a create by any
  other identity, a create outside the window, a different grant (an extra subject), and
  look-alike names. There is deliberately **no name-prefix allowlist**: anyone allowed to
  create bindings can name one `kubeadm:x`.
  *Why suppress instead of "keep alerting with low confidence and an
  `expected_platform_bootstrap` feature":* confidence in ExtorQ states evidence completeness
  (the contract's definition), and the evidence for these creates is complete; lowering it
  to encode "probably benign" would make `low` ambiguous for every consumer (analysts,
  Jev, the console). A high-severity alert on every cluster creation also trains analysts to
  ignore K8S-002. The exception is narrow enough that what it hides is exactly what kubeadm
  grants by design, every condition is deterministic and tested on both sides, and the two
  bindings stay visible elsewhere: the posture scan reports them (flagged accepted risk by
  `infra/kind/kind.sh`) and the audit events remain searchable.
  *Residual risk (blind spot):* an actor holding kubeadm's bootstrap credentials in the first
  ten minutes after birth who creates exactly the two documented objects.
* **Summary:** cluster-scoped objects read `<name> (cluster-scoped)` (feature `object_ref`,
  `scope`); v1.0.0 rendered `unknown/<name>`. `documented_bootstrap_object` is true when an
  alerting object carries a documented kubeadm name (the exception did not apply).
* **Identity:** (cluster, kind, namespace, name, sorted risk flags).
* **Confidence:** high when audit and inventory state agree; medium with one source.
* **False positives:** operators/Helm charts shipping cluster-admin bindings; temporary
  incident access; re-applying an unchanged risky object (no metadata-only marker for a full
  update). Cluster bootstrap and annotation-only writes: handled in v1.1.0 (see above and
  "Real false-positive observations").
* **Blind spots:** stolen tokens of existing privileged identities; excluded controllers.
* **Tests (captured records):** ClusterRoleBinding patched to system:authenticated
  (medium, summary `b2-fixture-crb (cluster-scoped)`), wildcard Role (alert), escalate
  ClusterRole audit + state (high); negatives: aggregation controller, forbidden create,
  delete, benign/baseline state. v1.1.0: the **genuine** birth records of the lab cluster
  (10 events exported from ClickHouse, `tests/rules/captures/`) -> no alert (v1.0.0: 2);
  B2's real `kubectl annotate` capture -> no alert (v1.0.0: 1); exception conditions not
  met (documented binding 15 minutes after birth, look-alike `kubeadm:cluster-admin`,
  documented RoleBinding by a workload service account) -> 3 alerts; documented name with
  an extra subject -> alert; live create without an observed birth -> alert; label-only
  patch -> alert; the inventory view of the excepted create -> excepted with it, the same
  inventory row without the audit create -> alert (state alone never proves the identity).
* **Verified live:** B2's run `c9c96ff29f33` (ServiceAccount bound to cluster-admin) ->
  alert confidence high (audit and inventory agree).

## GH-001 GitHub Actions workflow privilege escalation

* **Purpose:** CI/CD supply-chain risk: a commit gives a workflow more power.
* **Telemetry:** `github.workflow.modified` (`github.api`; C1's before/after analysis:
  `write_all_added`, `added_write_scopes`, `triggers_added`, `dangerous_triggers_added`,
  `untrusted_checkout_added`, `effective_permissions_unknown`, `parse_error_before/after`).
* **Logic:** fires when the change adds `permissions: write-all`, a sensitive write scope
  (contents, actions, packages, id-token, ...), a privileged trigger (pull_request_target,
  workflow_run, issue_comment) or a checkout of untrusted code under a privileged trigger.
* **Identity:** (repository, workflow path, commit sha).
* **Lexical fallback (v1.1.0):** C1's analyser 1.1.0 fails closed: when a workflow version
  exists but cannot be parsed as YAML (duplicate keys, invalid YAML, size or alias budget),
  both versions are compared with a bounded lexical scan (`attributes.analysis =
  lexical_fallback`, `effective_permissions_unknown = true`) that fills the same escalation
  attributes. GH-001 alerts on them with confidence **medium** (v1.0.0 rated them low because
  a parse error was present). `features.analysis_methods` and `lexical_scan_truncated` tell
  the analyst how the evidence was obtained.
* **Confidence:** medium for a lexical-fallback comparison; otherwise high when both
  versions parsed and effective permissions are known, medium when the repository default
  permissions are unknown, low when a version did not parse and no lexical comparison exists
  (analyser 1.0.0).
* **False positives:** release/deploy workflows that need write scopes; labelling bots on
  pull_request_target.
* **Blind spots:** org/repo default permission changes (separate event type), unpolled
  history, reusable workflows from other repositories.
* **Tests:** write-all (high), pull_request_target with simulation tag, id-token write with
  unknown default (medium), unparseable escalation compared lexically (medium, attributes
  computed by C1's analyser); negatives: benign edits, unparseable benign edit. C1's
  collector-output fixtures (real collector code path over a synthetic API fake) are
  declared cases: baseline, escalation and cleanup commits -> exactly one alert, high, for
  the escalation commit; the lexical-fallback variant -> exactly one, medium.
  `tests/rules/test_gh001_collector_contract.py` repeats both checks on C1's current files.
* **Verified live:** lab repository `Exigent07/extorq-lab` (private), run `8dwz3wf6zji4`:
  escalation commit `bf4026a` -> alert `e70639259d3044a6da955d9bc79e48cd`, high, 1 evidence
  event (`github.api`, producer `github-collector`); baseline and cleanup commits did not
  alert.

## HTTP-001 Web probing from one source

* **Purpose:** reconnaissance of a web server (wordlist scanning for config files, admin
  consoles, known-vulnerable paths).
* **Telemetry:** `http.request` from `linux.nginx` (required), `k8s.container_log`
  (optional), also `linux.apache`/`linux.app` when present: `network.src_ip`, `http.route`
  (no query string), `http.status_code`, `http.user_agent`.
* **Logic:** sliding 300 s window per (asset, src_ip) over 4xx responses: >= 10 requests
  and >= 5 distinct probe-like routes (`params.probe_route_pattern`: .env, .git,
  wp-login.php, phpmyadmin, server-status, actuator, admin consoles, ...).
* **Confidence:** high for a non-NAT source; medium through a shared NAT address.
* **False positives:** authorised scanners and uptime checks; broken clients requesting
  missing admin paths; NAT.
* **Blind spots:** slow/distributed probing; probes answered 2xx/3xx/5xx; payloads in query
  strings or bodies.
* **Tests:** external probe of 12 paths (high), the shape of B1's `http_probe.sh` through
  10.0.2.2 (medium); negatives: ordinary 404s, probe spread over 30 minutes.
* **Verified live:** B1's runs `8c8e999442ed` and `fff5113314b3` -> alerts confidence medium.

## MAC-001 New or modified macOS LaunchAgent/LaunchDaemon

* **Purpose:** launchd persistence on the macOS host.
* **Telemetry:** `persistence.launchd.item_created|item_modified` (`macos.launchd` snapshot
  diff of ~/Library/LaunchAgents, /Library/LaunchAgents, /Library/LaunchDaemons;
  attributes `label`, `program`, `run_at_load`, `keep_alive`, `sha256`, `scope`, `kind`,
  `allowlisted`, `parse_error`). The collector's first scan is a baseline without events.
* **Logic:** created/modified plists whose `attributes.allowlisted` is not true and whose
  label is not in `params.allowlist_labels`.
* **Identity:** (asset, plist path, content sha256).
* **Confidence:** high when the plist was read and parsed (program and digest known);
  medium otherwise.
* **False positives:** software installs/updaters, MDM agents (allow-list their labels after
  review; allow-listed items stay visible as events).
* **Blind spots:** plists created and removed between scans; other persistence (Background
  Task Management login items, cron, profiles); whether launchd loaded the job.
* **Tests:** shape of B3's `mac_001_launchagent.sh` (high, simulation tag); unparseable
  daemon rewrite (medium); negatives: allow-listed agent, deleted plist.
* **Verified live:** B3's MAC-001 run produced alert `MAC-001` with confidence high from
  the genuine `persistence.launchd.item_created` event (see docs/team/status/C2.md).

## APP-001 Burst of failed web application logins

* **Purpose:** credential guessing or spraying against an instrumented web application
  (structured authentication events, not HTTP status heuristics).
* **Telemetry:** `app.auth.login_failed` from `linux.app` (lab portal on the VM, B1 log
  contract) and `k8s.container_log` (the same app in kind; optional): `actor.name`,
  `network.src_ip`, `attributes.reason`, service/workload attribution.
* **Logic:** sliding 300 s window per application (attributed service, else Kubernetes
  workload, pod or the app's `service` field). Variant *guessing*: >= 5 failures for one
  user name; variant *spraying*: >= 5 failures from one source across >= 3 user names (the
  variants never double-count one burst).
* **Confidence:** high when all sources are non-NAT addresses; medium when a shared NAT
  address is involved or a source is unknown.
* **False positives:** forgotten passwords, stale saved credentials, tests/monitors with a
  rotated credential, many users behind one NAT.
* **Blind spots:** applications without structured auth events; slow guessing; spraying
  with fewer than 3 names per source.
* **Tests:** the shape of B1's `http_probe.sh` (5 failures for `lab-admin` via 10.0.2.2,
  medium); spraying 6 names from one external address in a Kubernetes app (high); negatives:
  4 failures, 6 failures over 30 minutes.
* **Verified live:** B1's HTTP-001 runs `8c8e999442ed` and `fff5113314b3` -> APP-001 alerts
  (guessing, medium).
* **Id note:** the requested `K8S-APP-001` id violates the contract's `RuleId` pattern (one
  hyphen); APP-001 covers Kubernetes workloads and Linux services alike.

## CORR-002 Ordered HTTP probing, SSH failures and systemd persistence on one host

* **Purpose:** a multi-stage pattern across three services of one Linux host (web server,
  sshd, systemd) in the order an intrusion would typically show it.
* **Telemetry:** `http.request` 4xx from `linux.nginx` (also Apache/app lines), sshd failures
  from `linux.journald`, `persistence.systemd.unit_created|modified|enabled` from
  `linux.inventory`, optional `file.audit.watch` (key `extorq_systemd`) from `linux.auditd`.
* **Logic:** stage markers: (1) probing = >= 10 4xx incl. >= 5 distinct probe-like routes
  from one source within 300 s (sliding); (2) SSH failures = >= 3 failed connections or
  >= 5 failed attempts from one source within 300 s; (3) **creation or modification
  evidence** of a unit (v1.2.0): a non-baseline, non-allowlisted inventory diff (unit
  created, modified or enabled) or a successful auditd create/modify syscall
  (`params.change_syscalls`, allowlist) whose written path is a unit file under
  `params.unit_dirs` matching `params.unit_file_pattern`. Deletions are context only
  (`context_unit_removals`, `context_removal_events`), never stage or alert evidence; failed,
  xattr/timestamp, editor swap files, unknown and numeric syscalls never count. ClickHouse
  `windowFunnel`
  over the markers (epoch milliseconds, window 1800 s) gates assets where the three stages
  occur in order; the concrete chains (stage 1 < stage 2 < stage 3 <= stage 1 + 30 min)
  are then materialised to collect evidence from all three stages.
* **Identity:** asset, 30-minute bucket of the first probe crossing.
* **Confidence:** medium when the probing and the SSH failures share a source IP that is
  not a shared NAT address; low otherwise. Never high: the rule shows **ordered
  co-occurrence, not causation**, and `features.causation_established` is always false.
* **Features:** stage times, probe counts/routes, SSH connections/usernames, units,
  `persistence_units_inventory_confirmed` (the inventory saw new or changed content) vs
  `persistence_units_audit_only` (a write auditd saw, e.g. an unchanged unit re-installed),
  `persistence_writers`, `context_unit_removals`, `same_source_ip`,
  `same_non_nat_source_ip`, `source_ip_shared_nat`.
* **False positives:** unrelated activity that lines up within 30 minutes; pentests followed
  by maintenance; the lab's QEMU NAT (all Mac traffic arrives from 10.0.2.2).
* **Blind spots:** slower sequences, sub-threshold stages, other persistence mechanisms,
  stages older than the 45-minute lookback.
* **Tests:** same external source (medium), through 10.0.2.2 with simulation tag (low),
  different sources (low), auditd-only creation with a removal of another unit in the window
  (alert; the removal appears only in `context_unit_removals`, `persistence_events` = 1);
  negatives: wrong order, more than 30 minutes, baseline-only persistence, below the probe
  threshold, deletion-only persistence (an `unlinkat` by rm), non-changing audit hits (failed
  openat, fsetxattr on `?`, editor swap file, numeric syscall, unit moved out of the
  directory; v1.1.0 alerted on this fixture, v1.2.0 does not).
* **Verified live:** B1's HTTP-001, VM-001 and VM-002 runs on 2026-11-21 -> one alert
  (`b46da3805d1c6f17b6c1ed363b49a777`), confidence low (every stage arrived from 10.0.2.2;
  the SSH stage also contained the lab operator's own failed key attempts, which illustrates
  why a shared NAT source is never identity). That alert was created by v1.0.0 and keeps a
  deletion in its evidence (see below).

## Real false-positive observations (live lab, 2026-11-21) and how they are handled

Found by the lead and C2 on genuine telemetry; each fix is tested on fixtures derived from
the real records and checked against the stored data with the read-only dry run.

| # | Rule | Observation (genuine data) | Handling | Stored alerts |
|---|---|---|---|---|
| 1 | CORR-002 | v1.0.0 took the VM-002 simulation's cleanup, an auditd `unlinkat` of `extorq-sim-0e49c82d82bc.service` by `/usr/bin/rm` (14:42:35Z), as the "unexpected systemd persistence change" | v1.1.0 excluded deletions with a denylist, which still let other non-changing hits count (live: `fsetxattr` with path `?` by `install`); v1.2.0 requires creation/modification evidence (allowlist of successful create/modify syscalls on a unit file, or an inventory diff); removals are context features | alert `b46da380...` (created 15:05Z by v1.0.0) keeps that event and `/usr/bin/rm` in `persistence_writers` (evidence is append-only); the dry run shows v1.2.0 still finds the chain through the unit creation at 15:07:11Z and no longer produces the deletion or the `fsetxattr` |
| 2 | CORR-002 | B1's `vm.sh redeploy` re-installs `lab-portal.service` with `install` (unlinkat, openat CREATE, fsetxattr, fchownat, fchmodat; content unchanged, so no inventory diff), which fell inside the chain window | Counted on purpose (a genuine write to a unit file), but shown as `persistence_units_audit_only` with writer `/usr/bin/install`, separate from `persistence_units_inventory_confirmed`; the removal half is context | unchanged; visible in the dry run (`persistence_units_audit_only=lab-portal.service`) |
| 3 | VM-002 | Same denylist weakness for corroboration: a failed `openat`, an `fsetxattr` or a numeric syscall on the unit path would have raised confidence to high | v1.2.0 uses the same allowlist; the investigation context's `auditd_corroborated` uses the same definition (`extorq.detection.linux_audit`) and reports `auditd_removals` separately | the live VM-002 alert (`5ac7d8f5...`, high) is corroborated by a genuine `openat CREATE`, unaffected |
| 4 | K8S-002 | kubeadm's bootstrap bindings `kubeadm:cluster-admins` (by `kubernetes-super-admin`, 10:16:01.080Z) and `kube-public/kubeadm:bootstrap-signer-clusterinfo` (by `kubernetes-admin`, 10:16:03.118Z) alerted at cluster creation | v1.1.0 documented bootstrap exception (identity + exact object signature + cluster-birth window; no prefix allowlist); genuine birth records: v1.0.0 2 alerts -> v1.1.0 0 | alerts `38d0d427...` and `05678dbf...` (v1.0.0) remain; recommend closing them as benign with a note in the console |
| 5 | K8S-002 | `infra/kind/kind.sh` marked those two bindings as accepted risks with `kubectl annotate` (14:55Z); each PATCH alerted again (the response object is still risky) | v1.1.0 ignores writes whose changed fields are only annotations (B2-IC-7; labels stay in scope); B2's real capture of that patch: v1.0.0 1 alert -> v1.1.0 0 | the stored 14:55 events predate B2's marker, so a re-evaluation of that window still matches them (dry run); new annotate patches carry the marker (the running gateway has B2's current normaliser) |
| 6 | K8S-002 | Summaries of cluster-scoped objects read `unknown/<name>` | `object_ref` renders `<name> (cluster-scoped)` | stored summaries keep the text their version rendered (e.g. the K8S-002 scenario alert `afc76864...`) |
| 7 | GH-001 | C1's fail-closed analyser marks unparseable workflows `lexical_fallback`; v1.0.0 would rate such an escalation low because a parse error is present | v1.1.0: medium, `analysis_methods` feature | no live lexical-fallback event yet |

Detections of B2's own captured test objects (`b2-fixture-*`, created at 10:18Z to record
audit fixtures) are genuine risky RBAC objects and stay alerted.

## Planned (not implemented)

* **CORR-001** (SSH failures and HTTP probing from the same source within 15 minutes) is
  planned; CORR-002 covers the ordered three-stage case and HTTP-001 + VM-001 cover the
  stages individually.
