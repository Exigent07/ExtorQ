# Detection catalogue

Owner: DET (detection and correlation). Rules: `rules/<domain>/<RULE-ID>.{yaml,sql}`.
Engine: [detection-engine.md](detection-engine.md). Correlation:
[correlation.md](correlation.md). Detection tests: `detection_tests/` (matrix in
[docs/team/PLAN.md](team/PLAN.md) section 12).

ExtorQ ships 24 versioned SQL rules over four asset classes. Every rule has fixture tests
that mirror its matrix test (a real activity on the monitored asset) and that test's
negative control, documented false positives with their handling, blind spots, a
deterministic confidence rule and ATT&CK technique ids. Detection tests perform real
activity; rules never special-case them (contract schema 2.0 removed the simulation
category: there are no test markers in telemetry).

## How to read an entry

* **Severity** is the impact if the alert is a true positive. It is fixed per rule.
* **Confidence** says how complete the evidence is, never how malicious the activity is:
  `high` when independent sources agree or the authoritative source recorded everything
  the rule needs; `medium` when one source or one attribute is missing (for example the
  origin is a shared NAT address, or a corroborating source is absent); `low` only for
  correlations whose stages share no identity. Confidence can grow as late evidence
  arrives within one rule version. A version change reassesses confidence for a matching
  alert using the new evidence criteria.
* **False-positive handling** uses, in this order: thresholds and windows; context in the
  alert features and the investigation context; and, where unavoidable, allowlists keyed
  on attributes an attacker cannot choose: exact identities issued by a trusted authority
  (Kubernetes user and service account names), executable paths in SIP-protected system
  locations, content digests, and paths in root-only directories. Never names an attacker
  controls (launchd labels, bundle identifiers, user-chosen account or file names,
  process names, action owners).
* **Shared NAT/gateway addresses** (`10.0.2.2` QEMU gateway: every connection from the Mac
  to the VM; `172.18.0.1` kind Docker gateway; `10.244.0.1` kind pod gateway; loopback)
  never identify an origin. Rules that key on a source address lower confidence for them.
* **Matrix test** ids are those of `uv run python -m detection_tests run --asset <asset>`
  (`make test-detections`). Fixture cases named `matrix-*` mirror the positive,
  `matrix-control-*` the negative control (`tests/rules/test_rules_fixtures.py` enforces
  both for every rule).

## Summary

| Asset | Rule | Title | Severity | ATT&CK | Evidence | Matrix test |
|---|---|---|---|---|---|---|
| Linux | VM-001 | Burst of failed SSH authentication from one source | medium | T1110, .001, .003 | sshd (journald) | `linux.vm-001` |
| Linux | VM-002 | New or modified systemd unit (persistence) | high | T1543.002 | inventory diff + auditd | `linux.vm-002` |
| Linux | VM-003 | Local account created | medium | T1136.001 | inventory diff + auditd | `linux.vm-003` |
| Linux | VM-004 | Cron persistence | high | T1053.003 | inventory diff + auditd | `linux.vm-004` |
| Linux, Kubernetes | HTTP-001 | Web probing from one source | low | T1595.003 | nginx / app access logs | `linux.http-001` |
| Linux, Kubernetes | APP-001 | Burst of failed web application logins | medium | T1110.001, T1110.003 | web app auth events | `linux.app-001`, `kubernetes.app-001` |
| Linux | CORR-002 | Ordered HTTP probing, SSH failures and systemd persistence | high | T1595.003, T1110, T1543.002 | nginx + sshd + inventory/auditd | `linux.corr-002` |
| Kubernetes | K8S-001 | Privileged pod denied by Pod Security admission | medium | T1610, T1611 | API audit log | `kubernetes.k8s-001` |
| Kubernetes | K8S-002 | Risky RBAC grant | high | T1098, T1078.004 | API audit log + inventory | `kubernetes.k8s-002` |
| Kubernetes | K8S-003 | Interactive exec into a pod by a human identity | medium | T1609 | API audit log | `kubernetes.k8s-003` |
| Kubernetes | K8S-004 | Secret enumeration by a non-system identity | high | T1552.007, T1613 | API audit log | `kubernetes.k8s-004` |
| Kubernetes | K8S-005 | Privileged or host-access pod admitted | high | T1610, T1611 | API audit log + inventory | `kubernetes.k8s-005` |
| GitHub | GH-001 | Workflow permission escalation | high | T1098, T1195.002 | workflow analysis | `github.gh-001` |
| GitHub | GH-002 | Privileged trigger checks out untrusted code | high | T1195.002, T1059 | workflow analysis | `github.gh-002` |
| GitHub | GH-003 | Unpinned third-party action added | medium | T1195.001 | workflow analysis | `github.gh-003` |
| GitHub | GH-004 | Script injection through an untrusted context | high | T1059.004, T1195.002 | workflow analysis | `github.gh-004` |
| GitHub | GH-005 | Credential committed to a repository | high | T1552.001 | commit scan (redacted) | `github.gh-005` |
| macOS | MAC-001 | New or modified launch item | medium | T1543.001, T1543.004 | launchd diff | `macos.mac-001` |
| macOS | MAC-002 | Launch item runs a shell, interpreter or temporary-path program | high | T1543.001, T1543.004, T1059.004 | launchd diff | `macos.mac-002` |
| macOS | MAC-003 | TCP listener on all interfaces by a non-allowlisted process | medium | T1571, T1205 | listener diff (lsof) | `macos.mac-003` |
| macOS | MAC-004 | Burst of sudo authentication failures | medium | T1110.001, T1548.003 | unified log (sudo, opendirectoryd) | `macos.mac-004` |
| macOS | MAC-005 | Unsigned or ad-hoc signed application installed | medium | T1204.002, T1553.001 | application diff + codesign | `macos.mac-005` |

Rules per asset class: Linux 7, Kubernetes 6 (HTTP-001 also covers the cluster web
application's access log), GitHub 5, macOS 5.

---

## Linux host (`linux:lab-vm-01`)

Telemetry: the agentless SSH collector (journald, auditd, inventory snapshot diffs every
60 s, nginx and web-application logs); see [telemetry/linux.md](telemetry/linux.md).
Inventory diffs carry the host's own snapshot time, the same clock as auditd, which is
what the corroboration windows rely on.

### VM-001 Burst of failed SSH authentication from one source (v1.1.0)

* **Purpose:** password guessing and key spraying against sshd.
* **Telemetry:** `auth.ssh.login_failed`, `auth.ssh.invalid_user`, `auth.ssh.preauth_closed`
  (a client offered a rejected key and disconnected), `auth.ssh.max_auth_exceeded`
  (`linux.journald`): `network.src_ip`, `network.src_port`, `actor.name`.
* **Logic:** sliding 5-minute window per (asset, source address): at least 5 distinct
  failed connections `(src_ip, src_port)`, or at least 10 `Failed <method>` attempts (several
  passwords per connection). One row per crossing bucket; a burst crossing a bucket boundary
  stays one alert; failures from the same address within the window extend it.
* **Confidence:** high when the connection threshold is met from an attributable address;
  medium for a shared NAT address (every test from the Mac arrives from 10.0.2.2) or when only
  the attempt threshold is met.
* **False positives and handling:** a misconfigured client or deploy key retrying (the
  threshold is above typo retries; successful logins never count); users behind one NAT
  (shared addresses are configured and lower confidence); scanners and health checks (no
  source allowlist: addresses are not identities; the usernames and counts are in the alert).
* **Blind spots:** slower guessing, many sources with few attempts each, attempts refused
  before sshd, lines journald dropped. Success after failures is shown by the investigation
  context (`ssh_success_after_failures`), not by this rule.
* **Matrix test `linux.vm-001`:** about ten connections from the Mac with commonly guessed
  users and throwaway keys (alert, medium) / three successful key logins of `extorq-admin`
  (no alert). Fixtures: `matrix-key-rejected-burst-via-qemu-nat`,
  `matrix-control-successful-key-logins`, plus a captured burst from the VM parsed by the
  collector's journal parser (`captured-vm-burst-and-throwaway-key`), an external source
  (high), a bucket-boundary burst, many passwords on two connections, below threshold, slow
  guessing and distributed sources.

### VM-002 New or modified systemd unit (v1.4.0)

* **Purpose:** systemd persistence (a unit that runs at boot or on a timer).
* **Telemetry:** `persistence.systemd.unit_created`, `unit_modified`, `unit_enabled`
  (`linux.inventory`: path, sha256, ExecStart, vendor flag, WantedBy) and, optionally,
  `file.audit.watch` with key `extorq_systemd` (`linux.auditd`: syscall, success, path items,
  executable).
* **Logic:** every unit file created or modified outside `allowlist_paths`, and units newly
  enabled (own row when the file did not change). auditd corroborates only successful
  create/modify syscalls from an allowlist (open/openat/creat/truncate, rename/link/symlink/
  mknod into the directory, chmod/chown family) whose written path is exactly the unit file
  (the CREATE item of a rename counts). Deletions, failed attempts, xattr changes and unknown
  or numeric syscalls corroborate nothing (fail closed). Unit state changes (start, stop,
  restart) are never evaluated. Identity: asset, unit path, content digest.
* **Confidence:** high for a qualifying audit write on the same asset and path within
  two minutes before the inventory observation. Inventory-only and enable-only rows
  are medium.
* **False positives and handling:** package installs and upgrades (vendor units flagged,
  package changes in the context; no package-name allowlist because a unit can be named after
  any package); configuration management (exact root-only paths in `allowlist_paths`;
  `config.file.changed` keeps monitoring them); redeploys of unchanged content (no diff, or
  the same digest extends the existing alert).
* **Blind spots:** units created and removed between snapshots, other persistence
  mechanisms (VM-004 covers cron), audit logs without enriched syscall names.
* **Matrix test `linux.vm-002`:** a unit written with sudo, daemon-reload, enable, never
  started (alert, high) / restart of an existing unit (no alert). Fixtures:
  `matrix-unit-created-enabled-captured` (the real VM inventory diff and auditd records,
  parsed by the collector's own code), `matrix-control-restart-existing-unit`, inventory-only
  modification with non-corroborating auditd hits (medium), rename into place (high),
  enable-only (medium), the captured cleanup plus unrelated events (no alert).

### VM-003 Local account created (v1.0.0)

* **Purpose:** backdoor accounts (T1136.001).
* **Telemetry:** `account.user.created` (`linux.inventory`: `actor.name`, uid, gid, shell,
  home, groups) and, optionally, `file.audit.watch` with key `extorq_identity` (writes of
  `/etc/passwd` and `/etc/shadow`).
* **Logic:** every account that was not in the previous snapshot. Corroboration: a successful
  create/modify syscall (same allowlist as VM-002) whose written path is `/etc/passwd` or
  `/etc/shadow`, within 10 minutes BEFORE the snapshot that first saw the account (the
  dispatcher reads `/etc/passwd` before stamping the snapshot, so later writes, such as a
  `userdel` cleanup, never corroborate). One alert per creation event.
* **Reported context:** uid, `uid_zero` (a second root), `system_uid_range` (1..999),
  `login_shell`, `privileged_groups` (root, sudo, adm, wheel, docker, lxd, ...), writer
  executables (`useradd`, `adduser`).
* **Confidence:** high when inventory and auditd agree; medium for the inventory alone.
* **False positives and handling:** service accounts created by package installs (system
  uid, no login shell: reported, not suppressed, because an attacker can choose both; the
  context lists the package changes); provisioning by automation (recognisable by the writer
  and change records; no account-name allowlist).
* **Blind spots:** accounts created and deleted within one snapshot interval (the auditd write
  remains visible in the context), changes to existing accounts (uid set to 0, group changes:
  `config.file.changed` on `/etc/group`), directory-service accounts.
* **Matrix test `linux.vm-003`:** `sudo useradd --no-create-home --shell /usr/sbin/nologin
  extorq-test-<id>` (alert) / an ordinary file in `/tmp` (no account event, no alert).
  Fixtures: `matrix-useradd-captured-with-auditd` (captured useradd: inventory diff and
  identity-file hits, high), a uid-0 login account (medium, `uid_zero`), an identity write an
  hour earlier that must not corroborate (medium), `matrix-control-temp-file`, the captured
  userdel cleanup plus a baseline row (no alert).

### VM-004 Cron persistence (v1.0.0)

* **Purpose:** cron persistence (T1053.003): `/etc/crontab`, `/etc/anacrontab`,
  `/etc/cron.d`, the hourly/daily/weekly/monthly directories, user crontabs.
* **Telemetry:** `persistence.cron.changed` (`linux.inventory`: path, change
  `added`/`modified`/`removed`, sha256, mode, owner) and, optionally, `file.audit.watch` with
  key `extorq_cron` (watch on `/etc/cron.d`).
* **Logic:** every cron file added or modified outside `allowlist_paths` (removals are never
  persistence). Corroboration: a successful create/modify syscall on exactly that path within
  10 minutes before and 5 seconds after the snapshot time (the dispatcher reads the cron files
  just after stamping the snapshot). Identity: asset, path, content digest.
* **Reported context:** `cron_location`, `world_writable` (from the mode), writer executables
  and syscalls, `package_manager_writer` (dpkg/apt wrote the file).
* **Confidence:** high when inventory and auditd agree; medium for the inventory alone, which
  is always the case for locations without an audit watch.
* **False positives and handling:** packages shipping cron files (reported with
  `package_manager_writer`; not suppressed because root can install a malicious package);
  administrators and configuration management (exact root-only paths in `allowlist_paths`).
* **Blind spots:** the cron entry itself is not collected (contents are never collected,
  only digests), entries added and removed within one snapshot, systemd timers (VM-002), `at`
  jobs, shell profiles.
* **Matrix test `linux.vm-004`:** `sudo tee /etc/cron.d/extorq-test-<id>` with a harmless
  `/bin/true` job (alert) / `crontab -l` and a listing of `/etc/cron.d` (no alert). Fixtures:
  `matrix-cron-d-file-written-with-tee` (high), `/etc/crontab` modified (medium), a file
  written by dpkg (high, `package_manager_writer`), `matrix-control-crontab-listing`, removal
  and baseline (no alert).

### HTTP-001 Web probing from one source (v1.1.0)

* **Purpose:** active scanning of web applications (T1595.003).
* **Telemetry:** `http.request` from `linux.nginx` (also `linux.apache`, `linux.app`,
  `k8s.container_log`): source address, route without query string, status.
* **Logic:** sliding 5-minute window per (asset, source): at least 10 client errors (4xx)
  AND at least 5 distinct probe-like routes (`.env`, `.git`, `wp-`, `phpmyadmin`,
  `server-status`, admin consoles, path traversal, ...). Successful and 5xx responses never
  count.
* **Confidence:** high for an attributable source; medium for a shared NAT address.
* **False positives and handling:** authorised scanners and uptime checks (no address
  allowlist; routes, statuses and user agents in the alert; severity low); broken links
  (both thresholds must hold; ordinary 404s never match the probe pattern); NAT (medium).
* **Blind spots:** slow or distributed probing, probes answered 2xx/3xx/5xx, payloads in
  query strings or bodies, uncollected web servers.
* **Matrix test `linux.http-001`:** about 14 probe paths from the Mac, at least 12 answered
  4xx (alert, medium, src 10.0.2.2) / 20 ordinary requests answered 200 (no alert).
  Fixtures: `matrix-probe-paths-via-qemu-nat`, `matrix-control-normal-requests`, an external
  probe (high), ordinary 404s, slow probing.

### APP-001 Burst of failed web application logins (v1.1.0)

* **Purpose:** password guessing and spraying against the web application (T1110.001,
  T1110.003), on the VM and in the cluster.
* **Telemetry:** `app.auth.login_failed` from the application's structured log (`linux.app`
  on the VM, `k8s.container_log` in the cluster): user name, source address, reason.
* **Logic:** two variants per application, each a sliding 5-minute window: guessing (at least
  5 failures for one user name) and spraying (at least 5 failures from one source across at
  least 3 user names). Successful logins never count.
* **Confidence:** high when every source address is known and none is a shared NAT address;
  medium otherwise (the VM application sees 10.0.2.2, the cluster application 10.244.0.1).
* **False positives and handling:** forgotten passwords and stale saved credentials (5 in 5
  minutes is above retrying; one failure then success never alerts); automation with a rotated
  credential (no user or address allowlist; user names and reasons in the alert); NAT (medium).
* **Blind spots:** applications without structured auth events, slow guessing, spraying with
  fewer than 3 names per source.
* **Matrix tests `linux.app-001` and `kubernetes.app-001`:** six failed logins for the demo
  account `lab-admin` (alert, medium) / one failure then a success (no alert). Fixtures:
  `matrix-vm-app-failed-logins`, `matrix-cluster-app-failed-logins`,
  `matrix-control-one-failure-then-success`, spraying from an external address (high), below
  threshold and slow.

### CORR-002 Ordered HTTP probing, SSH failures and systemd persistence (v1.3.0)

* **Purpose:** a multi-stage pattern across three services of one host (web server, sshd,
  systemd), in order, within 30 minutes.
* **Telemetry:** the inputs of HTTP-001, VM-001 and VM-002 on one Linux host.
* **Logic:** stage 1 probing (10 client errors with 5 probe routes in 5 minutes), stage 2 SSH
  failures (3 failed connections or 5 failed attempts in 5 minutes), stage 3 a systemd change
  with creation or modification evidence (inventory diff, or a successful auditd
  create/modify syscall on a unit file); stage 3 at most 30 minutes after stage 1. ClickHouse
  `windowFunnel` gates the order; deletions are reported as context only. States ordered
  co-occurrence, never causation (`causation_established` is always false).
* **Confidence:** medium when the probing and the SSH failures share a source address that is
  not a shared NAT address; low otherwise (never high).
* **False positives and handling:** unrelated activity that lines up (order, thresholds and
  window must all hold; low confidence unless a non-NAT address is shared); penetration tests
  followed by maintenance (units and writers named); redeploys rewriting a unit (inventory-
  confirmed and audit-only units are separated).
* **Blind spots:** slower sequences, stages below threshold, persistence other than systemd
  units, a stage before the 45-minute lookback.
* **Matrix test `linux.corr-002`:** the HTTP-001, VM-001 and VM-002 tests in that order (alert,
  low) / the VM-001 test alone, run first (no alert). Fixtures:
  `matrix-http-ssh-systemd-sequence-via-qemu-nat`, `matrix-control-ssh-failures-alone`, same
  external source (medium), different sources (low), wrong order, too slow, baseline only,
  below the probe threshold, deletion only, non-changing audit hits (no alert), audit-only
  creation with a removal as context (medium).

---

## Kubernetes (`k8s:extorq-lab`)

Telemetry: the kube-apiserver audit log through the OpenTelemetry pipeline (normalised by
`backend/src/extorq/ingest/otlp_k8s.py`) and the read-only inventory collector; see
[telemetry/kubernetes.md](telemetry/kubernetes.md). The audit policy logs pod and RBAC
writes with their bodies (reduced to a summary and risk flags), exec/attach with the request
options, and every secret request at Metadata level (never bodies).

### K8S-001 Privileged pod denied by Pod Security admission (v1.1.0)

* **Purpose:** an attempt to run a privileged workload that the namespace's Pod Security
  level refused (T1610, T1611). The control worked; the alert records who tried what.
* **Telemetry:** `k8s.api.request` (`k8s.audit`): pod create or ephemeral-container
  patch/update answered 403 with a Pod Security violation; `attributes.risk_flags`,
  `pod_security_violation`, `dry_run`.
* **Logic:** at least one privileged control in the risk flags or the violation text
  (privileged, hostPID/hostNetwork/hostIPC, hostPath, dangerous capabilities). A 403 from
  another admission plugin never matches. One alert per audit id.
* **Confidence:** high when the request body's risk flags and the violation text both name a
  privileged control; medium when only one does.
* **False positives and handling:** node agents deployed into a restricted namespace (not
  suppressed; the fix is a privileged namespace, where K8S-005 evaluates them); server-side
  dry runs (alerted, `dry_run = true`); controller retries (one alert per denial, grouped by
  cluster, namespace and user).
* **Blind spots:** admissions (K8S-005), bodies not logged, other Pod Security controls.
* **Matrix test `kubernetes.k8s-001`:** a privileged pod into `extorq-restricted` (alert) /
  a compliant pod admitted there (no alert). Fixtures: `matrix-privileged-pod-into-restricted-namespace`
  (captured), dry run and ephemeral container (captured), `matrix-control-compliant-pod-admitted`,
  a non-Pod-Security admission denial and unrelated denials (no alert).

### K8S-002 Risky RBAC grant (v1.3.0)

* **Purpose:** privilege escalation through RBAC (T1098, T1078.004): cluster-admin bindings,
  wildcard rules, escalate/bind/impersonate, secrets read, pods/exec, bindings of anonymous,
  unauthenticated, all-authenticated or default service account subjects.
* **Telemetry:** successful RBAC writes in the audit log (post-change object, actor) and
  `k8s.resource.created/updated` inventory diffs, both with the same risk vocabulary.
* **Logic:** an object whose risk flags include a risky flag; identity includes the sorted
  risk signature. Ignored: the role-aggregation controller and the API server, annotation-only
  writes (labels stay in scope: they drive aggregation), inventory views of `system:*`
  objects, and exactly the two kubeadm bootstrap objects created by the bootstrap identity
  within 10 minutes of the cluster's observed birth (identity AND exact object AND time;
  no observed birth means no exception).
* **Confidence:** high when audit and inventory agree on the object UID, resource
  version and risk signature. A missing or different revision gives medium confidence.
* **False positives and handling:** operators and charts shipping cluster-admin (reported with
  actor and object; no name allowlist); temporary elevated access (one alert per grant); re-
  applying unchanged objects (extends the alert); kubeadm bootstrap (the narrow exception
  above); read-only bindings such as `view` (no risky flag, never alert).
* **Blind spots:** privileges obtained without RBAC writes (stolen tokens), changes by the
  excluded controllers, aggregation through labels on non-risky roles.
* **Matrix test `kubernetes.k8s-002`:** a ClusterRoleBinding of a test service account to
  `cluster-admin` (alert) / a RoleBinding to `view` in one namespace (no alert). Fixtures:
  `matrix-crb-service-account-to-cluster-admin` (captured audit record and an inventory
  fixture without matched revision metadata, medium), `matrix-control-rolebinding-to-view`,
  and the captured cluster-birth cases.

### K8S-003 Interactive exec into a pod by a human identity (v1.0.0)

* **Purpose:** command execution inside containers (T1609): the container's token, mounted
  secrets and network position.
* **Telemetry:** `k8s.api.request`: `pods/exec` or `pods/attach`, verb `get` (WebSocket) or
  `create` (SPDY), response 101 or 2xx; user, namespace, pod; `attributes.exec_command`
  (redacted), `exec_tty`, container.
* **Logic:** accepted sessions by identities without the reserved `system:` prefix (that
  excludes control-plane components, nodes and every service account, by design); exact
  identities in `excluded_users` are ignored. Sessions of one person in one pod within 15
  minutes are one alert.
* **Confidence:** high when the pod is named and the session was established; medium
  otherwise.
* **False positives and handling:** administrators debugging (alerted by design; one alert per
  15-minute episode); tooling with a personal credential (exact identity in `excluded_users`
  after review: user names come from the credential, not the request).
* **Blind spots:** exec by service accounts (excluded; K8S-002 covers granting pods/exec),
  exec through the kubelet API or the runtime, denied attempts, port-forward, what an
  interactive shell did.
* **Matrix test `kubernetes.k8s-003`:** `kubectl exec` running `id` in the web application's pod
  (alert) / `kubectl logs` of the same pod (no alert). Fixtures:
  `matrix-kubectl-exec-id-into-web-app-pod` (captured, command `id`),
  `matrix-control-kubectl-logs`, repeated sessions merged into one alert, service account,
  node and denied sessions (no alert).

### K8S-004 Secret enumeration by a non-system identity (v1.0.0)

* **Purpose:** credential access through the API (T1552.007, T1613).
* **Telemetry:** `k8s.api.request` on `secrets`: verb, namespace (absent = cluster-wide),
  response code, user, impersonated user.
* **Logic:** successful requests only, two variants per identity and 15-minute episode:
  `cluster_wide` (list or watch without a namespace: one request returns every secret) and
  `namespace_sweep` (lists in at least 3 namespaces within 10 minutes). Excluded: control-plane
  identities (`system:*` other than workload service accounts), every
  `system:serviceaccount:kube-system:*` controller, exact `allowed_identities`. Workload service
  accounts are NOT excluded: a stolen workload token enumerating secrets is the main case.
* **Confidence:** high (the audit record is authoritative for who received which secrets).
* **False positives and handling:** operators that watch secrets cluster-wide (exact service
  account identity in `allowed_identities` after review; that identity is issued by the
  cluster for its namespace); an administrator running `kubectl get secrets -A` (alerted by
  design); control-plane watches (excluded by identity prefix).
* **Blind spots:** reads of individual secrets by name, secrets read through mounted volumes,
  etcd or node credentials, denied attempts, slower sweeps.
* **Matrix test `kubernetes.k8s-004`:** `kubectl get secrets -A` by the administrator (alert) /
  `kubectl get configmap <one>` in one namespace (no alert). Fixtures:
  `matrix-kubectl-get-secrets-all-namespaces`, a workload service account sweeping four
  namespaces, `matrix-control-get-one-configmap`, controller watches, a denied cluster-wide
  list and lists in only two namespaces (no alert).

### K8S-005 Privileged or host-access pod admitted (v1.0.0)

* **Purpose:** a privileged, host-namespace, hostPath or dangerous-capability pod that the API
  server ADMITTED (T1610, T1611), the usual first step of a container escape.
* **Telemetry:** `k8s.api.request`: pod create (or ephemeral-container patch) answered 2xx,
  not a dry run, with risk flags; optionally the inventory's view of the same named pod.
* **Logic:** at least one privileged flag. Platform exemption needs BOTH a platform namespace
  (`kube-system`, `local-path-storage`, `extorq-system`) AND a kubelet or kube-system
  controller as the creator; a person creating a privileged pod there is still alerted. One
  alert per (namespace, creator, flags) per hour.
* **Confidence:** high when the inventory's view of the same named pod carries a privileged
  flag; medium for the audit record alone (always for controller-created pods, whose audit
  record has no name).
* **False positives and handling:** platform DaemonSets and static pods (the two-condition
  exemption); node agents in other namespaces (add the namespace after reviewing who can write
  to it); `kubectl debug node/...` (alerted by design: full node access).
* **Blind spots:** privileged workloads created through controllers in platform namespaces,
  templates audited at Metadata level, pods admitted while the audit pipeline was down.
* **Matrix test `kubernetes.k8s-005`:** a privileged/hostPath pod created in a namespace
  without Pod Security labels (alert) / an unprivileged pod in the same namespace (no alert).
  Fixtures: `matrix-hostpath-pod-admitted` (audit plus inventory: high), a person's hostPath
  pod in a platform namespace (medium), `matrix-control-unprivileged-pod`, DaemonSet
  controller and kubelet mirror pods, a dry run and a denied pod (no alert).

---

## GitHub (`github:exigent07/extorq-lab`)

Telemetry: the GitHub collector's commit polling with its workflow analyser (before/after
analysis of every changed workflow; unparseable versions are compared lexically and fail
closed) and its commit secret scan (only added lines; pattern name, location and a redacted
match); see [telemetry/github.md](telemetry/github.md).

### GH-001 Workflow permission escalation (v2.0.0)

* **Purpose:** a workflow whose GITHUB_TOKEN gains privileges (T1098, T1195.002).
* **Telemetry:** `github.workflow.modified`: `write_all_added`, `added_write_scopes`,
  `permissions_before/after`, `effective_permissions_unknown`, `analysis`.
* **Logic:** `permissions: write-all` added, or a sensitive write scope (contents, actions,
  packages, id-token, ...) added to the effective permissions. Since v2.0.0 permission
  escalation only (triggers and checkouts are GH-002). Identity: repository, workflow, commit.
* **Confidence:** high when both versions parsed and the effective permissions are known;
  medium for a lexical comparison or an unknown repository default; low when a version did not
  parse and no lexical comparison was made.
* **False positives and handling:** release or deployment workflows needing write scopes (one
  alert per commit and workflow with before/after permissions; no path or actor allowlist);
  write scopes coming from a permissive repository default (fixed by a read-only default).
* **Blind spots:** privilege changes outside workflow files (repository settings), unpolled
  branches and rewritten history, reusable workflows from other repositories.
* **Matrix test `github.gh-001`:** `permissions: contents: read` changed to `write-all` (alert,
  high) / the revert reducing permissions (no alert). Fixtures: `matrix-ci-workflow-write-all`,
  `matrix-control-permissions-reduced`, an id-token scope with unknown default (medium), a
  lexical-fallback write-all (medium), benign edits, a benign lexical edit and a
  pull_request_target workflow without permission changes (no alert).

### GH-002 Privileged trigger checks out untrusted code (v1.0.0)

* **Purpose:** the "pwn request" pattern (T1195.002): pull_request_target, workflow_run or
  issue_comment (base repository secrets, write-capable token) checking out code controlled by
  a pull-request author or another run.
* **Telemetry:** `github.workflow.modified`: `untrusted_checkout_added`,
  `dangerous_triggers_added`, `triggers_after`, `analysis`.
* **Logic:** the pattern is new in this commit. A privileged trigger without a checkout of
  untrusted code (labelling bots) is the documented safe use and does not alert.
* **Confidence:** high for a structured analysis of both versions; medium for a lexical
  comparison; low without either.
* **False positives and handling:** checkouts used only to read files (alerted: build scripts
  and hooks run implicitly); workflows gated by a label or environment approval (the analyser
  does not evaluate `if:`; fails closed, the reviewer confirms the gate).
* **Blind spots:** artifact or cache poisoning between workflows, composite actions checking
  out internally, patterns that existed before monitoring.
* **Matrix test `github.gh-002`:** a pull_request_target workflow checking out the pull request
  head (alert) / the same workflow on pull_request (no alert). Fixtures:
  `matrix-pull-request-target-checks-out-pr-head`, a lexical workflow_run case (medium),
  `matrix-control-pull-request-with-checkout`, a labeller on pull_request_target (no alert).

### GH-003 Unpinned third-party action added (v1.0.0)

* **Purpose:** supply-chain trust in a mutable tag (T1195.001; tj-actions/changed-files, 2025).
* **Telemetry:** `github.workflow.modified`: `unpinned_actions_added` (third-party `uses:`
  references not pinned to a full commit SHA, docker images without a digest; `actions/*` and
  `github/*` are not third-party; null when not analysed).
* **Logic:** at least one newly referenced unpinned third-party action.
* **Confidence:** high (the attribute exists only for a structured analysis).
* **False positives and handling:** verified publishers pinned by tag (alerted by design: tags
  are mutable whoever publishes; the fix is a SHA pin; no publisher allowlist); tag bumps of an
  unpinned action alert again (new trust), unchanged references never alert twice.
* **Blind spots:** unparseable workflows, SHA pins of malicious commits, code downloaded at
  runtime, references inside composite actions or remote reusable workflows.
* **Matrix test `github.gh-003`:** `docker/setup-buildx-action@v3` added (alert) / the same action
  pinned to a 40-hex SHA (no alert). Fixtures: `matrix-third-party-action-pinned-by-tag`,
  `matrix-control-same-action-sha-pinned`, an unparseable workflow (not analysed, no alert).

### GH-004 Script injection through an untrusted context (v1.0.0)

* **Purpose:** command injection into a workflow run script (T1059.004, T1195.002).
* **Telemetry:** `github.workflow.modified`: `script_injection_added` (untrusted `${{ }}`
  contexts interpolated into `run:` or github-script; null when not analysed).
* **Logic:** at least one newly interpolated untrusted expression (issue/PR title or body,
  comment body, head ref, commit message, ...). Passing the value through `env:` and quoting
  the variable is the safe pattern and does not alert.
* **Confidence:** high (structured analysis only).
* **False positives and handling:** values only echoed (alerted: substitution happens before
  the shell parses the line); triggers outsiders cannot reach (reported with the triggers so
  the reviewer can judge).
* **Blind spots:** unparseable workflows, values passed through outputs or files first,
  contexts outside the analyser's list.
* **Matrix test `github.gh-004`:** `run:` interpolating `${{ github.event.issue.title }}`
  (alert) / the value through `env:` and a quoted variable (no alert). Fixtures:
  `matrix-run-interpolates-issue-title`, `matrix-control-env-and-quoted-variable`, trusted
  expressions only (no alert).

### GH-005 Credential committed to a repository (v1.0.0)

* **Purpose:** credentials in source history (T1552.001).
* **Telemetry:** `github.secret.exposed`: repository, commit, path, line, pattern name (the
  redaction rule that matched), redacted match. The value is never stored.
* **Logic:** every event alerts; one alert per file and commit lists all patterns and lines.
  A credential stays exposed in history after a later commit removes it.
* **Confidence:** high when a provider-specific format matched (AWS, GitHub, GitLab, Slack,
  Google keys, private keys, ExtorQ tokens); medium for generic key/value assignments (whether
  the value is live and not a placeholder is not established).
* **False positives and handling:** examples and fixtures (generic matches are medium; no path
  allowlist because paths are chosen by the committer); high-entropy non-credentials such as
  checksums (the collector matches credential shapes, never entropy alone); Actions
  expressions such as `${{ secrets.X }}` (not treated as values by the collector).
* **Blind spots:** unknown formats, split or encoded credentials, binary files, history
  rewritten before polling, validity of the credential.
* **Matrix test `github.gh-005`:** a generated AWS-shaped access key id and secret committed
  (alert, high) / a SHA-256 checksum line (no alert). Fixtures:
  `matrix-fake-aws-key-committed` (two patterns, one alert), a generic password assignment
  (medium), `matrix-control-checksum-line`.

---

## macOS (`macos:workstation-01`)

Telemetry: the native macOS collector (launchd plist diffs every 60 s, listener diffs every
60 s from lsof, the unified log, application folders every 60 s with codesign checks of new
bundles); see [telemetry/macos.md](telemetry/macos.md). The collector runs as the logged-in
user without sudo.

### MAC-001 New or modified launch item (v2.0.0)

* **Purpose:** launchd persistence (T1543.001, T1543.004).
* **Telemetry:** `persistence.launchd.item_created/modified` (`macos.launchd`): path, label,
  program, scope, kind, sha256, RunAtLoad, KeepAlive, parse/read errors.
* **Logic:** every new or changed plist in `~/Library/LaunchAgents`, `/Library/LaunchAgents`,
  `/Library/LaunchDaemons` whose content digest is not in `allowlist_sha256`. Since v2.0.0 the
  collector's label allow-list no longer suppresses (reported as `collector_label_allowlisted`).
* **Confidence:** high when the plist was parsed (program and digest known); medium otherwise.
* **False positives and handling:** installers, updaters and Homebrew services (one alert per
  distinct content; reviewed content can be allowlisted by exact digest; no label or path
  allowlist because both are chosen by the plist author); MDM agents (program and scope shown).
* **Blind spots:** items created and removed between scans, other persistence (login items,
  cron, profiles), whether launchd loaded the job.
* **Matrix test `macos.mac-001`:** a launch agent running `/usr/bin/true`, never loaded (alert)
  / a `.txt` file in the same directory (no event, no alert). Fixtures:
  `matrix-user-launch-agent-created`, a reused allow-listed label (still alerts), an
  unparseable daemon (medium), `matrix-control-text-file-and-deletion` (deletion plus a
  digest-allowlisted item), and the same item alerting without the digest exception.

### MAC-002 Launch item runs a shell, interpreter or temporary-path program (v1.0.0)

* **Purpose:** the high-risk subset of launch items (T1543.001, T1543.004, T1059.004).
* **Telemetry:** as MAC-001, plus `program_arguments`.
* **Logic:** any of: the program (or the program after `/usr/bin/env`) is a shell or script
  interpreter; the program or an argument is in `/tmp`, `/var/tmp`, `/var/folders`,
  `/Users/Shared` or `~/Downloads`; a LaunchDaemon (root at boot) runs a program from a user's
  home. Exceptions only by exact content digest.
* **Confidence:** high (evaluated on the parsed plist; unparseable plists stay MAC-001 medium).
* **False positives and handling:** vendor agents wrapping their binary in `sh -c` or running a
  script (one alert per content, digest allowlist after review; never labels, paths or
  programs); installers staging in `/tmp` (the offending argument is named).
* **Blind spots:** compiled wrappers running scripts, renamed interpreters, other user-writable
  locations, the payload itself.
* **Matrix test `macos.mac-002`:** an agent with `["/bin/sh", "-c", "/tmp/extorq-test-<id>"]`
  (alert; MAC-001 alerts too) / an agent running `/usr/bin/true` (MAC-001 only). Fixtures:
  `matrix-plist-runs-sh-c-tmp-payload`, `/usr/bin/env python3` and a daemon in a home directory
  (two alerts), `matrix-control-plist-runs-usr-bin-true` (with an unparseable plist).

### MAC-003 TCP listener on all interfaces by a non-allowlisted process (v1.0.0)

* **Purpose:** an exposed service or bind shell (T1571, T1205).
* **Telemetry:** `network.listener.opened` (`macos.inventory`): bind address, port,
  protocol, owning process and executable (lsof).
* **Logic:** TCP listeners bound to `0.0.0.0` or `::` whose executable is not in
  `allowlist_executables` (exact paths; defaults: rapportd, sharingd, ControlCenter, launchd,
  all in SIP-protected locations). Loopback listeners and UDP sockets (client sockets that lsof
  lists as listeners) never match. Unknown owners are never allowlisted. One alert per (port,
  executable) per hour.
* **Confidence:** high when the owner is known; medium when lsof could not attribute it.
* **False positives and handling:** Apple services listening by design (exact SIP-protected
  paths, never process names); developers' servers on 0.0.0.0 (alerted by design: reachable
  from the network); LAN-discovery apps (exact path after review).
* **Blind spots:** UDP services, listeners shorter than one scan, malicious use of an
  allowlisted daemon (launchd socket activation is covered by MAC-001/MAC-002).
* **Matrix test `macos.mac-003`:** an accept-and-close Python listener on `0.0.0.0:<high port>`
  for up to three cycles (alert) / the same listener on `127.0.0.1` (no alert). Fixtures:
  `matrix-accept-and-close-listener-on-all-interfaces`, an unattributed IPv6 listener
  (medium), `matrix-control-loopback-listener` (with allowlisted Apple daemons and UDP sockets).

### MAC-004 Burst of sudo authentication failures (v1.0.0)

* **Purpose:** password guessing against sudo from a user session (T1110.001, T1548.003).
* **Telemetry:** `auth.sudo.failure` (`macos.unified_log`): account, reason
  (`N incorrect password attempts`), `failed_attempts`; `auth.local.failure` from
  opendirectoryd for corroboration; `auth.sudo.command` for context.
* **Logic:** at least 3 failed password attempts for one account within 5 minutes (sliding
  window; each record counts the attempts sudo reports). Authorisation denials and
  `a password is required` are not password guesses and never count.
* **Confidence:** high when opendirectoryd password-verification failures for the same
  account fall within a minute of the burst; medium for sudo's log alone.
* **False positives and handling:** a person mistyping three times (threshold = sudo's own
  limit; `sudo_success_after` shows the typo pattern; no account allowlist because the
  account is the target); scripts with a wrong password on stdin (`ttys` shows no terminal).
* **Blind spots:** slower guessing, password prompts other than sudo, NOPASSWD and cached
  timestamps, records the collector missed.
* **Matrix test `macos.mac-004`:** `sudo -k`, then three `sudo -k -S -v` with a wrong password
  (alert) / a single attempt (no alert). Fixtures: `matrix-three-wrong-passwords-via-sudo-S`
  (with opendirectoryd: high), one exhausted prompt then a success (medium,
  `sudo_success_after`), `matrix-control-single-failed-attempt` (with an authorisation denial,
  `sudo -n` and screen-unlock failures).

### MAC-005 Unsigned or ad-hoc signed application installed (v1.0.0)

* **Purpose:** trojanised or unknown applications (T1204.002, T1553.001).
* **Telemetry:** `software.installed` (`macos.inventory`): bundle path, name, bundle id,
  version, `signed` (true/false/"unknown"), `signature_type`, team id.
* **Logic:** `signed` explicitly false (unsigned or the signature does not verify) or
  `signature_type = adhoc` (signed without any identity). An undetermined check never alerts.
  No allowlist: such a bundle has no verifiable identity.
* **Confidence:** high when the bundle identifier was read with the verdict; medium otherwise.
* **False positives and handling:** unsigned open-source or locally built apps (alerted by
  design; sign in-house builds); bundles still being copied (the collector waits until the
  bundle settles and re-checks a just-settled failure); self-modifying apps (reviewed, because
  tampering looks the same).
* **Blind spots:** bundles outside the application folders, command-line binaries,
  notarisation and quarantine are not evaluated.
* **Matrix test `macos.mac-005`:** the unsigned bundle `/Applications/ExtorQ Test.app`, never
  executed (alert) / a copy of Apple's signed Calculator (no alert). Fixtures:
  `matrix-unsigned-test-bundle-installed`, an ad-hoc bundle without identity (medium),
  `matrix-control-signed-apple-bundle-copy` (with an undetermined signature and a removal).

---

## Expected overlaps between rules

| Activity | Rules |
|---|---|
| The CORR-002 sequence | CORR-002, HTTP-001, VM-001, VM-002 |
| A launch item running a shell or a temporary path | MAC-001, MAC-002 |
| A new workflow whose token relies on a write default and checks out PR code | GH-001 (if a sensitive write scope results), GH-002 |
| A privileged pod: denied / admitted | K8S-001 / K8S-005 (never both for one request) |

## Changes for contract schema 2.0 (2026-11-22)

* All rules: no simulation output (`simulation_run_ids`) and no simulation inputs; patch or
  minor version bumps where only that changed (VM-001 1.1.0, VM-002 1.3.0, HTTP-001 1.1.0,
  APP-001 1.1.0, CORR-002 1.3.0, K8S-001 1.1.0, K8S-002 1.2.0). HTTP-001 and APP-001 are now
  `stable`.
* GH-001 2.0.0: permission escalation only; triggers and untrusted checkout moved to GH-002.
* MAC-001 2.0.0: the label allow-list no longer suppresses; exceptions by content digest.
* New: VM-003, VM-004, K8S-003, K8S-004, K8S-005, GH-002, GH-003, GH-004, GH-005, MAC-002,
  MAC-003, MAC-004, MAC-005.
* Fixtures regenerated for schema 2.0; rule test cases can override declared parameters
  (allowlists are tested without putting test values into the production rule).

## Planned (not implemented)

* Revalidating stored alert evidence when a rule version changes (a `superseded` evidence
  role; needs a contract change).
* Exec by service accounts as a separate, lower-severity rule (excluded from K8S-003 by
  design).
* Denied secret enumeration attempts (403) as reconnaissance signal.
