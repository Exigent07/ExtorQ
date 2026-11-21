# Attack scenarios

Safe, reversible scenarios against ExtorQ's own lab assets. Each produces **genuine
telemetry** through the normal collection path; detections come from that telemetry, never
from the scenario's own bookkeeping. Scripts are owned by the producing agent (paths below);
verification tooling (`simulations/lib/`) by C2. See also `simulations/README.md`,
`docs/detection-catalog.md` and `docs/correlation.md`.

## Rules of engagement (all scenarios)

* Only lab assets created by ExtorQ: the QEMU VM `linux:lab-vm-01`, the kind cluster
  `extorq-lab`, the macOS host's own user LaunchAgents directory, the private lab GitHub
  repository. Never the `motorq-security` cluster or any third-party system.
* Every run has a run id (8-32 lower-case alphanumerics). The scenario embeds the marker
  `extorq-sim-<run_id>` (or `com.extorq.sim.<run_id>` for launchd labels,
  `[extorq-sim <run_id>]` in commit messages) in attacker-visible text, so the genuine
  telemetry carries `event.simulation.run_id`. Rules never filter it out.
* Scenarios record a `SimulationRun` (`extorq-collect sim-record`, started / completed /
  cleaned_up). It documents that a scenario ran; it is never evidence.
* No credentials are used or printed; throwaway keys/passwords are random and discarded.
  Every action is reversible (`--cleanup`), and most change nothing persistent.

## Verifying a run

```bash
# stack + debug proxy (127.0.0.1:18123) running; read-only identity extorq_api_ro
uv run python simulations/lib/verify_scenario.py <run_id> --expect <RULE> [--wait 300]
uv run python simulations/lib/simlib.py wait-alert --rule <RULE> --run-id <run_id> --timeout 600
uv run python simulations/lib/simlib.py tagged --run-id <run_id>
```

`verify_scenario.py` prints the SimulationRun record, the telemetry tagged with the run (per
source type, event type, asset and **authenticated producer**: the gateway sets
`producer_id` from the producer's token), every alert carrying the run id with its evidence
events and source types, any synthetic-labelled evidence (flagged as not genuine), the
stored investigation context, and whether the expected rules alerted (exit 0 / 1).

## Scenarios

### VM-001 Failed SSH authentication burst (owner B1)

* **Preconditions:** lab VM up (`infra/vm/vm.sh up`), Linux collector running, detector up.
* **Run:** `simulations/vm/vm_001_ssh_failed_auth.sh [--run-id ID] [--attempts N]`.
  From the Mac, >= 8 SSH connections to 127.0.0.1:2222 as the non-existent user
  `extorq-sim-<run_id>`, each offering a fresh throwaway ed25519 key, plus one connection
  exceeding MaxAuthTries. Every attempt fails; nothing changes on the VM.
* **Expected telemetry (`linux.journald`):** `auth.ssh.invalid_user`,
  `auth.ssh.login_failed`, `auth.ssh.preauth_closed`, `auth.ssh.max_auth_exceeded`, source
  `10.0.2.2` (QEMU SLIRP gateway), many source ports.
* **Expected alert:** `VM-001`, confidence **medium** (shared NAT source: the burst is real,
  its origin is not attributable).
* **Cleanup:** nothing persistent; `--cleanup --run-id ID` records `cleaned_up`.
* **Verified (2026-11-21):** runs `bace7dc4a3d2` and `c7cbc976ecaf` -> VM-001 medium (the
  second run's lines arrived 26 minutes late and were evaluated by the late-data catch-up).

### VM-002 systemd persistence (owner B1)

* **Run:** `simulations/vm/vm_002_systemd_persistence.sh [--run-id ID]`: as the lab operator
  (sudo) creates `/etc/systemd/system/extorq-sim-<run_id>.service` (`Type=oneshot`,
  `ExecStart=/bin/true`), `daemon-reload`, `enable`; the unit is not started.
* **Expected telemetry:** `file.audit.watch` key `extorq_systemd` (`linux.auditd`),
  `auth.sudo.command`, `system.systemd.daemon_reload` (`linux.journald`),
  `persistence.systemd.unit_created` and `unit_enabled` (`linux.inventory`, within one
  inventory interval), `service.discovered`.
* **Expected alert:** `VM-002`, confidence **high** when auditd corroborates the inventory
  diff on the same path.
* **Cleanup:** `simulations/vm/vm_002_systemd_persistence.sh --cleanup --run-id ID`
  (disables and removes the unit, reloads systemd). The cleanup's auditd `unlinkat` is not
  counted as persistence (VM-002/CORR-002 v1.1.0).
* **Verified (2026-11-21):** run `b7a712bc786d` -> VM-002 high (auditd + inventory agree).

### HTTP-001 Web probing and failed application logins (owner B1)

* **Run:** `simulations/http/http_probe.sh [--run-id ID]`: 6 probe-like paths (`/.env`,
  `/.git/config`, `/wp-login.php`, `/phpmyadmin/`, `/server-status`, `/admin`) and 5 failed
  `POST /login` against http://127.0.0.1:8088 (nginx -> lab-portal), user agent containing
  `extorq-sim-<run_id>`. Nothing changes on the VM.
* **Expected telemetry:** `http.request` (`linux.nginx`, 11 lines, 4xx), `app.authz.denied`,
  `app.auth.login_failed` (`linux.app`, nginx request id propagated).
* **Expected alerts:** `HTTP-001` (>= 10 client errors, >= 5 probe-like routes) and
  `APP-001` (5 failed logins for `lab-admin`), both confidence **medium** (source 10.0.2.2).
  Correlation links the app events to the nginx lines by the propagated request id (DIRECT).
* **Verified (2026-11-21):** runs `8c8e999442ed` and `fff5113314b3` -> HTTP-001 and APP-001
  (`verify_scenario.py <run> --expect HTTP-001 --expect APP-001`).

### CORR-002 Ordered probing, SSH failures and persistence on one host (B1 scripts, C2 rule)

* **Run** the three scripts above **in this order within 30 minutes with one run id**:

  ```bash
  RUN_ID="$(uv run python simulations/lib/simlib.py new-run-id)"
  simulations/http/http_probe.sh --run-id "$RUN_ID"
  simulations/vm/vm_001_ssh_failed_auth.sh --run-id "$RUN_ID"
  simulations/vm/vm_002_systemd_persistence.sh --run-id "$RUN_ID"
  uv run python simulations/lib/verify_scenario.py "$RUN_ID" \
      --expect HTTP-001 --expect VM-001 --expect VM-002 --expect CORR-002 --wait 600
  simulations/vm/vm_002_systemd_persistence.sh --cleanup --run-id "$RUN_ID"
  ```

* **Expected alerts:** HTTP-001, VM-001, VM-002 and `CORR-002` with confidence **low**: all
  three stages come from 10.0.2.2, a shared NAT address, so a common origin is not
  established. The alert states ordered co-occurrence across nginx, sshd and systemd, never
  causation (`features.causation_established = false`).
* **Verified (2026-11-21):** B1's HTTP-001, VM-001 and VM-002 runs (separate run ids) ->
  one CORR-002 alert, confidence low, evidence from linux.nginx, linux.journald,
  linux.auditd and linux.inventory.

### K8S-001 Privileged pod denied by Pod Security (owner B2)

* **Preconditions:** kind cluster `extorq-lab` up, OTel audit pipeline delivering.
* **Run:** `simulations/k8s/k8s_001_privileged_pod_denied.sh [--run-id ID]`: `kubectl create`
  of Pod `extorq-sim-<run_id>` (privileged, hostPID) in `extorq-restricted` (Pod Security
  `baseline` enforced); the API server answers 403 and no pod is created.
* **Expected telemetry (`k8s.audit`):** `k8s.api.request` create pods, response 403,
  `attributes.pod_security_violation`, `risk_flags` [host_pid, privileged].
* **Expected alert:** `K8S-001` (one per audit id), confidence **high**.
* **Cleanup:** `--cleanup --run-id ID` double-checks no pod exists.
* **Verified (2026-11-21):** run `bcfcb726ff01` -> K8S-001 high.

### K8S-002 Risky RBAC grant (owner B2)

* **Run:** `simulations/k8s/k8s_002_risky_rbac.sh [--run-id ID] [--collect-once]`: creates
  ServiceAccount `extorq-apps/extorq-sim-<run_id>` and ClusterRoleBinding
  `extorq-sim-<run_id>` to `cluster-admin`, waits for audit and inventory evidence, then
  always deletes both (trap on exit).
* **Expected telemetry:** `k8s.api.request` create clusterrolebindings (201, `risk_flags`
  [cluster_admin]) and `k8s.resource.created` (`k8s.api_inventory`, same flags).
* **Expected alert:** `K8S-002`, confidence **high** when audit and inventory agree.
* **Verified (2026-11-21):** run `c9c96ff29f33` -> K8S-002 high (audit + inventory).

### GH-001 Workflow permission escalation (owner C1)

* **Run:** `simulations/github/gh_001_workflow_permissions.sh` (default `--dry-run`: local
  analysis only, no network). `--execute` pushes `permissions: write-all` and a
  `pull_request_target` job checking out the PR head to the **private** lab repository; it
  is run only by the lead after the user approved pushing. Commit message carries
  `[extorq-sim <run_id>]`.
* **Expected telemetry (`github.api`):** `github.commit.observed`,
  `github.workflow.modified` (`write_all_added`, `dangerous_triggers_added`,
  `untrusted_checkout_added`), possibly `github.workflow_run.observed`.
* **Expected alert:** `GH-001`, confidence **high** (both versions parsed, permissions known).
* **Cleanup:** `--cleanup` restores the baseline workflow with a new commit (history is never
  rewritten).

### MAC-001 LaunchAgent persistence (owner B3)

* **Preconditions:** macOS collector running (`uv run extorq-collect run --only
  macos-workstation-01`).
* **Run:** `simulations/macos/mac_001_launchagent.sh [--run-id ID]`: creates
  `~/Library/LaunchAgents/com.extorq.sim.<run_id>.plist` (`/usr/bin/true`, RunAtLoad false);
  the job is never loaded. macOS may show a "Background Items Added" notification.
* **Expected telemetry (`macos.launchd`):** `persistence.launchd.item_created`
  (label, program, sha256, scope user), `service.discovered` at the next inventory cycle.
* **Expected alert:** `MAC-001`, confidence **high**.
* **Cleanup:** `--cleanup --run-id ID` deletes exactly the file the scenario created.
* **Verified (2026-11-21):** run `51ff258a3b7d` -> `MAC-001` alert from the genuine event
  delivered by producer `macos-workstation-01`; `verify_scenario.py ... --expect MAC-001`
  exit 0 (docs/team/status/C2.md).
