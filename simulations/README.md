# simulations/

Safe, reversible attack scenarios against ExtorQ's own lab assets, plus shared tooling to
prove that an alert came from genuine telemetry. Scenario details (preconditions, exact
commands, expected telemetry and alerts, cleanup, safety): `docs/attack-scenarios.md`.

| Path | Scenario | Owner |
|---|---|---|
| `vm/vm_001_ssh_failed_auth.sh` | VM-001 failed SSH burst against the lab VM | B1 |
| `vm/vm_002_systemd_persistence.sh` | VM-002 systemd unit created + enabled (reversible) | B1 |
| `http/http_probe.sh` | HTTP-001 probe paths + failed app logins | B1 |
| `k8s/k8s_001_privileged_pod_denied.sh` | K8S-001 privileged pod denied by Pod Security | B2 |
| `k8s/k8s_002_risky_rbac.sh` | K8S-002 cluster-admin binding (auto-removed) | B2 |
| `github/gh_001_workflow_permissions.sh` | GH-001 workflow permission escalation (dry run by default) | C1 |
| `macos/mac_001_launchagent.sh` | MAC-001 LaunchAgent plist (never loaded) | B3 |
| `lib/` | shared helpers and verification (this section) | C2 |

CORR-002 is the HTTP-001, VM-001 and VM-002 scripts run in that order within 30 minutes
with one run id.

## Safety rules

Lab assets only (never `motorq-security` or third-party systems); every run carries the
`extorq-sim-<run_id>` marker so its telemetry is tagged, never filtered; no real
credentials; every change reversible with `--cleanup`; GitHub pushes only with the lead's
explicit approval. Telemetry produced by a scenario is genuine; the `SimulationRun` record
only documents that the scenario ran and is never evidence.

## lib/ (owner C2)

Read-only helpers (ClickHouse user `extorq_api_ro` through the debug proxy
127.0.0.1:18123; the password is read from its file by A's client factory, never passed on
a command line). Every value read from telemetry is sanitised before printing.

```bash
uv run python simulations/lib/simlib.py new-run-id                  # 12 hex chars (CSPRNG)
uv run python simulations/lib/simlib.py marker <run_id>             # extorq-sim-<run_id>
uv run python simulations/lib/simlib.py tagged --run-id <run_id>     # telemetry carrying the run id
uv run python simulations/lib/simlib.py wait-alert --rule VM-001 --run-id <run_id> --timeout 600
uv run python simulations/lib/verify_scenario.py <run_id> [--expect RULE ...] [--wait S]
```

From bash (macOS bash 3.2 compatible):

```bash
. simulations/lib/lib.sh
run_id="$(extorq_sim_new_run_id)"
extorq_sim_wait_alert VM-001 "$run_id" 600 && extorq_sim_verify "$run_id" --expect VM-001
```

`verify_scenario.py` exits 0 when every expected rule (from `--expect`, else the
SimulationRun's `expected_rule_ids`) has an alert for the run, 1 otherwise, 2 on usage or
connection errors. Synthetic-labelled evidence (test fixtures) is flagged as not genuine.
Tests: `uv run pytest tests/rules/test_simulation_verify.py -q` (ephemeral ClickHouse).
