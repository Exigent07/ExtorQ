"""Regenerate the SYNTHETIC rule fixtures under rules/<domain>/tests/.

Usage: ``uv run python tests/rules/generate_fixtures.py``

Output is deterministic (fixed timestamps, deterministic event ids), so the
committed JSONL files can be reviewed and diffed. See fixture_builder.py for the
synthetic-labelling conventions.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixture_builder import (
    BASE,
    K8S,
    LINUX,
    FixtureWriter,
    k8s_audit_events,
    k8s_risk_flags,
    ssh_failed_connection,
    ssh_success,
    workflow_delta_attributes,
)

ROOT = Path(__file__).resolve().parents[2] / "rules"
S = timedelta(seconds=1)
M = timedelta(minutes=1)

Builder = Callable[[], dict[str, FixtureWriter]]
BUILDERS: list[Builder] = []


def builder(func: Builder) -> Builder:
    BUILDERS.append(func)
    return func


# ── VM-001 ───────────────────────────────────────────────────────────


@builder
def vm001() -> dict[str, FixtureWriter]:
    out: dict[str, FixtureWriter] = {}
    d = "linux/tests/VM-001"

    fx = FixtureWriter("vm001-burst-external")
    for i, user in enumerate(["admin", "admin", "oracle", "test", "ubuntu", "postgres"]):
        ssh_failed_connection(fx, BASE + i * 10 * S, "203.0.113.45", 50100 + i, user, pid=4000 + i)
    out[f"{d}/positive_burst_external.jsonl"] = fx

    fx = FixtureWriter("vm001-bucket-boundary")
    start = BASE + 4 * M + 40 * S  # 10:04:40 .. 10:05:20 straddles the 10:05 bucket boundary
    for i in range(6):
        ssh_failed_connection(
            fx, start + i * 8 * S, "198.51.100.7", 41000 + i, "deploy", pid=4200 + i
        )
    out[f"{d}/positive_bucket_boundary.jsonl"] = fx

    fx = FixtureWriter("vm001-nat-sim")
    sim = {"run_id": "fixture0vm001", "scenario_id": "VM-001"}
    for i in range(6):
        ssh_failed_connection(
            fx,
            BASE + i * 5 * S,
            "10.0.2.2",
            52000 + i,
            "extorq-sim-fixture0vm001",
            pid=4300 + i,
            simulation=sim,
        )
    out[f"{d}/positive_nat_gateway_sim.jsonl"] = fx

    fx = FixtureWriter("vm001-two-connections")
    ssh_failed_connection(
        fx, BASE, "192.0.2.10", 43001, "root", invalid=False, attempts=6, pid=4400
    )
    ssh_failed_connection(
        fx, BASE + 20 * S, "192.0.2.10", 43002, "root", invalid=False, attempts=6, pid=4401
    )
    out[f"{d}/positive_failures_two_connections.jsonl"] = fx

    fx = FixtureWriter("vm001-below")
    for i in range(4):
        ssh_failed_connection(
            fx, BASE + i * 30 * S, "203.0.113.46", 50200 + i, "admin", pid=4500 + i
        )
    out[f"{d}/negative_below_threshold.jsonl"] = fx

    fx = FixtureWriter("vm001-slow")
    for i in range(6):
        ssh_failed_connection(
            fx, BASE + i * 4 * M, "203.0.113.47", 50300 + i, "admin", pid=4600 + i
        )
    out[f"{d}/negative_slow.jsonl"] = fx

    fx = FixtureWriter("vm001-distributed")
    for i in range(6):
        ssh_failed_connection(
            fx, BASE + i * 5 * S, f"198.51.100.{20 + i}", 50400 + i, "admin", pid=4700 + i
        )
    out[f"{d}/negative_distributed.jsonl"] = fx

    fx = FixtureWriter("vm001-successes")
    for i in range(6):
        ssh_success(fx, BASE + i * 5 * S, "203.0.113.48", 50500 + i, "ubuntu", pid=4800 + i)
    out[f"{d}/negative_successes.jsonl"] = fx
    return out


# ── K8S-001 / K8S-002 (derived from B2's captured audit records) ─────


def _derived(name: str, *files: str, rename: dict[str, str] | None = None) -> FixtureWriter:
    fx = FixtureWriter(name)
    for file in files:
        fx.events.extend(k8s_audit_events(file, rename=(rename or {}).get(file)))
    return fx


@builder
def k8s001() -> dict[str, FixtureWriter]:
    d = "kubernetes/tests/K8S-001"
    return {
        f"{d}/positive_psa_privileged_pod.jsonl": _derived("k8s001-a", "psa_denied_privileged_pod.json"),
        f"{d}/positive_psa_dry_run.jsonl": _derived("k8s001-b", "psa_denied_dry_run.json"),
        f"{d}/positive_psa_ephemeral_container.jsonl": _derived(
            "k8s001-c", "psa_denied_ephemeral_container.json"
        ),
        f"{d}/positive_psa_simulation.jsonl": _derived(
            "k8s001-d",
            "psa_denied_privileged_pod.json",
            rename={"psa_denied_privileged_pod.json": "extorq-sim-fixture0k8s001"},
        ),
        f"{d}/negative_admission_denied_not_psa.jsonl": _derived(
            "k8s001-e", "bootstrap_mirror_pod_admission_denied.json"
        ),
        f"{d}/negative_unrelated_audit.jsonl": _derived(
            "k8s001-f",
            "forbidden_impersonated_secret_list.json",
            "unauthenticated_401.json",
            "serviceaccount_create.json",
            "pod_patch_json.json",
            "anonymous_forbidden_secret_list.json",
        ),
    }


def _rbac_state(fx: FixtureWriter, audit_file: str, kind: str, name: str, namespace: str | None,
                *, offset_s: int = 30, baseline: bool = False, flags: list[str] | None = None) -> None:
    audit = k8s_audit_events(audit_file)[0]
    attrs: dict[str, object] = {"risk_flags": flags if flags is not None else k8s_risk_flags(audit_file)}
    if baseline:
        attrs["baseline"] = True
    fx.add(
        "k8s.resource.created",
        audit.event_time + offset_s * S,
        asset=K8S,
        action="created",
        outcome="success",
        resource={"type": kind, "name": name, "namespace": namespace},
        kubernetes={"cluster": "extorq-lab", "namespace": namespace},
        message=f"{kind} {name} observed for the first time",
        attributes=attrs,
    )


@builder
def k8s002() -> dict[str, FixtureWriter]:
    d = "kubernetes/tests/K8S-002"
    out = {
        f"{d}/positive_crb_patch_subjects.jsonl": _derived("k8s002-a", "rbac_crb_patch_subjects.json"),
        f"{d}/positive_role_wildcard.jsonl": _derived("k8s002-b", "rbac_role_wildcard_create.json"),
        f"{d}/negative_controller_denied_delete.jsonl": _derived(
            "k8s002-d",
            "rbac_clusterrole_aggregation_patch.json",
            "bootstrap_rbac_forbidden.json",
            "rbac_crb_delete.json",
        ),
    }
    fx = _derived("k8s002-c", "rbac_clusterrole_escalate_create.json")
    _rbac_state(fx, "rbac_clusterrole_escalate_create.json", "ClusterRole", "b2-fixture-escalate", None)
    out[f"{d}/positive_escalate_audit_and_state.jsonl"] = fx

    fx = FixtureWriter("k8s002-e")
    _rbac_state(fx, "rbac_role_wildcard_create.json", "Role", "reader", "extorq-apps", flags=[])
    _rbac_state(fx, "rbac_clusterrole_escalate_create.json", "ClusterRole", "legacy-escalate", None,
                baseline=True, offset_s=60)
    out[f"{d}/negative_benign_state.jsonl"] = fx
    return out


# ── GH-001 (attributes computed by C1's workflow analyser) ───────────

WF_BASE = """name: ci
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955
      - run: make test
"""
REPO_ASSET = ("github:example-org/extorq-lab", "github_repository")


def _workflow_event(fx: FixtureWriter, t, sha: str, path: str, before: str | None, after: str | None,
                    *, repo_default: str | None = "read", actor: str = "octo-dev",
                    sim: dict[str, str] | None = None) -> None:
    attrs = workflow_delta_attributes(path, before, after, repo_default=repo_default)
    fields: dict[str, object] = {}
    if sim:
        fields["simulation"] = sim
    fx.add(
        "github.workflow.modified",
        t,
        asset=REPO_ASSET,
        native_key=f"{sha}:{path}",
        action="workflow_modified",
        outcome="success",
        actor={"type": "github_user", "name": actor},
        resource={"type": "github_workflow", "name": path.rsplit("/", 1)[-1], "path": path},
        github={"repository": "example-org/extorq-lab", "ref": "refs/heads/main", "commit_sha": sha,
                "workflow_path": path, "workflow_name": "ci", "actor_login": actor},
        message=f"Workflow {path} modified (synthetic fixture)",
        attributes=attrs,
        **fields,
    )


@builder
def gh001() -> dict[str, FixtureWriter]:
    d = "github/tests/GH-001"
    path = ".github/workflows/ci.yml"
    out: dict[str, FixtureWriter] = {}
    fx = FixtureWriter("gh001-a")
    _workflow_event(fx, BASE, "1" * 40, path, WF_BASE,
                    WF_BASE.replace("permissions:\n  contents: read", "permissions: write-all"))
    out[f"{d}/positive_write_all.jsonl"] = fx

    fx = FixtureWriter("gh001-b")
    after = WF_BASE.replace("on:\n  push:\n    branches: [main]",
                            "on:\n  push:\n    branches: [main]\n  pull_request_target:")
    _workflow_event(fx, BASE, "2" * 40, path, WF_BASE, after, actor="extorq-sim-fixture0gh001",
                    sim={"run_id": "fixture0gh001", "scenario_id": "GH-001"})
    out[f"{d}/positive_pull_request_target_sim.jsonl"] = fx

    fx = FixtureWriter("gh001-c")
    no_perms = WF_BASE.replace("permissions:\n  contents: read\n", "")
    with_oidc = WF_BASE.replace("permissions:\n  contents: read",
                                "permissions:\n  contents: read\n  id-token: write")
    _workflow_event(fx, BASE, "3" * 40, ".github/workflows/deploy.yml", no_perms, with_oidc,
                    repo_default=None)
    out[f"{d}/positive_scope_unknown_default.jsonl"] = fx

    fx = FixtureWriter("gh001-d")
    _workflow_event(fx, BASE, "4" * 40, path, WF_BASE, WF_BASE.replace("make test", "make lint test"))
    _workflow_event(fx, BASE + M, "5" * 40, path, WF_BASE,
                    WF_BASE.replace("permissions:\n  contents: read",
                                    "permissions:\n  contents: read\n  issues: read"))
    _workflow_event(fx, BASE + 2 * M, "6" * 40, path, WF_BASE,
                    WF_BASE.replace("    branches: [main]", "    branches: [main, develop]\n  pull_request:"))
    out[f"{d}/negative_benign_edits.jsonl"] = fx
    return out


# ── VM-002 (synthetic, catalog key_fields) ───────────────────────────


def _unit_event(fx: FixtureWriter, event_type: str, t, path: str, sha: str, *, prev: str | None = None,
                baseline: bool = False, sim: dict[str, str] | None = None) -> None:
    name = path.rsplit("/", 1)[-1]
    attrs: dict[str, object] = {"sha256": sha, "exec_start": "/bin/sh -c 'sleep infinity'",
                                "vendor_unit": False}
    if prev:
        attrs["previous_sha256"] = prev
    if baseline:
        attrs["baseline"] = True
    fields: dict[str, object] = {"simulation": sim} if sim else {}
    fx.add(event_type, t, asset=LINUX, action=event_type.rsplit(".", 1)[-1], outcome="success",
           resource={"type": "systemd_unit", "name": name, "path": path},
           message=f"systemd unit {name} {event_type.rsplit('_', 1)[-1]} (snapshot diff)",
           attributes=attrs, **fields)


def _audit_watch(fx: FixtureWriter, t, path: str, key: str, serial: int,
                 sim: dict[str, str] | None = None) -> None:
    fields: dict[str, object] = {"simulation": sim} if sim else {}
    fx.add("file.audit.watch", t, asset=LINUX, action="write", outcome="success",
           resource={"path": path}, process={"executable": "/usr/bin/tee", "name": "tee", "pid": 7021},
           actor={"type": "user", "id": "1000"},
           message=f"audit watch {key}: {path} written by /usr/bin/tee",
           attributes={"audit_key": key, "syscall": "openat", "audit_serial": str(serial)}, **fields)


def _enabled(fx: FixtureWriter, t, unit: str, wanted_by: str = "multi-user.target") -> None:
    fx.add("persistence.systemd.unit_enabled", t, asset=LINUX, action="unit_enabled",
           outcome="success", resource={"type": "systemd_unit", "name": unit},
           message=f"systemd unit {unit} enabled ({wanted_by})", attributes={"wanted_by": wanted_by})


@builder
def vm002() -> dict[str, FixtureWriter]:
    d = "linux/tests/VM-002"
    out: dict[str, FixtureWriter] = {}
    sim = {"run_id": "fixture0vm002", "scenario_id": "VM-002"}
    unit = "/etc/systemd/system/extorq-sim-fixture0vm002.service"
    fx = FixtureWriter("vm002-a")
    _audit_watch(fx, BASE, unit, "extorq_systemd", 811, sim)
    _unit_event(fx, "persistence.systemd.unit_created", BASE + 45 * S, unit, "a" * 64, sim=sim)
    _enabled(fx, BASE + 45 * S, "extorq-sim-fixture0vm002.service")
    out[f"{d}/positive_created_with_audit_sim.jsonl"] = fx

    fx = FixtureWriter("vm002-b")
    _unit_event(fx, "persistence.systemd.unit_modified", BASE, "/etc/systemd/system/ssh-tunnel.service",
                "b" * 64, prev="c" * 64)
    out[f"{d}/positive_modified_inventory_only.jsonl"] = fx

    fx = FixtureWriter("vm002-c")
    _enabled(fx, BASE, "rsync.service")
    out[f"{d}/positive_enabled_only.jsonl"] = fx

    fx = FixtureWriter("vm002-d")
    _unit_event(fx, "persistence.systemd.unit_created", BASE, "/etc/systemd/system/nginx.service",
                "d" * 64, baseline=True)
    _audit_watch(fx, BASE + S, "/etc/ssh/sshd_config", "extorq_sshd", 812)
    fx.add("persistence.systemd.unit_deleted", BASE + 2 * S, asset=LINUX, action="unit_deleted",
           resource={"type": "systemd_unit", "name": "old.service",
                     "path": "/etc/systemd/system/old.service"},
           message="systemd unit old.service deleted (snapshot diff)")
    fx.add("persistence.cron.changed", BASE + 3 * S, asset=LINUX, action="changed",
           resource={"path": "/etc/crontab"}, attributes={"sha256": "e" * 64},
           message="cron configuration changed (snapshot diff)")
    out[f"{d}/negative_baseline_and_unrelated.jsonl"] = fx
    return out


def main() -> int:
    written = 0
    for build in BUILDERS:
        for rel, fx in build().items():
            fx.write(ROOT / rel)
            written += 1
            print(f"wrote {rel} ({len(fx.events)} synthetic events)")
    print(f"{written} fixture files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
