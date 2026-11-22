"""Regenerate the SYNTHETIC rule fixtures under rules/<domain>/tests/.

Usage: ``uv run python tests/rules/generate_fixtures.py``

Output is deterministic (fixed timestamps, deterministic event ids), so the
committed JSONL files can be reviewed and diffed. See fixture_builder.py for the
synthetic-labelling conventions.
"""

from __future__ import annotations

import sys
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixture_builder import (
    BASE,
    K8S,
    LINUX,
    MACOS,
    FixtureWriter,
    captured_events,
    http_probe,
    k8s_audit_events,
    k8s_risk_flags,
    nginx_request,
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
        f"{d}/positive_psa_privileged_pod.jsonl": _derived(
            "k8s001-a", "psa_denied_privileged_pod.json"
        ),
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


def _rbac_state(
    fx: FixtureWriter,
    audit_file: str,
    kind: str,
    name: str,
    namespace: str | None,
    *,
    offset_s: int = 30,
    baseline: bool = False,
    flags: list[str] | None = None,
) -> None:
    audit = k8s_audit_events(audit_file)[0]
    attrs: dict[str, object] = {
        "risk_flags": flags if flags is not None else k8s_risk_flags(audit_file)
    }
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
        f"{d}/positive_crb_patch_subjects.jsonl": _derived(
            "k8s002-a", "rbac_crb_patch_subjects.json"
        ),
        f"{d}/positive_role_wildcard.jsonl": _derived("k8s002-b", "rbac_role_wildcard_create.json"),
        f"{d}/negative_controller_denied_delete.jsonl": _derived(
            "k8s002-d",
            "rbac_clusterrole_aggregation_patch.json",
            "bootstrap_rbac_forbidden.json",
            "rbac_crb_delete.json",
        ),
    }
    fx = _derived("k8s002-c", "rbac_clusterrole_escalate_create.json")
    _rbac_state(
        fx, "rbac_clusterrole_escalate_create.json", "ClusterRole", "b2-fixture-escalate", None
    )
    out[f"{d}/positive_escalate_audit_and_state.jsonl"] = fx

    fx = FixtureWriter("k8s002-e")
    _rbac_state(fx, "rbac_role_wildcard_create.json", "Role", "reader", "extorq-apps", flags=[])
    _rbac_state(
        fx,
        "rbac_clusterrole_escalate_create.json",
        "ClusterRole",
        "legacy-escalate",
        None,
        baseline=True,
        offset_s=60,
    )
    out[f"{d}/negative_benign_state.jsonl"] = fx
    out.update(_k8s002_bootstrap(d))
    return out


# Genuine normalised audit events of the lab cluster's birth (2026-11-21 10:16Z), exported
# read-only from the live store (tests/rules/captures/README.md).
BIRTH_CAPTURE = "k8s_cluster_birth_live.jsonl"
RBAC_GROUP = "rbac.authorization.k8s.io"


def _subject(kind: str, name: str) -> dict[str, str]:
    return {"kind": kind, "apiGroup": RBAC_GROUP, "name": name}


def _rbac_create_variant(
    base: str,
    *,
    at: datetime,
    name: str,
    user: str,
    groups: list[str],
    subjects: list[dict[str, str]],
    role_ref: tuple[str, str],
    namespace: str | None = None,
) -> list:
    """B2's captured RBAC create reshaped into another object/actor/time (SYNTHETIC)."""

    def mutate(record: dict[str, Any]) -> None:
        key = f"extorq-fixture:{base}:{namespace}:{name}:{user}:{at.isoformat()}"
        record["auditID"] = str(uuid.uuid5(uuid.NAMESPACE_URL, key))
        record["user"] = {"username": user, "groups": groups}
        record["objectRef"]["name"] = name
        kind = record["objectRef"]["resource"]
        if namespace is None:
            record["objectRef"].pop("namespace", None)
            uri = f"/apis/{RBAC_GROUP}/v1/{kind}?fieldManager=kubectl-create"
        else:
            record["objectRef"]["namespace"] = namespace
            uri = f"/apis/{RBAC_GROUP}/v1/namespaces/{namespace}/{kind}?fieldManager=kubectl-create"
        record["requestURI"] = uri
        meta = {"name": name, **({"namespace": namespace} if namespace else {})}
        for body in ("requestObject", "responseObject"):
            record[body]["metadata"] = dict(meta)
            record[body]["subjects"] = subjects
            record[body]["roleRef"] = {
                "apiGroup": RBAC_GROUP,
                "kind": role_ref[0],
                "name": role_ref[1],
            }
        record["requestReceivedTimestamp"] = at.isoformat().replace("+00:00", "Z")
        stage = at + timedelta(milliseconds=2)
        record["stageTimestamp"] = stage.isoformat().replace("+00:00", "Z")

    return k8s_audit_events(base, mutate=mutate)


def _k8s002_bootstrap(d: str) -> dict[str, FixtureWriter]:
    out: dict[str, FixtureWriter] = {}
    live = captured_events(BIRTH_CAPTURE)
    birth = next(e for e in live if e.kubernetes and e.kubernetes.resource == "namespaces")
    t0 = birth.event_time
    super_admin = ("kubernetes-super-admin", ["system:masters", "system:authenticated"])
    crb_base = "rbac_crb_cluster_admin_create.json"
    rb_base = "rbac_rolebinding_anonymous_create.json"

    fx = FixtureWriter("k8s002-birth-live")
    fx.events.extend(live)
    out[f"{d}/negative_kubeadm_bootstrap_live.jsonl"] = fx

    # Inventory (state) view of the documented binding, as the K8s inventory collector
    # reports a non-baseline creation (event_time = creationTimestamp). SYNTHETIC record.
    admins_create = next(
        e for e in live if e.kubernetes and e.kubernetes.object_name == "kubeadm:cluster-admins"
    )

    def kubeadm_state(fx: FixtureWriter) -> None:
        fx.add(
            "k8s.resource.created",
            admins_create.event_time.replace(microsecond=0),
            asset=K8S,
            action="created",
            outcome="success",
            resource={"type": "clusterrolebindings", "name": "kubeadm:cluster-admins"},
            kubernetes={"cluster": "extorq-lab"},
            message="clusterrolebindings kubeadm:cluster-admins observed for the first time",
            attributes={
                "kind": "ClusterRoleBinding",
                "object_summary": admins_create.attributes["request_summary"],
                "risk_flags": ["cluster_admin"],
                "time_source": "creation_timestamp",
            },
        )

    fx = FixtureWriter("k8s002-birth-live-state")
    fx.events.extend(live)
    kubeadm_state(fx)
    out[f"{d}/negative_kubeadm_bootstrap_with_state.jsonl"] = fx

    fx = FixtureWriter("k8s002-state-only")
    fx.events.append(
        next(e for e in live if e.kubernetes and e.kubernetes.resource == "namespaces")
    )
    kubeadm_state(fx)
    out[f"{d}/positive_kubeadm_state_without_audit_create.jsonl"] = fx

    fx = FixtureWriter("k8s002-no-birth")
    fx.events.extend(
        e for e in live if e.kubernetes and e.kubernetes.object_name == "kubeadm:cluster-admins"
    )
    out[f"{d}/positive_kubeadm_create_no_birth.jsonl"] = fx

    out[f"{d}/negative_annotation_only_patch.jsonl"] = _derived(
        "k8s002-annotate", "rbac_crb_annotate_patch.json"
    )

    def labels_only(record: dict[str, Any]) -> None:
        record["auditID"] = str(uuid.uuid5(uuid.NAMESPACE_URL, "extorq-fixture:label-only-patch"))
        record["requestObject"] = {"metadata": {"labels": {"extorq.io/owner": "platform"}}}
        record["responseObject"]["metadata"]["labels"] = {"extorq.io/owner": "platform"}

    fx = FixtureWriter("k8s002-labels")
    fx.events.extend(k8s_audit_events("rbac_crb_annotate_patch.json", mutate=labels_only))
    out[f"{d}/positive_label_only_patch.jsonl"] = fx

    # Around the observed birth, each variant misses exactly one exception condition.
    fx = FixtureWriter("k8s002-exception-not-met")
    fx.events.append(birth)
    admins = [_subject("Group", "kubeadm:cluster-admins")]
    fx.events.extend(  # documented object and identity, but 15 minutes after the birth
        _rbac_create_variant(
            crb_base,
            at=t0 + 15 * M,
            name="kubeadm:cluster-admins",
            user=super_admin[0],
            groups=super_admin[1],
            subjects=admins,
            role_ref=("ClusterRole", "cluster-admin"),
        )
    )
    fx.events.extend(  # inside the window, bootstrap identity, look-alike name
        _rbac_create_variant(
            crb_base,
            at=t0 + 5 * S,
            name="kubeadm:cluster-admin",
            user=super_admin[0],
            groups=super_admin[1],
            subjects=admins,
            role_ref=("ClusterRole", "cluster-admin"),
        )
    )
    fx.events.extend(  # documented object inside the window, created by another identity
        _rbac_create_variant(
            rb_base,
            at=t0 + 3 * S,
            name="kubeadm:bootstrap-signer-clusterinfo",
            namespace="kube-public",
            user="system:serviceaccount:extorq-apps:default",
            groups=[
                "system:serviceaccounts",
                "system:serviceaccounts:extorq-apps",
                "system:authenticated",
            ],
            subjects=[_subject("User", "system:anonymous")],
            role_ref=("Role", "kubeadm:bootstrap-signer-clusterinfo"),
        )
    )
    out[f"{d}/positive_bootstrap_exception_not_met.jsonl"] = fx

    fx = FixtureWriter("k8s002-content-differs")
    fx.events.append(birth)
    fx.events.extend(  # documented name, identity and time, but an extra subject
        _rbac_create_variant(
            crb_base,
            at=t0 - 80 * S / 1000,
            name="kubeadm:cluster-admins",
            user=super_admin[0],
            groups=super_admin[1],
            subjects=[*admins, _subject("User", "mallory")],
            role_ref=("ClusterRole", "cluster-admin"),
        )
    )
    out[f"{d}/positive_bootstrap_content_differs.jsonl"] = fx
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


def _workflow_event(
    fx: FixtureWriter,
    t,
    sha: str,
    path: str,
    before: str | None,
    after: str | None,
    *,
    repo_default: str | None = "read",
    actor: str = "octo-dev",
    sim: dict[str, str] | None = None,
) -> None:
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
        github={
            "repository": "example-org/extorq-lab",
            "ref": "refs/heads/main",
            "commit_sha": sha,
            "workflow_path": path,
            "workflow_name": "ci",
            "actor_login": actor,
        },
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
    _workflow_event(
        fx,
        BASE,
        "1" * 40,
        path,
        WF_BASE,
        WF_BASE.replace("permissions:\n  contents: read", "permissions: write-all"),
    )
    out[f"{d}/positive_write_all.jsonl"] = fx

    fx = FixtureWriter("gh001-b")
    after = WF_BASE.replace(
        "on:\n  push:\n    branches: [main]",
        "on:\n  push:\n    branches: [main]\n  pull_request_target:",
    )
    _workflow_event(
        fx,
        BASE,
        "2" * 40,
        path,
        WF_BASE,
        after,
        actor="extorq-sim-fixture0gh001",
        sim={"run_id": "fixture0gh001", "scenario_id": "GH-001"},
    )
    out[f"{d}/positive_pull_request_target_sim.jsonl"] = fx

    fx = FixtureWriter("gh001-c")
    no_perms = WF_BASE.replace("permissions:\n  contents: read\n", "")
    with_oidc = WF_BASE.replace(
        "permissions:\n  contents: read", "permissions:\n  contents: read\n  id-token: write"
    )
    _workflow_event(
        fx, BASE, "3" * 40, ".github/workflows/deploy.yml", no_perms, with_oidc, repo_default=None
    )
    out[f"{d}/positive_scope_unknown_default.jsonl"] = fx

    fx = FixtureWriter("gh001-d")
    _workflow_event(
        fx, BASE, "4" * 40, path, WF_BASE, WF_BASE.replace("make test", "make lint test")
    )
    _workflow_event(
        fx,
        BASE + M,
        "5" * 40,
        path,
        WF_BASE,
        WF_BASE.replace(
            "permissions:\n  contents: read", "permissions:\n  contents: read\n  issues: read"
        ),
    )
    _workflow_event(
        fx,
        BASE + 2 * M,
        "6" * 40,
        path,
        WF_BASE,
        WF_BASE.replace("    branches: [main]", "    branches: [main, develop]\n  pull_request:"),
    )
    out[f"{d}/negative_benign_edits.jsonl"] = fx

    # Analyser >= 1.1.0 fails closed: an unparseable new version (here a duplicate
    # mapping key) is compared lexically with the old one (analysis = lexical_fallback).
    broken_escalation = WF_BASE.replace(
        "on:\n  push:\n    branches: [main]",
        "on:\n  push:\n    branches: [main]\n  pull_request_target:\n  push:\n    branches: [dev]",
    ).replace("permissions:\n  contents: read", "permissions: write-all")
    fx = FixtureWriter("gh001-lexical")
    _workflow_event(fx, BASE, "7" * 40, path, WF_BASE, broken_escalation)
    out[f"{d}/positive_lexical_fallback_write_all.jsonl"] = fx

    fx = FixtureWriter("gh001-lexical-benign")
    _workflow_event(fx, BASE, "8" * 40, path, WF_BASE, WF_BASE.replace("jobs:", "jobs:\njobs:"))
    out[f"{d}/negative_lexical_fallback_benign.jsonl"] = fx
    return out


# ── VM-002 (synthetic, catalog key_fields) ───────────────────────────


def _unit_event(
    fx: FixtureWriter,
    event_type: str,
    t,
    path: str,
    sha: str,
    *,
    prev: str | None = None,
    baseline: bool = False,
    sim: dict[str, str] | None = None,
) -> None:
    name = path.rsplit("/", 1)[-1]
    attrs: dict[str, object] = {
        "sha256": sha,
        "exec_start": "/bin/sh -c 'sleep infinity'",
        "vendor_unit": False,
    }
    if prev:
        attrs["previous_sha256"] = prev
    if baseline:
        attrs["baseline"] = True
    fields: dict[str, object] = {"simulation": sim} if sim else {}
    fx.add(
        event_type,
        t,
        asset=LINUX,
        action=event_type.rsplit(".", 1)[-1],
        outcome="success",
        resource={"type": "systemd_unit", "name": name, "path": path},
        message=f"systemd unit {name} {event_type.rsplit('_', 1)[-1]} (snapshot diff)",
        attributes=attrs,
        **fields,
    )


#: Name type of the primary PATH record as B1's auditd parser reports it (live values on
#: the lab VM: openat CREATE/NORMAL, unlinkat DELETE, fchmodat/fchownat/fsetxattr NORMAL).
_NAMETYPE_BY_SYSCALL = {"unlinkat": "DELETE", "unlink": "DELETE", "rmdir": "DELETE"}


def _audit_watch(
    fx: FixtureWriter,
    t,
    path: str | None,
    key: str,
    serial: int,
    sim: dict[str, str] | None = None,
    *,
    syscall: str = "openat",
    exe: str = "/usr/bin/tee",
    nametype: str | None = None,
    success: bool = True,
    paths: list[str] | None = None,
) -> None:
    """One auditd watch hit with the attribute shape of B1's parser (``linux/auditd.py``).

    ``path`` is the primary (first non-PARENT) PATH item, which B1 maps to
    ``resource.path``; ``paths`` lists every PATH item as ``NAMETYPE:/abs/path``.
    """
    nt = nametype or _NAMETYPE_BY_SYSCALL.get(
        syscall, "CREATE" if syscall in ("openat", "open", "creat") else "NORMAL"
    )
    if paths is None:
        if path is None:
            paths = [f"{nt}:?"]
        elif nt == "NORMAL":
            paths = [f"NORMAL:{path}"]
        else:
            paths = [f"PARENT:{path.rsplit('/', 1)[0]}/", f"{nt}:{path}"]
    fields: dict[str, object] = {"simulation": sim} if sim else {}
    if path is not None:
        fields["resource"] = {"type": "file", "path": path, "name": path.rsplit("/", 1)[-1]}
    fx.add(
        "file.audit.watch",
        t,
        asset=LINUX,
        action=f"audit.{syscall}",
        outcome="success" if success else "failure",
        process={"executable": exe, "name": exe.rsplit("/", 1)[-1], "pid": 7021},
        actor={"type": "user", "id": "1000"},
        message=f"auditd {key}: {syscall} {path or '?'} by 1000 via {exe.rsplit('/', 1)[-1]}",
        attributes={
            "audit_key": key,
            "syscall": syscall,
            "audit_serial": serial,
            "success": success,
            "exit_code": "0" if success else "-13",
            "nametype": nt,
            "paths": paths,
            "arch": "aarch64",
            "auid": 1000,
            "euid": 0 if success else 1000,
            "cwd": "/etc/systemd/system",
        },
        **fields,
    )


def _enabled(fx: FixtureWriter, t, unit: str, wanted_by: str = "multi-user.target") -> None:
    fx.add(
        "persistence.systemd.unit_enabled",
        t,
        asset=LINUX,
        action="unit_enabled",
        outcome="success",
        resource={"type": "systemd_unit", "name": unit},
        message=f"systemd unit {unit} enabled ({wanted_by})",
        attributes={"wanted_by": wanted_by},
    )


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
    tunnel = "/etc/systemd/system/ssh-tunnel.service"
    # None of these auditd hits create or modify the unit: they corroborate nothing.
    _audit_watch(
        fx, BASE - 30 * S, tunnel, "extorq_systemd", 813, syscall="unlinkat", exe="/usr/bin/rm"
    )
    _audit_watch(fx, BASE - 25 * S, tunnel, "extorq_systemd", 814, success=False, nametype="NORMAL")
    _audit_watch(
        fx, BASE - 20 * S, None, "extorq_systemd", 815, syscall="fsetxattr", exe="/usr/bin/install"
    )
    _audit_watch(fx, BASE - 15 * S, tunnel, "extorq_systemd", 816, syscall="276", exe="/usr/bin/mv")
    _unit_event(fx, "persistence.systemd.unit_modified", BASE, tunnel, "b" * 64, prev="c" * 64)
    out[f"{d}/positive_modified_inventory_only.jsonl"] = fx

    fx = FixtureWriter("vm002-rename")
    beacon = "/etc/systemd/system/beacon.service"
    _audit_watch(
        fx,
        BASE,
        "/tmp/beacon.service",
        "extorq_systemd",
        817,
        syscall="renameat",
        exe="/usr/bin/mv",
        nametype="DELETE",
        paths=[
            "PARENT:/tmp/",
            "PARENT:/etc/systemd/system/",
            "DELETE:/tmp/beacon.service",
            f"CREATE:{beacon}",
        ],
    )
    _unit_event(fx, "persistence.systemd.unit_created", BASE + 40 * S, beacon, "9" * 64)
    out[f"{d}/positive_renamed_into_place.jsonl"] = fx

    fx = FixtureWriter("vm002-c")
    _enabled(fx, BASE, "rsync.service")
    out[f"{d}/positive_enabled_only.jsonl"] = fx

    fx = FixtureWriter("vm002-d")
    _unit_event(
        fx,
        "persistence.systemd.unit_created",
        BASE,
        "/etc/systemd/system/nginx.service",
        "d" * 64,
        baseline=True,
    )
    _audit_watch(fx, BASE + S, "/etc/ssh/sshd_config", "extorq_sshd", 812)
    fx.add(
        "persistence.systemd.unit_deleted",
        BASE + 2 * S,
        asset=LINUX,
        action="unit_deleted",
        resource={
            "type": "systemd_unit",
            "name": "old.service",
            "path": "/etc/systemd/system/old.service",
        },
        message="systemd unit old.service deleted (snapshot diff)",
    )
    fx.add(
        "persistence.cron.changed",
        BASE + 3 * S,
        asset=LINUX,
        action="changed",
        resource={"path": "/etc/crontab"},
        attributes={"sha256": "e" * 64},
        message="cron configuration changed (snapshot diff)",
    )
    out[f"{d}/negative_baseline_and_unrelated.jsonl"] = fx
    return out


# ── CORR-002 (synthetic; nginx + sshd + systemd on one host) ─────────


def _corr002_sequence(
    fx: FixtureWriter,
    *,
    probe_ip: str,
    ssh_ip: str,
    unit: str,
    ssh_at: timedelta = 5 * M,
    persist_at: timedelta = 12 * M,
    sim: dict[str, str] | None = None,
    user: str = "admin",
    probe_routes: tuple[str, ...] | None = None,
    baseline: bool = False,
) -> None:
    kwargs = {"routes": probe_routes} if probe_routes is not None else {}
    http_probe(fx, BASE, probe_ip, simulation=sim, **kwargs)
    for i in range(4):
        ssh_failed_connection(
            fx, BASE + ssh_at + i * 9 * S, ssh_ip, 51000 + i, user, pid=5000 + i, simulation=sim
        )
    path = f"/etc/systemd/system/{unit}"
    if not baseline:
        _audit_watch(fx, BASE + persist_at, path, "extorq_systemd", 900, sim)
    _unit_event(
        fx,
        "persistence.systemd.unit_created",
        BASE + persist_at + 40 * S,
        path,
        "f" * 64,
        baseline=baseline,
        sim=sim,
    )


@builder
def corr002() -> dict[str, FixtureWriter]:
    d = "correlation/tests/CORR-002"
    out: dict[str, FixtureWriter] = {}

    fx = FixtureWriter("corr002-same-source")
    _corr002_sequence(fx, probe_ip="203.0.113.60", ssh_ip="203.0.113.60", unit="backdoor.service")
    out[f"{d}/positive_same_external_source.jsonl"] = fx

    fx = FixtureWriter("corr002-nat-sim")
    sim = {"run_id": "fixture0corr002", "scenario_id": "CORR-002"}
    _corr002_sequence(
        fx,
        probe_ip="10.0.2.2",
        ssh_ip="10.0.2.2",
        unit="extorq-sim-fixture0corr002.service",
        sim=sim,
        user="extorq-sim-fixture0corr002",
    )
    out[f"{d}/positive_nat_gateway_sim.jsonl"] = fx

    fx = FixtureWriter("corr002-different-sources")
    _corr002_sequence(fx, probe_ip="198.51.100.20", ssh_ip="203.0.113.61", unit="updater.service")
    out[f"{d}/positive_different_sources.jsonl"] = fx

    fx = FixtureWriter("corr002-wrong-order")
    _corr002_sequence(
        fx,
        probe_ip="203.0.113.62",
        ssh_ip="203.0.113.62",
        unit="early.service",
        ssh_at=10 * M,
        persist_at=3 * M,
    )
    out[f"{d}/negative_wrong_order.jsonl"] = fx

    fx = FixtureWriter("corr002-too-slow")
    _corr002_sequence(
        fx,
        probe_ip="203.0.113.63",
        ssh_ip="203.0.113.63",
        unit="late.service",
        ssh_at=10 * M,
        persist_at=40 * M,
    )
    out[f"{d}/negative_too_slow.jsonl"] = fx

    fx = FixtureWriter("corr002-baseline")
    _corr002_sequence(
        fx, probe_ip="203.0.113.64", ssh_ip="203.0.113.64", unit="nginx.service", baseline=True
    )
    out[f"{d}/negative_missing_stage_baseline.jsonl"] = fx

    fx = FixtureWriter("corr002-below-probe")
    _corr002_sequence(
        fx,
        probe_ip="203.0.113.65",
        ssh_ip="203.0.113.65",
        unit="quiet.service",
        probe_routes=("/.env", "/.git/config", "/wp-login.php", "/admin.php"),
    )
    nginx_request(fx, BASE + 30 * S, "203.0.113.65", "/", 200)
    nginx_request(fx, BASE + 31 * S, "203.0.113.65", "/favicon.ico", 404)
    out[f"{d}/negative_below_probe_threshold.jsonl"] = fx

    fx = FixtureWriter("corr002-deletion")
    http_probe(fx, BASE, "203.0.113.66")
    for i in range(4):
        ssh_failed_connection(fx, BASE + 5 * M + i * 9 * S, "203.0.113.66", 51100 + i, "admin")
    _audit_watch(
        fx,
        BASE + 12 * M,
        "/etc/systemd/system/old-agent.service",
        "extorq_systemd",
        901,
        syscall="unlinkat",
        exe="/usr/bin/rm",
    )
    out[f"{d}/negative_deletion_only.jsonl"] = fx

    # auditd hits that neither create nor modify a unit file: none of them is stage 3.
    fx = FixtureWriter("corr002-noncounting")
    http_probe(fx, BASE, "203.0.113.68")
    for i in range(4):
        ssh_failed_connection(fx, BASE + 5 * M + i * 9 * S, "203.0.113.68", 51200 + i, "admin")
    evil = "/etc/systemd/system/evil.service"
    _audit_watch(fx, BASE + 10 * M, evil, "extorq_systemd", 910, success=False, nametype="NORMAL")
    _audit_watch(
        fx, BASE + 11 * M, None, "extorq_systemd", 911, syscall="fsetxattr", exe="/usr/bin/install"
    )
    _audit_watch(fx, BASE + 12 * M, "/etc/systemd/system/.evil.service.swp", "extorq_systemd", 912)
    _audit_watch(fx, BASE + 13 * M, evil, "extorq_systemd", 913, syscall="56")
    _audit_watch(
        fx,
        BASE + 14 * M,
        "/etc/systemd/system/old.service",
        "extorq_systemd",
        914,
        syscall="renameat",
        exe="/usr/bin/mv",
        nametype="DELETE",
        paths=[
            "PARENT:/etc/systemd/system/",
            "PARENT:/tmp/",
            "DELETE:/etc/systemd/system/old.service",
            "CREATE:/tmp/old.service",
        ],
    )
    out[f"{d}/negative_noncounting_audit_hits.jsonl"] = fx

    # Persistence seen by auditd only, plus a removal of another unit (context only).
    fx = FixtureWriter("corr002-removal-context")
    http_probe(fx, BASE, "203.0.113.69")
    for i in range(4):
        ssh_failed_connection(fx, BASE + 5 * M + i * 9 * S, "203.0.113.69", 51300 + i, "admin")
    _audit_watch(fx, BASE + 12 * M, "/etc/systemd/system/beacon.service", "extorq_systemd", 920)
    _audit_watch(
        fx,
        BASE + 13 * M,
        "/etc/systemd/system/old-agent.service",
        "extorq_systemd",
        921,
        syscall="unlinkat",
        exe="/usr/bin/rm",
    )
    out[f"{d}/positive_audit_create_removal_context.jsonl"] = fx
    return out


# ── HTTP-001 (synthetic nginx access lines) ──────────────────────────


@builder
def http001() -> dict[str, FixtureWriter]:
    d = "http/tests/HTTP-001"
    out: dict[str, FixtureWriter] = {}

    fx = FixtureWriter("http001-external")
    http_probe(fx, BASE, "203.0.113.70")
    out[f"{d}/positive_external_probe.jsonl"] = fx

    # Shape of B1's simulations/http/http_probe.sh (6 probe paths + 5 failed logins).
    fx = FixtureWriter("http001-b1-shape")
    sim = {"run_id": "fixture0http01", "scenario_id": "HTTP-001"}
    paths = ("/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/server-status")
    for i, route in enumerate(paths):
        nginx_request(fx, BASE + i * S, "10.0.2.2", route, 404, simulation=sim)
    nginx_request(fx, BASE + 6 * S, "10.0.2.2", "/admin", 401, simulation=sim)
    for i in range(5):
        nginx_request(
            fx, BASE + (8 + i) * S, "10.0.2.2", "/login", 401, method="POST", simulation=sim
        )
    out[f"{d}/positive_nat_b1_shape_sim.jsonl"] = fx

    fx = FixtureWriter("http001-ordinary")
    ordinary = (
        "/favicon.ico",
        "/static/app.css",
        "/images/logo.png",
        "/about",
        "/blog/2026",
        "/robots.txt",
        "/apple-touch-icon.png",
        "/docs/start",
        "/news",
        "/team",
        "/static/app.js",
        "/contact",
    )
    http_probe(fx, BASE, "203.0.113.71", routes=ordinary)
    out[f"{d}/negative_ordinary_404.jsonl"] = fx

    fx = FixtureWriter("http001-slow")
    http_probe(fx, BASE, "203.0.113.72", spacing_s=150.0)
    out[f"{d}/negative_slow_probe.jsonl"] = fx
    return out


# ── MAC-001 (synthetic launchd diffs, attribute set of B3's collector) ─


def _launchd(
    fx: FixtureWriter,
    event_type: str,
    t,
    path: str,
    attrs: dict[str, object],
    sim: dict[str, str] | None = None,
) -> None:
    label = attrs.get("label")
    fields: dict[str, object] = {"simulation": sim} if sim else {}
    change = event_type.rsplit("_", 1)[-1]
    fx.add(
        event_type,
        t,
        asset=MACOS,
        source_type="macos.launchd",
        action=f"launchd_item_{change}",
        outcome="success",
        resource={"type": "launchd_plist", "name": label or path.rsplit("/", 1)[-1], "path": path},
        message=f"launchd plist {change}: {path} (synthetic fixture)",
        attributes={k: v for k, v in attrs.items() if v is not None},
        **fields,
    )


@builder
def mac001() -> dict[str, FixtureWriter]:
    d = "macos/tests/MAC-001"
    out: dict[str, FixtureWriter] = {}

    fx = FixtureWriter("mac001-sim")
    label = "com.extorq.sim.fixture0mac001"
    _launchd(
        fx,
        "persistence.launchd.item_created",
        BASE,
        f"/Users/labuser/Library/LaunchAgents/{label}.plist",
        {
            "label": label,
            "program": "/usr/bin/true",
            "run_at_load": False,
            "sha256": "a" * 64,
            "size": 412,
            "mode": "0600",
            "owner_uid": 501,
            "world_writable": False,
            "scope": "user",
            "kind": "agent",
            "allowlisted": False,
        },
        sim={"run_id": "fixture0mac001", "scenario_id": "MAC-001"},
    )
    out[f"{d}/positive_user_agent_created_sim.jsonl"] = fx

    fx = FixtureWriter("mac001-daemon")
    _launchd(
        fx,
        "persistence.launchd.item_modified",
        BASE,
        "/Library/LaunchDaemons/com.example.helper.plist",
        {
            "sha256": "b" * 64,
            "previous_sha256": "c" * 64,
            "size": 97,
            "scope": "system",
            "kind": "daemon",
            "allowlisted": False,
            "parse_error": "plist could not be parsed",
        },
    )
    out[f"{d}/positive_daemon_modified_unparseable.jsonl"] = fx

    fx = FixtureWriter("mac001-negative")
    _launchd(
        fx,
        "persistence.launchd.item_created",
        BASE,
        "/Users/labuser/Library/LaunchAgents/com.google.keystone.agent.plist",
        {
            "label": "com.google.keystone.agent",
            "program": "/Users/labuser/Library/Google/x",
            "run_at_load": True,
            "sha256": "d" * 64,
            "scope": "user",
            "kind": "agent",
            "allowlisted": True,
        },
    )
    _launchd(
        fx,
        "persistence.launchd.item_deleted",
        BASE + M,
        "/Users/labuser/Library/LaunchAgents/com.example.old.plist",
        {"label": "com.example.old", "scope": "user", "kind": "agent", "previous_sha256": "e" * 64},
    )
    out[f"{d}/negative_allowlisted_and_deleted.jsonl"] = fx
    return out


# ── APP-001 (synthetic lab-portal auth events, B1 log contract) ──────


def _app_login_failed(
    fx: FixtureWriter,
    t,
    user: str,
    ip: str,
    *,
    k8s: bool = False,
    reason: str = "invalid_password",
    sim: dict[str, str] | None = None,
) -> None:
    fields: dict[str, object] = {"simulation": sim} if sim else {}
    if k8s:
        fields["kubernetes"] = {
            "cluster": "extorq-lab",
            "namespace": "extorq-apps",
            "pod_name": "lab-portal-7c9d8f6b5-x2x4q",
            "pod_uid": "0f6e2c1a-9a8b-4c3d-8e7f-112233445566",
            "container_name": "lab-portal",
            "workload_kind": "Deployment",
            "workload_name": "lab-portal",
        }
    fx.add(
        "app.auth.login_failed",
        t,
        asset=K8S if k8s else LINUX,
        source_type="k8s.container_log" if k8s else "linux.app",
        action="login",
        outcome="failure",
        actor={"type": "user", "name": user},
        network={"src_ip": ip},
        http={"method": "POST", "route": "/login", "status_code": 401},
        message=f"login failed for {user} ({reason})",
        attributes={"reason": reason, "service": "lab-portal", "request_id_source": "generated"},
        **fields,
    )


@builder
def app001() -> dict[str, FixtureWriter]:
    d = "app/tests/APP-001"
    out: dict[str, FixtureWriter] = {}

    fx = FixtureWriter("app001-guessing")
    sim = {"run_id": "fixture0app001", "scenario_id": "HTTP-001"}
    for i in range(5):
        _app_login_failed(fx, BASE + i * S, "lab-admin", "10.0.2.2", sim=sim)
    out[f"{d}/positive_guessing_nat_sim.jsonl"] = fx

    fx = FixtureWriter("app001-spraying")
    for i, user in enumerate(["admin", "root", "test", "guest", "lab-admin", "operator"]):
        _app_login_failed(
            fx,
            BASE + i * 3 * S,
            user,
            "203.0.113.80",
            k8s=True,
            reason="unknown_user" if user != "lab-admin" else "invalid_password",
        )
    out[f"{d}/positive_spraying_k8s.jsonl"] = fx

    fx = FixtureWriter("app001-negative")
    for i in range(4):
        _app_login_failed(fx, BASE + i * 5 * S, "lab-admin", "203.0.113.81")
    for i in range(6):
        _app_login_failed(fx, BASE + 10 * M + i * 6 * M, "alice", "203.0.113.82")
    out[f"{d}/negative_below_and_slow.jsonl"] = fx
    return out


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", action="append", help="builder name, e.g. corr002 (repeatable)")
    args = parser.parse_args(argv)
    selected = [b for b in BUILDERS if not args.only or b.__name__ in set(args.only)]
    written = 0
    for build in selected:
        for rel, fx in build().items():
            fx.write(ROOT / rel)
            written += 1
            print(f"wrote {rel} ({len(fx.events)} synthetic events)")
    print(f"{written} fixture files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
