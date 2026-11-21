"""Lab trust-boundary invariants: Kubernetes manifests (B2) and the VM launcher (B1).

Kubernetes (``infra/kind/**``; simulations under ``simulations/`` are excluded
because they deliberately create risky objects):

* RBAC never grants wildcards, ``secrets``, ``escalate``/``bind``/``impersonate``,
  exec/attach/port-forward, token creation, or broad write verbs.
* No binding to ``cluster-admin``/``admin``/``edit``.
* Workloads: no ``privileged``, host namespaces, container-runtime sockets or
  writable host paths outside ``/var/lib`` state directories; privilege
  escalation disabled. Running as root or mounting host paths needs an
  ``extorq.io/accepted-risk`` annotation (the node log collector case).
* The API audit policy never records request/response bodies for Secrets,
  TokenRequests or TokenReviews (those bodies carry credentials).
* The kind cluster's API server and every host port mapping bind 127.0.0.1
  (kind's default ``listenAddress`` is 0.0.0.0).

VM (``infra/vm/**``, ``scripts/**``, ``Makefile``):

* Every QEMU ``hostfwd=`` binds 127.0.0.1 explicitly (QEMU's default host
  address is all interfaces).
"""

from __future__ import annotations

import re
import warnings
from typing import Any

import pytest
from security_helpers import (
    REPO_ROOT,
    format_findings,
    iter_files,
    load_yaml_documents,
    read_text,
    rel,
)

KIND_ROOT = "infra/kind"
ACCEPTED_RISK = "extorq.io/accepted-risk"
POSTURE_LAB_LABEL = "extorq.io/purpose"

WORKLOAD_KINDS = frozenset(
    {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}
)
FORBIDDEN_VERBS = frozenset({"escalate", "bind", "impersonate"})
WRITE_VERBS = frozenset({"create", "update", "patch", "delete", "deletecollection"})
FORBIDDEN_RESOURCES = frozenset(
    {
        "secrets",
        "pods/exec",
        "pods/attach",
        "pods/portforward",
        "serviceaccounts/token",
        "nodes/proxy",
        "certificatesigningrequests/approval",
    }
)
#: (apiGroup, resource) pairs where write verbs are acceptable for collectors.
WRITE_ALLOWED = frozenset(
    {("coordination.k8s.io", "leases"), ("", "events"), ("events.k8s.io", "events")}
)
FORBIDDEN_ROLEREFS = frozenset({"cluster-admin", "admin", "edit"})
RUNTIME_SOCKETS = ("docker.sock", "containerd.sock", "crio.sock", "cri-dockerd.sock")


def _kind_documents() -> list[tuple[str, dict[str, Any]]]:
    docs: list[tuple[str, dict[str, Any]]] = []
    for path in sorted(iter_files(suffixes=(".yaml", ".yml"), roots=(KIND_ROOT,))):
        try:
            loaded = load_yaml_documents(path)
        except Exception as exc:  # noqa: BLE001 - report unparsable manifests as findings
            docs.append((rel(path), {"__parse_error__": type(exc).__name__}))
            continue
        docs.extend((rel(path), d) for d in loaded if isinstance(d, dict))
    return docs


KIND_DOCS = _kind_documents()
requires_kind = pytest.mark.skipif(
    not KIND_DOCS, reason="infra/kind manifests not present yet (owner: B2)"
)


def _name(doc: dict[str, Any]) -> str:
    meta = doc.get("metadata") or {}
    return f"{doc.get('kind')}/{meta.get('namespace', '-')}/{meta.get('name', '?')}"


# ── RBAC ─────────────────────────────────────────────────────────────────────


def rbac_rule_problems(rule: dict[str, Any], where: str) -> list[str]:
    problems: list[str] = []
    verbs = {str(v) for v in rule.get("verbs") or []}
    resources = {str(r) for r in rule.get("resources") or []}
    groups = {str(g) for g in rule.get("apiGroups") or []}
    if "*" in verbs or "*" in resources or "*" in groups:
        problems.append(f"{where}: wildcard in verbs/resources/apiGroups")
    if rule.get("nonResourceURLs") and "*" in {str(u) for u in rule.get("nonResourceURLs") or []}:
        problems.append(f"{where}: wildcard nonResourceURLs")
    if verbs & FORBIDDEN_VERBS:
        problems.append(f"{where}: forbidden verbs {sorted(verbs & FORBIDDEN_VERBS)}")
    if resources & FORBIDDEN_RESOURCES:
        problems.append(f"{where}: forbidden resources {sorted(resources & FORBIDDEN_RESOURCES)}")
    write = verbs & WRITE_VERBS
    if write:
        for group in groups or {""}:
            for resource in resources:
                if (group, resource) not in WRITE_ALLOWED:
                    problems.append(
                        f"{where}: write verbs {sorted(write)} on {group or 'core'}/{resource}"
                    )
    return problems


@requires_kind
def test_rbac_is_read_only_and_never_touches_secrets() -> None:
    problems: list[str] = []
    for path, doc in KIND_DOCS:
        kind = doc.get("kind")
        if kind in {"Role", "ClusterRole"}:
            if doc.get("aggregationRule"):
                problems.append(f"{path} {_name(doc)}: aggregated roles are not allowed")
            for index, rule in enumerate(doc.get("rules") or []):
                problems.extend(rbac_rule_problems(rule or {}, f"{path} {_name(doc)} rule {index}"))
        if kind in {"RoleBinding", "ClusterRoleBinding"}:
            ref = (doc.get("roleRef") or {}).get("name")
            if ref in FORBIDDEN_ROLEREFS:
                problems.append(f"{path} {_name(doc)}: binds built-in role {ref}")
    assert not problems, format_findings(problems)


# ── workloads ────────────────────────────────────────────────────────────────


def _pod_spec(doc: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (pod_spec, pod_metadata) for any workload kind."""
    kind = doc.get("kind")
    if kind == "Pod":
        return doc.get("spec") or {}, doc.get("metadata") or {}
    spec = doc.get("spec") or {}
    if kind == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec")) or {}
    template = spec.get("template") or {}
    return template.get("spec") or {}, template.get("metadata") or {}


def is_posture_lab(doc: dict[str, Any]) -> bool:
    """Deliberately weak lab targets for the posture scanner (B2), labelled explicitly."""
    labels = (doc.get("metadata") or {}).get("labels") or {}
    return labels.get(POSTURE_LAB_LABEL) == "posture-lab"


def workload_problems(doc: dict[str, Any], where: str) -> list[str]:
    """Problems for a workload. Posture-lab targets skip the hardening tier only."""
    problems: list[str] = []
    pod, pod_meta = _pod_spec(doc)
    annotations = {
        **((doc.get("metadata") or {}).get("annotations") or {}),
        **(pod_meta.get("annotations") or {}),
    }
    lab_target = is_posture_lab(doc)
    # Deliberately weak lab targets may run as root / mount read-only host paths so the
    # posture scanner has genuine findings; they are still held to the "never" tier.
    accepted = bool(str(annotations.get(ACCEPTED_RISK, "")).strip()) or lab_target
    for key in ("hostNetwork", "hostPID", "hostIPC"):
        if pod.get(key):
            problems.append(f"{where}: {key}: true")
    pod_sc = pod.get("securityContext") or {}
    host_paths = {
        v.get("name"): str((v.get("hostPath") or {}).get("path", ""))
        for v in pod.get("volumes") or []
        if isinstance(v, dict) and v.get("hostPath")
    }
    if host_paths and not accepted:
        problems.append(f"{where}: hostPath volumes require an '{ACCEPTED_RISK}' annotation")
    for host_path in host_paths.values():
        if any(sock in host_path for sock in RUNTIME_SOCKETS) or host_path.rstrip("/") in {
            "",
            "/var/run",
            "/run",
        }:
            problems.append(
                f"{where}: hostPath {host_path!r} exposes the node or container runtime"
            )
    containers = list(pod.get("initContainers") or []) + list(pod.get("containers") or [])
    for container in containers:
        container = container or {}
        cname = container.get("name", "?")
        sc = container.get("securityContext") or {}
        if sc.get("privileged"):
            problems.append(f"{where} container {cname}: privileged: true")
        if sc.get("allowPrivilegeEscalation") is not False and not lab_target:
            problems.append(f"{where} container {cname}: allowPrivilegeEscalation must be false")
        drop = {str(c).upper() for c in ((sc.get("capabilities") or {}).get("drop") or [])}
        if "ALL" not in drop and not lab_target:
            problems.append(f"{where} container {cname}: capabilities.drop must include ALL")
        add = {str(c).upper() for c in ((sc.get("capabilities") or {}).get("add") or [])}
        if add & {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"}:
            problems.append(f"{where} container {cname}: dangerous capabilities {sorted(add)}")
        run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
        run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
        if (run_as_non_root is not True or run_as_user == 0) and not accepted:
            problems.append(
                f"{where} container {cname}: must set runAsNonRoot: true "
                "(or document accepted risk)"
            )
        for mount in container.get("volumeMounts") or []:
            host_path = host_paths.get((mount or {}).get("name"))
            if host_path is None:
                continue
            if not mount.get("readOnly") and not host_path.startswith("/var/lib/"):
                problems.append(
                    f"{where} container {cname}: hostPath {host_path!r} mounted writable "
                    "(only /var/lib/* state directories may be writable)"
                )
    return problems


@requires_kind
def test_infrastructure_workloads_are_hardened() -> None:
    problems: list[str] = []
    lab_targets: list[str] = []
    for path, doc in KIND_DOCS:
        if "__parse_error__" in doc:
            problems.append(f"{path}: YAML parse error {doc['__parse_error__']}")
            continue
        if doc.get("kind") in WORKLOAD_KINDS:
            problems.extend(workload_problems(doc, f"{path} {_name(doc)}"))
            if is_posture_lab(doc):
                lab_targets.append(f"{path} {_name(doc)}")
    if lab_targets:
        warnings.warn(
            "deliberately weak posture-lab workloads (hardening tier skipped):\n"
            + format_findings(lab_targets),
            stacklevel=1,
        )
    assert not problems, format_findings(problems)


# ── audit policy ─────────────────────────────────────────────────────────────

SENSITIVE_AUDIT_TARGETS = (
    ("", "secrets"),
    ("", "serviceaccounts/token"),
    ("authentication.k8s.io", "tokenreviews"),
)
SAFE_AUDIT_LEVELS = frozenset({"None", "Metadata"})


def _resource_matches(entry: dict[str, Any], group: str, resource: str) -> bool:
    if str(entry.get("group", "")) not in {group, "*"}:
        return False
    listed = [str(r) for r in entry.get("resources") or []]
    if not listed:
        return True  # all resources of the group
    base, _, sub = resource.partition("/")
    for item in listed:
        item_base, _, item_sub = item.partition("/")
        if item == "*" or item == resource:
            return True
        if sub and item_base in {base, "*"} and item_sub in {sub, "*"}:
            return True
    return False


def audit_policy_problems(policy: dict[str, Any], where: str) -> list[str]:
    problems: list[str] = []
    rules = policy.get("rules") or []
    for group, resource in SENSITIVE_AUDIT_TARGETS:
        for index, rule in enumerate(rules):
            rule = rule or {}
            if rule.get("nonResourceURLs"):
                continue
            entries = rule.get("resources")
            if entries:
                matching = [e for e in entries if _resource_matches(e or {}, group, resource)]
                if not matching:
                    continue
                partial = any((e or {}).get("resourceNames") for e in matching)
            else:
                partial = False
            level = str(rule.get("level", ""))
            if level not in SAFE_AUDIT_LEVELS:
                problems.append(
                    f"{where} rule {index}: {group or 'core'}/{resource} may be logged at "
                    f"level {level} "
                    "(bodies contain credentials; use Metadata or None)"
                )
            conditional = partial or any(
                rule.get(k) for k in ("users", "userGroups", "verbs", "namespaces")
            )
            if not conditional:
                break  # this rule decides every remaining request for the resource
    return problems


def _audit_policies() -> list[tuple[str, dict[str, Any]]]:
    return [
        (p, d)
        for p, d in KIND_DOCS
        if d.get("kind") == "Policy" and str(d.get("apiVersion", "")).startswith("audit.k8s.io/")
    ]


@requires_kind
def test_audit_policy_never_logs_credential_bodies() -> None:
    policies = _audit_policies()
    if not policies:
        pytest.skip("no audit.k8s.io Policy in infra/kind yet")
    problems: list[str] = []
    for path, policy in policies:
        problems.extend(audit_policy_problems(policy, path))
    assert not problems, format_findings(problems)


# ── kind cluster config ──────────────────────────────────────────────────────


@requires_kind
def test_kind_cluster_binds_loopback_only() -> None:
    clusters = [
        (p, d)
        for p, d in KIND_DOCS
        if d.get("kind") == "Cluster" and "kind.x-k8s.io" in str(d.get("apiVersion"))
    ]
    if not clusters:
        pytest.skip("no kind Cluster config in infra/kind yet")
    problems: list[str] = []
    for path, cluster in clusters:
        address = (cluster.get("networking") or {}).get("apiServerAddress")
        if address not in (None, "127.0.0.1"):
            problems.append(f"{path}: networking.apiServerAddress is {address!r}")
        for node in cluster.get("nodes") or []:
            for mapping in (node or {}).get("extraPortMappings") or []:
                if (mapping or {}).get("listenAddress") != "127.0.0.1":
                    problems.append(
                        f"{path}: extraPortMappings hostPort {mapping.get('hostPort')} must set "
                        "listenAddress: 127.0.0.1 (kind defaults to 0.0.0.0)"
                    )
    assert not problems, format_findings(problems)


# ── VM launcher ──────────────────────────────────────────────────────────────

HOSTFWD = re.compile(r"hostfwd=(?P<proto>tcp|udp)?:(?P<addr>[^:,\s\"']*):")
SHELL_ASSIGN = re.compile(
    r"^\s*(?:export\s+|readonly\s+|local\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>\S*)"
)
SHELL_VAR = re.compile(r"^\$\{?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}?$")


def _fixed_shell_values(text: str) -> dict[str, set[str]]:
    """Values assigned to shell variables; anything containing ``$`` is non-literal."""
    values: dict[str, set[str]] = {}
    for line in text.splitlines():
        match = SHELL_ASSIGN.match(line)
        if match:
            value = match.group("value").strip("\"'")
            values.setdefault(match.group("name"), set()).add(value)
    return values


def hostfwd_problems(text: str, relative: str) -> list[str]:
    """A forward is safe only if its host address is literally 127.0.0.1, or a shell
    variable whose every assignment in the same file is the literal 127.0.0.1
    (an env-overridable default such as ``${X:-127.0.0.1}`` is flagged)."""
    problems: list[str] = []
    fixed = _fixed_shell_values(text)
    for number, line in enumerate(text.splitlines(), start=1):
        for match in HOSTFWD.finditer(line):
            addr = match.group("addr")
            variable = SHELL_VAR.match(addr)
            if variable:
                assigned = fixed.get(variable.group("name"), set())
                if assigned == {"127.0.0.1"}:
                    continue
            if addr != "127.0.0.1":
                problems.append(f"{relative}:{number}: QEMU hostfwd must bind 127.0.0.1 explicitly")
    return problems


def _vm_launch_sources() -> list:
    files = list(iter_files(roots=("infra/vm", "scripts")))
    makefile = REPO_ROOT / "Makefile"
    if makefile.exists():
        files.append(makefile)
    return [p for p in files if p.suffix not in {".qcow2", ".img", ".iso", ".fd"}]


def test_qemu_port_forwards_bind_loopback() -> None:
    sources = _vm_launch_sources()
    if not sources:
        pytest.skip("infra/vm and scripts not present yet (owner: B1/A)")
    problems: list[str] = []
    for path in sources:
        try:
            text = read_text(path)
        except UnicodeDecodeError:
            continue
        problems.extend(hostfwd_problems(text, rel(path)))
    assert not problems, format_findings(problems)


# ── self-tests ───────────────────────────────────────────────────────────────


def test_rbac_checker() -> None:
    assert rbac_rule_problems({"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}, "r")
    assert rbac_rule_problems({"apiGroups": ["*"], "resources": ["pods"], "verbs": ["list"]}, "r")
    assert rbac_rule_problems(
        {
            "apiGroups": ["rbac.authorization.k8s.io"],
            "resources": ["clusterroles"],
            "verbs": ["bind"],
        },
        "r",
    )
    assert rbac_rule_problems({"apiGroups": [""], "resources": ["pods"], "verbs": ["delete"]}, "r")
    assert not rbac_rule_problems(
        {
            "apiGroups": ["", "apps"],
            "resources": ["pods", "deployments"],
            "verbs": ["get", "list", "watch"],
        },
        "r",
    )
    assert not rbac_rule_problems(
        {
            "apiGroups": ["coordination.k8s.io"],
            "resources": ["leases"],
            "verbs": ["create", "update"],
        },
        "r",
    )


def test_audit_policy_checker() -> None:
    unsafe = {"rules": [{"level": "RequestResponse"}]}
    assert len(audit_policy_problems(unsafe, "p")) == 3
    safe = {
        "rules": [
            {
                "level": "Metadata",
                "resources": [{"group": "", "resources": ["secrets", "serviceaccounts/token"]}],
            },
            {
                "level": "Metadata",
                "resources": [{"group": "authentication.k8s.io", "resources": ["tokenreviews"]}],
            },
            {"level": "RequestResponse", "resources": [{"group": "rbac.authorization.k8s.io"}]},
            {"level": "Request"},
        ]
    }
    assert audit_policy_problems(safe, "p") == []
    # A conditional safe rule does not protect requests it does not match.
    conditional = {
        "rules": [
            {
                "level": "Metadata",
                "users": ["admin"],
                "resources": [{"group": "", "resources": ["secrets"]}],
            },
            {"level": "Request"},
        ]
    }
    assert audit_policy_problems(conditional, "p")


def test_workload_checker() -> None:
    privileged = {
        "kind": "DaemonSet",
        "metadata": {"name": "x"},
        "spec": {
            "template": {
                "spec": {
                    "hostNetwork": True,
                    "containers": [{"name": "c", "securityContext": {"privileged": True}}],
                }
            }
        },
    }
    joined = "\n".join(workload_problems(privileged, "w"))
    assert "hostNetwork" in joined and "privileged" in joined and "runAsNonRoot" in joined
    collector = {
        "kind": "DaemonSet",
        "metadata": {"name": "otel", "annotations": {ACCEPTED_RISK: "reads node log files"}},
        "spec": {
            "template": {
                "spec": {
                    "volumes": [
                        {"name": "pods", "hostPath": {"path": "/var/log/pods"}},
                        {"name": "queue", "hostPath": {"path": "/var/lib/otelcol"}},
                    ],
                    "containers": [
                        {
                            "name": "otel",
                            "securityContext": {
                                "runAsUser": 0,
                                "allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"]},
                            },
                            "volumeMounts": [
                                {"name": "pods", "mountPath": "/var/log/pods", "readOnly": True},
                                {"name": "queue", "mountPath": "/var/lib/otelcol"},
                            ],
                        }
                    ],
                }
            }
        },
    }
    assert workload_problems(collector, "w") == []
    collector["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = False
    assert workload_problems(collector, "w")


def test_posture_lab_targets_still_obey_never_tier() -> None:
    weak = {
        "kind": "Deployment",
        "metadata": {"name": "weak", "labels": {POSTURE_LAB_LABEL: "posture-lab"}},
        "spec": {
            "template": {
                "spec": {
                    "securityContext": {"runAsUser": 0},
                    "volumes": [{"name": "logs", "hostPath": {"path": "/var/log"}}],
                    "containers": [
                        {
                            "name": "c",
                            "volumeMounts": [{"name": "logs", "mountPath": "/h", "readOnly": True}],
                        }
                    ],
                }
            }
        },
    }
    assert workload_problems(weak, "w") == []
    weak["spec"]["template"]["spec"]["hostPID"] = True
    assert workload_problems(weak, "w")
    weak["spec"]["template"]["spec"].pop("hostPID")
    weak["spec"]["template"]["spec"]["containers"][0]["securityContext"] = {"privileged": True}
    assert workload_problems(weak, "w")


def test_hostfwd_checker() -> None:
    fixed = 'SSH_HOST="127.0.0.1"\nqemu -netdev "user,hostfwd=tcp:${SSH_HOST}:2222-:22"\n'
    assert not hostfwd_problems(fixed, "x")
    overridable = (
        'SSH_HOST="${EXTORQ_HOST:-127.0.0.1}"\n'
        'qemu -netdev "user,hostfwd=tcp:${SSH_HOST}:2222-:22"\n'
    )
    assert hostfwd_problems(overridable, "x")
    assert hostfwd_problems("qemu -netdev user,hostfwd=tcp:${UNSET}:2222-:22", "x")
    assert hostfwd_problems("-netdev user,id=n0,hostfwd=tcp::2222-:22", "x")
    assert hostfwd_problems("-netdev user,id=n0,hostfwd=tcp:0.0.0.0:2222-:22", "x")
    assert not hostfwd_problems(
        "-netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:8088-:80", "x"
    )
