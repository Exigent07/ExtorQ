"""Check the guarantees of infra/kind/audit-policy.yaml against the REAL audit log.

Usage (wrapped by ``infra/kind/kind.sh audit-check``)::

    docker exec extorq-lab-control-plane cat /var/log/kubernetes/audit/kube-apiserver-audit.log \
        | python3 -I infra/kind/audit_check.py

Reads JSON lines on stdin (untrusted: parsed with json only, never evaluated) and prints
counts per (resource, verb class, level) plus every policy violation. It never prints
request/response bodies. Exit 0 when no violation was found, 1 otherwise, 2 on bad input.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from typing import Any

WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}
NO_BODY = {("", "secrets"), ("", "configmaps"), ("authentication.k8s.io", "tokenreviews")}
RBAC = {"roles", "rolebindings", "clusterroles", "clusterrolebindings"}
SYSTEM_READERS = {
    "system:kube-scheduler",
    "system:kube-controller-manager",
    "system:kube-proxy",
    "system:apiserver",
}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def violations_for(event: dict[str, Any]) -> list[str]:
    out: list[str] = []
    ref = _dict(event.get("objectRef"))
    group = str(ref.get("apiGroup") or "")
    resource = str(ref.get("resource") or "")
    sub = str(ref.get("subresource") or "")
    verb = str(event.get("verb") or "")
    level = event.get("level")
    user = _dict(event.get("user"))
    name = str(user.get("username") or "")
    raw_groups = user.get("groups")
    groups: list[Any] = raw_groups if isinstance(raw_groups, list) else []
    has_body = "requestObject" in event or "responseObject" in event
    if event.get("stage") == "RequestReceived":
        out.append("RequestReceived stage present (omitStages)")
    if ((group, resource) in NO_BODY or (resource == "serviceaccounts" and sub == "token")) and (
        level != "Metadata" or has_body
    ):
        out.append(f"{resource}{'/' + sub if sub else ''} logged at {level} or with a body")
    if (
        group == "rbac.authorization.k8s.io"
        and resource in RBAC
        and verb in WRITE_VERBS
        and level != "RequestResponse"
    ):
        out.append(f"RBAC {verb} {resource} at {level} (expected RequestResponse)")
    if (
        group == ""
        and resource == "pods"
        and not sub
        and verb in {"create", "update", "patch"}
        and level != "Request"
    ):
        out.append(f"pod {verb} at {level} (expected Request)")
    if (
        group == ""
        and resource == "pods"
        and sub in {"exec", "attach", "portforward"}
        and level != "Request"
    ):
        out.append(f"pods/{sub} at {level} (expected Request)")
    if group == "coordination.k8s.io" and resource == "leases":
        out.append("lease traffic logged (expected level None)")
    if (
        verb in {"get", "list", "watch"}
        and resource not in {"secrets", "configmaps"}
        and ("system:nodes" in groups or name in SYSTEM_READERS)
    ):
        out.append(f"system read {verb} {resource} by {name} logged (expected level None)")
    return out


def main() -> int:
    counts: Counter[tuple[str, str, str]] = Counter()
    problems: Counter[str] = Counter()
    lines = bad = 0
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        lines += 1
        try:
            event = json.loads(raw)
        except ValueError:
            bad += 1
            continue
        if not isinstance(event, dict):
            bad += 1
            continue
        ref = _dict(event.get("objectRef"))
        resource = str(ref.get("resource") or event.get("requestURI", "?"))[:48]
        if ref.get("subresource"):
            resource += "/" + str(ref["subresource"])[:24]
        verb = str(event.get("verb") or "?")
        verb_class = "write" if verb in WRITE_VERBS else "read"
        counts[(resource, verb_class, str(event.get("level")))] += 1
        for problem in violations_for(event):
            problems[problem] += 1
    if lines == 0:
        print("no audit lines on stdin")
        return 2
    print(f"audit lines: {lines} (unparseable: {bad})")
    print("level by resource (top 40):")
    for (resource, verb_class, level), n in counts.most_common(40):
        print(f"  {n:7d}  {level:16s} {verb_class:5s} {resource}")
    focus = [
        k
        for k in counts
        if k[0].split("/")[0] in {"secrets", "configmaps", "tokenreviews", "pods", *RBAC}
        or "token" in k[0]
    ]
    print("security-relevant resources:")
    for key in sorted(focus):
        print(f"  {counts[key]:7d}  {key[2]:16s} {key[1]:5s} {key[0]}")
    if problems:
        print("POLICY VIOLATIONS:")
        for problem, n in problems.most_common():
            print(f"  {n:7d}  {problem}")
        return 1
    print("policy guarantees hold: no violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
