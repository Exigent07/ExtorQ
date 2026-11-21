"""Read-only evidence check for the Kubernetes simulations (owner: B2).

    uv run python -m extorq_collectors.kubernetes.verify --scenario K8S-001 --run-id ID
    uv run python -m extorq_collectors.kubernetes.verify --scenario K8S-002 --run-id ID --wait 240

Queries ClickHouse as ``extorq_api_ro`` (password read from
``var/secrets/clickhouse/extorq_api_ro_password`` by ``extorq.storage.clickhouse``;
never printed) with server-side parameters only, and prints the genuine telemetry
produced by the simulation: the audit event(s), the inventory diff event(s) and any
alert the detector raised for the run. Exit 0 when every REQUIRED piece of evidence
is present, 1 on timeout. Alerts are reported but not required (the detector may
not be running).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

RUN_ID_RE = re.compile(r"^[a-z0-9]{8,32}$")


@dataclass(frozen=True)
class Requirement:
    label: str
    sql: str
    required: bool = True


# Every statement is a complete literal; run/object names are bound as server-side
# parameters ({name:String}, {run:String}), never interpolated.
_ALERTS = Requirement(
    "detector alerts for this run",
    "SELECT alert_id, rule_id, severity, confidence, first_seen, event_count, "
    "arrayStringConcat(evidence_event_ids, ',') AS evidence FROM alerts FINAL WHERE "
    "has(simulation_run_ids, {run:String}) ORDER BY first_seen LIMIT 10",
    required=False,
)

SCENARIOS: dict[str, list[Requirement]] = {
    "K8S-001": [
        Requirement(
            "audit: pod create denied by Pod Security admission (403)",
            "SELECT event_id, event_time, k8s_verb, k8s_resource, k8s_namespace, "
            "k8s_object_name, k8s_response_code, k8s_user, simulation_run_id, service_name, "
            "JSONExtractString(attributes, 'request_summary') AS request_summary, "
            "JSONExtract(attributes, 'risk_flags', 'Array(String)') AS risk_flags, "
            "substring(JSONExtractString(attributes, 'pod_security_violation'), 1, 300) AS "
            "psa_violation, JSONExtractString(attributes, 'denied_by') AS denied_by FROM "
            "events WHERE source_type = 'k8s.audit' AND event_type = 'k8s.api.request' AND "
            "k8s_resource = 'pods' AND k8s_verb = 'create' AND k8s_object_name = "
            "{name:String} AND k8s_response_code = 403 ORDER BY event_time LIMIT 1 BY "
            "event_id LIMIT 10",
        ),
        _ALERTS,
    ],
    "K8S-002": [
        Requirement(
            "audit: ClusterRoleBinding to cluster-admin created",
            "SELECT event_id, event_time, k8s_verb, k8s_resource, k8s_namespace, "
            "k8s_object_name, k8s_response_code, k8s_user, simulation_run_id, service_name, "
            "JSONExtractString(attributes, 'request_summary') AS request_summary, "
            "JSONExtract(attributes, 'risk_flags', 'Array(String)') AS risk_flags, "
            "substring(JSONExtractString(attributes, 'pod_security_violation'), 1, 300) AS "
            "psa_violation, JSONExtractString(attributes, 'denied_by') AS denied_by FROM "
            "events WHERE source_type = 'k8s.audit' AND event_type = 'k8s.api.request' AND "
            "k8s_resource = 'clusterrolebindings' AND k8s_verb = 'create' AND "
            "k8s_object_name = {name:String} AND k8s_response_code >= 200 AND "
            "k8s_response_code < 300 ORDER BY event_time LIMIT 1 BY event_id LIMIT 10",
        ),
        Requirement(
            "audit: ServiceAccount created",
            "SELECT event_id, event_time, k8s_verb, k8s_resource, k8s_namespace, "
            "k8s_object_name, k8s_response_code, k8s_user, simulation_run_id, service_name, "
            "JSONExtractString(attributes, 'request_summary') AS request_summary, "
            "JSONExtract(attributes, 'risk_flags', 'Array(String)') AS risk_flags, "
            "substring(JSONExtractString(attributes, 'pod_security_violation'), 1, 300) AS "
            "psa_violation, JSONExtractString(attributes, 'denied_by') AS denied_by FROM "
            "events WHERE source_type = 'k8s.audit' AND k8s_resource = 'serviceaccounts' AND "
            "k8s_verb = 'create' AND k8s_object_name = {name:String} ORDER BY event_time "
            "LIMIT 1 BY event_id LIMIT 10",
        ),
        Requirement(
            "inventory: k8s.resource.created clusterrolebindings (risk flags)",
            "SELECT event_id, event_time, event_type, resource_type, resource_namespace, "
            "resource_name, simulation_run_id, JSONExtract(attributes, 'risk_flags', "
            "'Array(String)') AS risk_flags, JSONExtractBool(attributes, 'baseline') AS "
            "baseline, JSONExtractString(attributes, 'object_summary') AS object_summary "
            "FROM events WHERE source_type = 'k8s.api_inventory' AND event_type = "
            "'k8s.resource.created' AND resource_type = 'clusterrolebindings' AND "
            "resource_name = {name:String} LIMIT 1 BY event_id LIMIT 10",
        ),
        _ALERTS,
    ],
    "K8S-002-CLEANUP": [
        Requirement(
            "audit: ClusterRoleBinding deleted",
            "SELECT event_id, event_time, k8s_verb, k8s_resource, k8s_namespace, "
            "k8s_object_name, k8s_response_code, k8s_user, simulation_run_id, service_name, "
            "JSONExtractString(attributes, 'request_summary') AS request_summary, "
            "JSONExtract(attributes, 'risk_flags', 'Array(String)') AS risk_flags, "
            "substring(JSONExtractString(attributes, 'pod_security_violation'), 1, 300) AS "
            "psa_violation, JSONExtractString(attributes, 'denied_by') AS denied_by FROM "
            "events WHERE source_type = 'k8s.audit' AND k8s_resource = 'clusterrolebindings' "
            "AND k8s_verb = 'delete' AND k8s_object_name = {name:String} ORDER BY event_time "
            "LIMIT 1 BY event_id LIMIT 10",
        ),
        Requirement(
            "inventory: k8s.resource.deleted clusterrolebindings",
            "SELECT event_id, event_time, event_type, resource_type, resource_namespace, "
            "resource_name, simulation_run_id, JSONExtract(attributes, 'risk_flags', "
            "'Array(String)') AS risk_flags, JSONExtractBool(attributes, 'baseline') AS "
            "baseline, JSONExtractString(attributes, 'object_summary') AS object_summary "
            "FROM events WHERE source_type = 'k8s.api_inventory' AND event_type = "
            "'k8s.resource.deleted' AND resource_type = 'clusterrolebindings' AND "
            "resource_name = {name:String} LIMIT 1 BY event_id LIMIT 10",
            required=False,
        ),
    ],
}


def _query(client: Any, sql: str, params: dict[str, str]) -> list[dict[str, Any]]:
    result = client.query(sql, parameters=params)
    return [dict(zip(result.column_names, row, strict=True)) for row in result.result_rows]


def check(
    scenario: str,
    run_id: str,
    *,
    wait_seconds: float,
    client_factory: Callable[[], Any] | None = None,
    poll_seconds: float = 5.0,
    out: Any = sys.stdout,
) -> bool:
    """Poll until every required piece of evidence exists (or the wait expires)."""
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}")
    if not RUN_ID_RE.match(run_id):
        raise ValueError("run id must be 8-32 lower-case alphanumerics")
    if client_factory is None:
        from extorq.storage.clickhouse import get_client

        def client_factory() -> Any:
            return get_client("api_ro")

    client = client_factory()
    params = {"name": f"extorq-sim-{run_id}", "run": run_id}
    deadline = time.monotonic() + max(0.0, wait_seconds)
    while True:
        results = {req.label: _query(client, req.sql, params) for req in SCENARIOS[scenario]}
        missing = [r.label for r in SCENARIOS[scenario] if r.required and not results[r.label]]
        if not missing or time.monotonic() >= deadline:
            break
        time.sleep(poll_seconds)
    for req in SCENARIOS[scenario]:
        rows = results[req.label]
        state = "FOUND" if rows else ("MISSING" if req.required else "none yet")
        print(f"[{state}] {req.label}: {len(rows)} row(s)", file=out)
        for row in rows[:5]:
            print("    " + json.dumps(row, default=str, sort_keys=True)[:1500], file=out)
    if missing:
        print(f"evidence missing after {wait_seconds:.0f}s: {', '.join(missing)}", file=out)
    return not missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--wait", type=float, default=0.0, help="seconds to keep polling")
    args = parser.parse_args(argv)
    try:
        ok = check(args.scenario, args.run_id, wait_seconds=args.wait)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
