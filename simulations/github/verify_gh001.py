"""Read-only verification of a GH-001 run in ClickHouse (C1).

Usage (after ``gh_001_workflow_permissions.sh --execute`` and one or two collector cycles)::

    uv run python simulations/github/verify_gh001.py --repo Exigent07/extorq-lab \\
        --run-id <run id> [--stage executed|cleaned]

Queries, as the read-only ``extorq_api_ro`` user with server-side parameters only:

* the SimulationRun lifecycle rows of ``run_id``;
* ``github.commit.observed`` / ``github.workflow.modified`` / ``github.workflow_run.observed``
  events tagged with ``run_id`` (genuine telemetry carrying the commit-message marker);
* GH-001 alerts whose ``simulation_run_ids`` contain ``run_id``;
* the current state of the posture finding ``github.workflow.write_all`` for the workflow.

Exit status 0 when the expected evidence for ``--stage`` is present: ``executed`` needs an
escalating workflow event (``write_all_added`` true) and a GH-001 alert; ``cleaned`` also
needs a later, non-escalating workflow event for the same file. Exit 1 otherwise, 2 on
usage or connection errors. Nothing is written.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

WORKFLOW = ".github/workflows/ci.yml"
_REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")
_RUN_RE = re.compile(r"^[a-z0-9]{8,32}$")


def _rows(client: Any, sql: str, **params: Any) -> list[dict[str, Any]]:
    result = client.query(sql, parameters=params)
    return [dict(zip(result.column_names, row, strict=True)) for row in result.result_rows]


def main(argv: list[str] | None = None, *, client: Any = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True, help="OWNER/NAME of the lab repository")
    parser.add_argument("--run-id", required=True, help="simulation run id")
    parser.add_argument("--stage", choices=("executed", "cleaned"), default="executed")
    args = parser.parse_args(argv)
    if not _REPO_RE.match(args.repo) or not _RUN_RE.match(args.run_id):
        print("error: invalid --repo or --run-id", file=sys.stderr)
        return 2
    asset = f"github:{args.repo.lower()}"

    if client is None:
        from extorq.storage.clickhouse import get_client

        try:
            client = get_client("api_ro")
        except Exception as exc:  # noqa: BLE001 - report and exit, never print secrets
            print(f"error: cannot connect to ClickHouse ({type(exc).__name__})", file=sys.stderr)
            return 2

    sims = _rows(
        client,
        "SELECT status, started_at, finished_at, expected_rule_ids FROM extorq.simulation_runs "
        "WHERE run_id = {run:String} ORDER BY row_version",
        run=args.run_id,
    )
    events = _rows(
        client,
        "SELECT event_type, event_time, gh_commit_sha AS commit_sha, gh_workflow_path AS path, "
        "gh_conclusion AS conclusion, actor_name AS actor, "
        "JSONExtractBool(attributes, 'write_all_added') AS write_all_added, "
        "JSONExtract(attributes, 'added_write_scopes', 'Array(String)') AS added_write_scopes, "
        "JSONExtract(attributes, 'triggers_added', 'Array(String)') AS triggers_added, "
        "JSONExtractBool(attributes, 'untrusted_checkout_added') AS untrusted_checkout_added, "
        "JSONExtractString(attributes, 'permissions_before') AS permissions_before, "
        "JSONExtractString(attributes, 'permissions_after') AS permissions_after "
        "FROM extorq.events WHERE asset_id = {asset:String} AND source_type = 'github.api' "
        "AND simulation_run_id = {run:String} ORDER BY event_time, event_type LIMIT 1 BY event_id",
        asset=asset,
        run=args.run_id,
    )
    alerts = _rows(
        client,
        "SELECT alert_id, confidence, severity, entities, event_count, created_at "
        "FROM extorq.alerts FINAL WHERE rule_id = 'GH-001' AND asset_id = {asset:String} "
        "AND has(simulation_run_ids, {run:String}) ORDER BY first_seen",
        asset=asset,
        run=args.run_id,
    )
    findings = _rows(
        client,
        "SELECT check_id, state, severity, last_observed_at, latest_scan_status "
        "FROM extorq.v_findings_current WHERE asset_id = {asset:String} "
        "AND check_id = 'github.workflow.write_all' AND resource_path = {path:String}",
        asset=asset,
        path=WORKFLOW,
    )
    report = {
        "asset_id": asset,
        "run_id": args.run_id,
        "simulation_runs": sims,
        "events": events,
        "gh001_alerts": alerts,
        "posture_write_all_finding": findings,
    }
    print(json.dumps(report, indent=2, default=str, sort_keys=True))

    workflow_events = [e for e in events if e["event_type"] == "github.workflow.modified"]
    escalated = [e for e in workflow_events if e["write_all_added"]]
    problems: list[str] = []
    if not escalated:
        problems.append("no github.workflow.modified event with write_all_added=true")
    if not alerts:
        problems.append("no GH-001 alert tagged with this run id")
    if args.stage == "cleaned":
        last_escalation = max(e["event_time"] for e in escalated) if escalated else None
        reverted = [
            e
            for e in workflow_events
            if not e["write_all_added"]
            and last_escalation is not None
            and e["event_time"] >= last_escalation
            and e["commit_sha"] != escalated[-1]["commit_sha"]
        ]
        if not reverted:
            problems.append("no later non-escalating github.workflow.modified (cleanup) event")
    for problem in problems:
        print(f"MISSING: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
