"""Read-only verification of Linux telemetry in ClickHouse (debug proxy, ``extorq_api_ro``).

Usage::

    uv run python -m extorq_collectors.linux.verify --asset linux:lab-vm-01 --since-minutes 30
    uv run python -m extorq_collectors.linux.verify --run-id <simulation run id>

Prints duplicate-safe counts (``uniqExact(event_id)``) per event type, the simulation run
records, the current service coverage and the latest posture scan. The ClickHouse
password is read from ``var/secrets/clickhouse/extorq_api_ro_password`` by
``extorq.storage.clickhouse.get_client`` and never printed. Every value is passed as a
server-side query parameter.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

_RUN_ID = re.compile(r"^[a-z0-9]{8,32}$")
_ASSET = re.compile(r"^[a-z0-9][a-z0-9._:/-]{2,199}$")


def _rows(client: Any, query: str, params: dict[str, Any]) -> list[tuple[Any, ...]]:
    return list(client.query(query, parameters=params).result_rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--asset", default="linux:lab-vm-01")
    parser.add_argument("--since-minutes", type=int, default=60)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)
    if not _ASSET.match(args.asset):
        parser.error("invalid asset id")
    if args.run_id is not None and not _RUN_ID.match(args.run_id):
        parser.error("invalid run id")
    if not 1 <= args.since_minutes <= 60 * 24 * 30:
        parser.error("--since-minutes must be 1..43200")

    from extorq.storage.clickhouse import get_client

    client = get_client("api_ro")
    report: dict[str, Any] = {"asset": args.asset}
    params: dict[str, Any] = {"asset": args.asset, "minutes": args.since_minutes}
    if args.run_id:
        params["run"] = args.run_id
        report["run_id"] = args.run_id
        report["events_by_type"] = _rows(
            client,
            (
                "SELECT event_type, source_type, uniqExact(event_id) AS n, min(event_time), "
                "max(event_time) FROM extorq.events WHERE simulation_run_id = {run:String} "
                "GROUP BY event_type, source_type ORDER BY event_type"
            ),
            params,
        )
        report["simulation_runs"] = _rows(
            client,
            (
                "SELECT scenario_id, status, asset_id, started_at, finished_at "
                "FROM extorq.simulation_runs WHERE run_id = {run:String} ORDER BY status"
            ),
            params,
        )
    else:
        report["events_by_type"] = _rows(
            client,
            (
                "SELECT event_type, source_type, uniqExact(event_id) AS n, count() AS rows "
                "FROM extorq.events WHERE asset_id = {asset:String} "
                "AND ingested_time >= now() - toIntervalMinute({minutes:UInt32}) "
                "GROUP BY event_type, source_type ORDER BY n DESC"
            ),
            params,
        )
        report["simulation_run_ids"] = _rows(
            client,
            (
                "SELECT simulation_run_id, uniqExact(event_id) FROM extorq.events "
                "WHERE asset_id = {asset:String} AND simulation_run_id IS NOT NULL "
                "AND ingested_time >= now() - toIntervalMinute({minutes:UInt32}) "
                "GROUP BY simulation_run_id ORDER BY 2 DESC LIMIT 20"
            ),
            params,
        )
        report["services"] = _rows(
            client,
            (
                "SELECT name, service_kind, adapter_id, adapter_support, monitoring_status, "
                "present FROM extorq.v_services WHERE asset_id = {asset:String} ORDER BY name"
            ),
            params,
        )
        report["latest_posture_scan"] = _rows(
            client,
            (
                "SELECT scanner, status, findings_count, finished_at FROM extorq.scan_runs "
                "WHERE asset_id = {asset:String} AND scanner = 'extorq-posture-linux' "
                "ORDER BY finished_at DESC LIMIT 1"
            ),
            params,
        )
        report["collector_health"] = _rows(
            client,
            (
                "SELECT collector_id, status, reported_at, events_collected, records_buffered, "
                "last_error FROM extorq.collector_health WHERE asset_id = {asset:String} "
                "ORDER BY reported_at DESC LIMIT 1"
            ),
            params,
        )
    if args.json:
        print(json.dumps(report, default=str, indent=1))
        return 0
    for key, value in report.items():
        if isinstance(value, list):
            print(f"{key}:")
            for row in value:
                print("   ", " | ".join(str(c) for c in row))
        else:
            print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
