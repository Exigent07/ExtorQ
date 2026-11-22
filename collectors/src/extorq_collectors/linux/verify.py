"""Read-only check of the Linux telemetry stored in ClickHouse (role ``extorq_api_ro``).

Usage::

    uv run python -m extorq_collectors.linux.verify --asset linux:lab-vm-01 --since-minutes 30
    uv run python -m extorq_collectors.linux.verify --from 2026-11-23T09:00:00Z \\
        --to 2026-11-23T09:20:00Z --json

The window is either the last ``--since-minutes`` of *ingestion* time or an explicit
``--from``/``--to`` range of *event* time (the detection-test runner verifies a test by
asset, rule and time window, so this tool reports exactly that view of the telemetry).
It prints duplicate-safe counts (``uniqExact(event_id)``) per event type and source, the
records quarantined at the gateway for this producer, the current service coverage, the
latest posture scan and the newest collector health row.

Why read-only: verification must never change what it verifies. The ClickHouse password
is read from ``var/secrets/clickhouse/extorq_api_ro_password`` by
``extorq.storage.clickhouse.get_client`` (by path, never printed) and every value reaches
the server as a typed query parameter, never as SQL text.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from typing import Any

_ASSET = re.compile(r"^[a-z0-9][a-z0-9._:/-]{2,199}$")
_PRODUCER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_MAX_WINDOW_SECONDS = 30 * 86400


def _rows(client: Any, query: str, params: dict[str, Any]) -> list[tuple[Any, ...]]:
    return list(client.query(query, parameters=params).result_rows)


def _utc(value: str) -> datetime:
    """Parse an ISO 8601 timestamp that carries a zone (``Z`` or an offset)."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp needs a zone (for example 2026-11-23T09:00:00Z)")
    return parsed.astimezone(UTC)


#: Event counts per type for the two window modes. Two complete constant queries (instead of
#: one query with a spliced-in clause) keep every query text static; only values are bound.
_EVENTS_BY_INGEST_TIME = (
    "SELECT event_type, source_type, uniqExact(event_id) AS n, count() AS stored_rows, "
    "min(event_time), max(event_time) FROM extorq.events "
    "WHERE asset_id = {asset:String} "
    "AND ingested_time >= now() - toIntervalMinute({minutes:UInt32}) "
    "GROUP BY event_type, source_type ORDER BY n DESC"
)
_EVENTS_BY_EVENT_TIME = (
    "SELECT event_type, source_type, uniqExact(event_id) AS n, count() AS stored_rows, "
    "min(event_time), max(event_time) FROM extorq.events "
    "WHERE asset_id = {asset:String} "
    "AND event_time >= {start:DateTime64(3, 'UTC')} AND event_time < {end:DateTime64(3, 'UTC')} "
    "GROUP BY event_type, source_type ORDER BY n DESC"
)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("--asset", default="linux:lab-vm-01")
    parser.add_argument("--producer", default="linux-ssh-lab-vm-01")
    parser.add_argument("--since-minutes", type=int, default=60)
    parser.add_argument("--from", dest="start_text", default=None, help="event-time start (UTC)")
    parser.add_argument("--to", dest="end_text", default=None, help="event-time end (UTC)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)
    if not _ASSET.match(args.asset):
        parser.error("invalid asset id")
    if not _PRODUCER.match(args.producer):
        parser.error("invalid producer id")
    if not 1 <= args.since_minutes <= 60 * 24 * 30:
        parser.error("--since-minutes must be 1..43200")
    args.start = args.end = None
    if (args.start_text is None) != (args.end_text is None):
        parser.error("--from and --to must be given together")
    if args.start_text is not None:
        try:
            args.start, args.end = _utc(args.start_text), _utc(args.end_text)
        except ValueError as exc:
            parser.error(str(exc))
        span = (args.end - args.start).total_seconds()
        if not 0 < span <= _MAX_WINDOW_SECONDS:
            parser.error("--to must be after --from and at most 30 days later")
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    from extorq.storage.clickhouse import get_client

    client = get_client("api_ro")
    params: dict[str, Any] = {"asset": args.asset, "producer": args.producer}
    if args.start is not None:
        params.update(start=args.start, end=args.end)
        events_query = _EVENTS_BY_EVENT_TIME
        window = f"event_time {args.start.isoformat()} .. {args.end.isoformat()}"
    else:
        params["minutes"] = args.since_minutes
        events_query = _EVENTS_BY_INGEST_TIME
        window = f"ingested in the last {args.since_minutes} min"
    report: dict[str, Any] = {"asset": args.asset, "window": window}
    report["events_by_type"] = _rows(client, events_query, params)
    report["quarantined"] = _rows(
        client,
        "SELECT reason, count() FROM extorq.ingest_quarantine "
        "WHERE producer_id = {producer:String} AND received_at >= now() - INTERVAL 1 DAY "
        "GROUP BY reason ORDER BY 2 DESC LIMIT 20",
        params,
    )
    report["services"] = _rows(
        client,
        "SELECT name, service_kind, adapter_id, adapter_support, monitoring_status, present "
        "FROM extorq.v_services WHERE asset_id = {asset:String} ORDER BY name",
        params,
    )
    report["latest_posture_scan"] = _rows(
        client,
        "SELECT scanner, status, findings_count, finished_at FROM extorq.scan_runs "
        "WHERE asset_id = {asset:String} AND scanner = 'extorq-posture-linux' "
        "ORDER BY finished_at DESC LIMIT 1",
        params,
    )
    report["collector_health"] = _rows(
        client,
        "SELECT collector_id, status, reported_at, events_collected, records_buffered, "
        "last_error FROM extorq.collector_health WHERE asset_id = {asset:String} "
        "ORDER BY reported_at DESC LIMIT 1",
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
