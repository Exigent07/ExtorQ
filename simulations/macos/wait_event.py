"""Wait until the macOS collector's event for a simulated change is stored (owner B3).

Usage (repository root; stack + ClickHouse debug proxy running):

    uv run python simulations/macos/wait_event.py --event-type persistence.launchd.item_created \
        --path /Users/<you>/Library/LaunchAgents/com.extorq.sim.<run_id>.plist \
        --since 2026-11-21T15:00:00Z [--timeout 240]

Read-only: one static, parameterised SELECT as ``extorq_api_ro`` (password read by
``extorq.storage.clickhouse.get_client`` from var/secrets/clickhouse/, never passed
on a command line). Telemetry values are untrusted and are sanitised before printing.
Exit status: 0 found, 1 timed out, 2 usage or connection error.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from datetime import UTC, datetime
from typing import Any

ASSET = "macos:workstation-01"
EVENT_TYPES = (
    "persistence.launchd.item_created",
    "persistence.launchd.item_modified",
    "persistence.launchd.item_deleted",
)
SQL = (
    "SELECT event_id, event_time, event_type, resource_path, simulation_run_id, service_name, "
    "collector_id, producer_id, JSONExtractString(attributes, 'scope') AS scope, "
    "JSONExtractRaw(attributes, 'run_at_load') AS run_at_load, "
    "JSONExtractString(attributes, 'sha256') AS sha256 "
    "FROM extorq.events "
    "WHERE asset_id = {asset:String} AND event_type = {event_type:String} "
    "AND resource_path = {path:String} AND event_time >= {since:DateTime64(3, 'UTC')} "
    "ORDER BY event_time LIMIT 1 BY event_id LIMIT 5"
)
_UNSAFE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


def clean(value: Any, limit: int = 160) -> str:
    text = _UNSAFE.sub("", "" if value is None else str(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def parse_since(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("--since must include a timezone (e.g. Z)")
    return parsed.astimezone(UTC)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--event-type", required=True, choices=EVENT_TYPES)
    parser.add_argument("--path", required=True)
    parser.add_argument("--since", required=True, type=parse_since)
    parser.add_argument("--timeout", type=float, default=240.0)
    parser.add_argument("--interval", type=float, default=10.0)
    args = parser.parse_args(argv)
    if not args.path.startswith("/") or len(args.path) > 1024:
        parser.error("--path must be an absolute path (<= 1024 characters)")
    timeout = min(max(args.timeout, 1.0), 3600.0)
    interval = min(max(args.interval, 2.0), 60.0)
    try:
        from extorq.storage.clickhouse import get_client

        client = get_client("api_ro")
    except Exception as exc:  # noqa: BLE001 - report the class only (no secrets in output)
        print(f"error: cannot connect to ClickHouse as extorq_api_ro ({type(exc).__name__})")
        return 2
    params = {
        "asset": ASSET,
        "event_type": args.event_type,
        "path": args.path,
        "since": args.since.replace(tzinfo=None),
    }
    deadline = time.monotonic() + timeout
    attempt = 0
    while True:
        attempt += 1
        try:
            rows = client.query(SQL, parameters=params).named_results()
        except Exception as exc:  # noqa: BLE001
            print(f"warning: query failed ({type(exc).__name__}); retrying")
            rows = []
        rows = list(rows)
        if rows:
            for row in rows:
                print(
                    "found {event_type} event_id={event_id} event_time={event_time} "
                    "scope={scope} run_at_load={run_at_load} simulation_run_id={sim} "
                    "service={service} collector={collector} producer={producer}".format(
                        event_type=clean(row["event_type"]),
                        event_id=clean(row["event_id"]),
                        event_time=clean(row["event_time"]),
                        scope=clean(row["scope"]),
                        run_at_load=clean(row["run_at_load"]),
                        sim=clean(row["simulation_run_id"]),
                        service=clean(row["service_name"]),
                        collector=clean(row["collector_id"]),
                        producer=clean(row["producer_id"]),
                    )
                )
            return 0
        if time.monotonic() >= deadline:
            print(
                f"timeout: no {args.event_type} for the path after {timeout:.0f}s "
                f"({attempt} queries). Is the macOS collector running? "
                "(uv run extorq-collect run --only macos-workstation-01)"
            )
            return 1
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
