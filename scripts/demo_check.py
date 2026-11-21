#!/usr/bin/env python3
"""Read-only demo readiness report (``make demo-check``).

Checks, without changing anything:

* compose services (running / health),
* the ingest gateway (``/healthz``, ``/v1/status`` with the least-privileged
  ``extorq-selftest`` token: spool depth, dead letters),
* ClickHouse through the loopback debug proxy as ``extorq_api_ro`` (when reachable):
  applied migrations, data freshness per asset and source, collector and pipeline
  health (stale = no success for 3 intervals), rules and recent rule failures, alerts
  per rule, service coverage, recent simulation runs.

Prints names, counts and timestamps only: never tokens, passwords or telemetry
content. Exit code 1 when a core component (gateway, writer, ClickHouse) is down.
"""

from __future__ import annotations

import argparse
import json
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
CORE = ("clickhouse", "ingest", "writer")


def compose_services() -> dict[str, str]:
    try:
        proc = subprocess.run(
            [
                "docker",
                "compose",
                "--profile",
                "full",
                "--profile",
                "debug",
                "ps",
                "--format",
                "json",
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    services: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        health = data.get("Health") or ""
        services[str(data.get("Service"))] = f"{data.get('State')}{'/' + health if health else ''}"
    return services


def gateway_status(url: str) -> tuple[bool, dict[str, Any] | None, str]:
    ca = REPO / "var" / "tls" / "ca.crt"
    token_file = REPO / "var" / "secrets" / "tokens" / "extorq-selftest.token"
    if not url.startswith("https://"):
        return False, None, "gateway URL must use https://"
    try:
        context = ssl.create_default_context(cafile=str(ca))
        health_url = f"{url}/healthz"
        with urllib.request.urlopen(health_url, context=context, timeout=5) as response:  # noqa: S310 - https only (checked above)
            healthy = response.status == 200
    except (OSError, urllib.error.URLError, ssl.SSLError) as exc:
        return False, None, type(exc).__name__
    if not token_file.is_file():
        return healthy, None, "no extorq-selftest token (run make bootstrap)"
    request = urllib.request.Request(  # noqa: S310 - https only (checked above)
        f"{url}/v1/status",
        headers={"Authorization": f"Bearer {token_file.read_text(encoding='utf-8').strip()}"},
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=5) as response:  # noqa: S310 - https only
            return healthy, json.loads(response.read().decode("utf-8")), ""
    except (OSError, urllib.error.URLError, ValueError) as exc:
        return healthy, None, type(exc).__name__


QUERIES: dict[str, str] = {
    "migrations": "SELECT groupArray(version) FROM (SELECT version FROM extorq.schema_migrations "
    "FINAL ORDER BY version)",
    "freshness": "SELECT asset_id, source_type, max(event_time), uniqExact(event_id) "
    "FROM extorq.events WHERE event_time > now64(3) - INTERVAL 24 HOUR "
    "GROUP BY asset_id, source_type ORDER BY asset_id, source_type",
    "collectors": "SELECT collector_id, asset_id, status, last_success_at, interval_seconds, "
    "records_buffered, dateDiff('second', last_success_at, now64(3)), collector_type "
    "FROM extorq.v_collector_latest ORDER BY asset_id, collector_id",
    "pipeline": "SELECT component, instance, status, last_reported_at, queue_depth, "
    "dead_letter_total FROM extorq.v_pipeline_latest ORDER BY component, instance",
    "rules": "SELECT rule_id, last_status, last_run_at, failures_24h, missing_sources "
    "FROM extorq.v_rule_latest_run ORDER BY rule_id",
    "alerts": "SELECT rule_id, count(), max(updated_at) FROM extorq.v_alerts GROUP BY rule_id "
    "ORDER BY rule_id",
    "services": "SELECT asset_id, adapter_support, monitoring_status, count() FROM "
    "extorq.v_services WHERE present = 1 GROUP BY asset_id, adapter_support, "
    "monitoring_status ORDER BY asset_id, adapter_support, monitoring_status",
    "simulations": "SELECT scenario_id, run_id, status, started_at FROM extorq.simulation_runs "
    "FINAL WHERE started_at > now64(3) - INTERVAL 24 HOUR ORDER BY started_at",
}


def clickhouse_report() -> tuple[bool, dict[str, Any]]:
    try:
        from extorq.common.config import Settings
        from extorq.storage.clickhouse import get_client

        client = get_client("api_ro", settings=Settings(home=REPO))
        client.query("SELECT 1")
    except Exception as exc:  # noqa: BLE001 - report reachability, never crash the check
        return False, {"error": type(exc).__name__}
    results: dict[str, Any] = {}
    for name, sql in QUERIES.items():
        try:
            results[name] = client.query(sql).result_rows
        except Exception as exc:  # noqa: BLE001 - one failing panel must not hide the others
            results[name] = f"query failed: {type(exc).__name__}"
    return True, results


def _print_rows(title: str, rows: Any, fmt: str) -> None:
    print(f"\n{title}")
    if isinstance(rows, str):
        print(f"  {rows}")
        return
    if not rows:
        print("  (none)")
        return
    for row in rows:
        print("  " + fmt.format(*row))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--gateway", default="https://127.0.0.1:8443")
    args = parser.parse_args(argv)
    problems: list[str] = []

    services = compose_services()
    print("compose services")
    for name in sorted(services):
        print(f"  {name:<18} {services[name]}")
    for name in CORE:
        state = services.get(name, "missing")
        if not state.startswith("running") or ("/" in state and not state.endswith("healthy")):
            problems.append(f"{name}: {state}")

    healthy, status, error = gateway_status(args.gateway)
    print(f"\ngateway {args.gateway}: {'healthy' if healthy else 'UNREACHABLE ' + error}")
    if not healthy:
        problems.append("gateway unreachable")
    if status:
        spool = status.get("spool", {})
        print(
            f"  schema {status.get('schema_version')}, spool depth {spool.get('depth')}, "
            f"oldest {spool.get('oldest_age_seconds')} s, "
            f"dead letters {spool.get('dead_letter')}"
        )

    reachable, ch = clickhouse_report()
    if not reachable:
        print(
            f"\nClickHouse (debug proxy 127.0.0.1:18123): not reachable ({ch.get('error')}). "
            "Run `make up-debug` for this report and stop the proxy before the demo."
        )
    else:
        print(f"\nmigrations applied: {ch['migrations'][0][0] if ch['migrations'] else '?'}")
        _print_rows(
            "events in the last 24 h (asset, source, newest, unique events)",
            ch["freshness"],
            "{:<28} {:<20} {} {:>8}",
        )
        _print_rows(
            "collectors (id, asset, status, last success, interval s, buffered, age s)",
            ch["collectors"],
            "{:<26} {:<26} {:<8} {} {:>5} {:>5} {}",
        )
        if isinstance(ch["collectors"], list):
            for row in ch["collectors"]:
                age, interval = row[6], row[4] or 0
                if row[7] == "heartbeat":
                    print(f"  note: {row[0]} is the SDK self-test (reports only when run)")
                elif age is None or (interval and age > 3 * interval):
                    print(f"  STALE: {row[0]} (no success for {age} s, interval {interval} s)")
        _print_rows(
            "pipeline (component, instance, status, reported, queue, dead letters)",
            ch["pipeline"],
            "{:<10} {:<14} {:<8} {} {:>7} {:>5}",
        )
        _print_rows(
            "rules (id, last status, last run, failures 24 h, missing sources)",
            ch["rules"],
            "{:<9} {:<10} {} {:>3} {}",
        )
        _print_rows("alerts (rule, count, last update)", ch["alerts"], "{:<9} {:>5} {}")
        _print_rows(
            "services (asset, adapter support, monitoring status, count)",
            ch["services"],
            "{:<34} {:<12} {:<12} {:>4}",
        )
        _print_rows("simulation runs in the last 24 h", ch["simulations"], "{:<9} {:<14} {:<11} {}")

    print()
    if problems:
        print("NOT READY: " + "; ".join(problems))
        return 1
    print("core platform ready")
    return 0


if __name__ == "__main__":
    sys.exit(main())
