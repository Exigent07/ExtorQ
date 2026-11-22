#!/usr/bin/env python3
"""Read-only demo readiness report (``make demo-check``).

Checks, without changing anything (exit 1 when any FAIL check fails):

* compose services: core + full profile running and healthy (``ai-worker`` optional);
* the ingest gateway (``/healthz``; ``/v1/status`` with the least-privileged
  ``extorq-selftest`` token: spool depth, dead letters, acceptance window);
* the analyst API (``/healthz``; authenticated viewer ``GET /api/v1/health``), the
  console (``/healthz``, ``/login``) and Grafana (``/api/health``; the provisioned
  ClickHouse datasource health with the admin account);
* ClickHouse as ``extorq_api_ro`` (debug proxy 127.0.0.1:18123 when it is up, otherwise
  the same read-only queries run inside the ``api`` container, so the proxy can stay
  off during the demo, F-01):

  - every migration file is applied;
  - the five mandatory scenarios (VM-001, VM-002, K8S-001, K8S-002, GH-001) each have
    at least one alert whose evidence ALL resolves to stored events, none of them
    labelled synthetic;
  - every enabled host collector (``config/collectors``) reports ok/degraded with a
    fresh ``last_success_at`` (age <= max(3 x interval, 180 s));
  - every rule in ``rules/`` ran in the last 15 min and has no failed run in 24 h;
  - informational: data freshness per source, pipeline, alerts, services, simulations,
    the Kubernetes inventory token lifetime.

Prints names, counts, ids and timestamps only: never tokens, passwords or telemetry.
"""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
REQUIRED_SERVICES = ("clickhouse", "ingest", "writer", "detector", "api", "frontend", "grafana")
OPTIONAL_SERVICES = ("ai-worker",)
MANDATORY_RULES = ("VM-001", "VM-002", "K8S-001", "K8S-002", "GH-001")
RULE_RUN_MAX_AGE_SECONDS = 15 * 60
MIN_STALE_SECONDS = 180
TOKEN_WARN_SECONDS = 24 * 3600
API = "http://127.0.0.1:8000"
CONSOLE = "http://127.0.0.1:3000"
GRAFANA = "http://127.0.0.1:3001"


@dataclass
class Report:
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def check(self, ok: bool, label: str, detail: str = "", *, warn_only: bool = False) -> bool:
        mark = "ok  " if ok else ("WARN" if warn_only else "FAIL")
        print(f"  [{mark}] {label}{': ' + detail if detail else ''}")
        if not ok:
            (self.warnings if warn_only else self.failures).append(label)
        return ok

    def info(self, text: str) -> None:
        print(f"         {text}")


def section(title: str) -> None:
    print(f"\n{title}")


# ── compose ───────────────────────────────────────────────────────────


def compose_services() -> dict[str, tuple[str, str]]:
    """``{service: (state, health)}`` of the running project containers."""
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
    services: dict[str, tuple[str, str]] = {}
    for line in proc.stdout.splitlines():
        try:
            data = json.loads(line)
        except ValueError:
            continue
        services[str(data.get("Service"))] = (str(data.get("State")), str(data.get("Health") or ""))
    return services


def check_compose(report: Report) -> None:
    section("compose services")
    services = compose_services()
    for name in (*REQUIRED_SERVICES, *OPTIONAL_SERVICES):
        state, health = services.get(name, ("missing", ""))
        ok = state == "running" and health in ("", "healthy")
        label = f"{name} {state}{'/' + health if health else ''}"
        report.check(ok, label, warn_only=name in OPTIONAL_SERVICES)
    if "clickhouse-debug" in services:
        report.check(
            False,
            "clickhouse-debug proxy is running",
            "stop it before the demo: docker compose stop clickhouse-debug (F-01)",
            warn_only=True,
        )


# ── HTTP endpoints ────────────────────────────────────────────────────


def http_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    context: ssl.SSLContext | None = None,
    timeout: float = 10.0,
) -> tuple[int | None, Any, str]:
    """``(status, parsed JSON or None, error)``; loopback URLs only (checked by callers)."""
    request = urllib.request.Request(url, headers=headers or {})  # noqa: S310 - fixed loopback URLs
    try:
        with urllib.request.urlopen(request, context=context, timeout=timeout) as response:  # noqa: S310
            body = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        return exc.code, None, f"HTTP {exc.code}"
    except (OSError, urllib.error.URLError, ssl.SSLError) as exc:
        return None, None, type(exc).__name__
    try:
        return status, json.loads(body) if body else None, ""
    except ValueError:
        return status, None, ""


def _secret(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def check_gateway(report: Report, url: str) -> None:
    section(f"ingest gateway {url}")
    if not url.startswith("https://"):
        report.check(False, "gateway URL must use https://")
        return
    context = ssl.create_default_context(cafile=str(REPO / "var" / "tls" / "ca.crt"))
    status, _, error = http_get(f"{url}/healthz", context=context, timeout=5)
    if not report.check(status == 200, "gateway /healthz", error or f"HTTP {status}"):
        return
    token = _secret(REPO / "var" / "secrets" / "tokens" / "extorq-selftest.token")
    if token is None:
        report.check(False, "gateway /v1/status", "no extorq-selftest token (make bootstrap)")
        return
    status, body, error = http_get(
        f"{url}/v1/status", headers={"Authorization": f"Bearer {token}"}, context=context
    )
    if not report.check(status == 200 and isinstance(body, dict), "gateway /v1/status", error):
        return
    spool, limits = body.get("spool", {}), body.get("limits", {})
    report.info(
        f"schema {body.get('schema_version')}, spool depth {spool.get('depth')}, oldest "
        f"{spool.get('oldest_age_seconds')} s, retention {limits.get('event_retention_days')} d"
    )
    report.check(
        not spool.get("dead_letter"),
        "spool dead letters",
        str(spool.get("dead_letter")),
        warn_only=True,
    )


def check_endpoints(report: Report) -> None:
    section("API, console, Grafana")
    status, _, error = http_get(f"{API}/healthz", timeout=5)
    report.check(status == 200, f"API {API}/healthz", error or f"HTTP {status}")
    token = _secret(REPO / "var" / "secrets" / "api_service_token")
    if token is None:
        report.check(False, "API /api/v1/health (viewer)", "no api_service_token (make bootstrap)")
    else:
        status, body, error = http_get(
            f"{API}/api/v1/health",
            headers={
                "Authorization": f"Bearer {token}",
                "X-ExtorQ-User": "demo-check",
                "X-ExtorQ-Role": "viewer",
            },
        )
        report.check(status == 200 and isinstance(body, dict), "API /api/v1/health (viewer)", error)
    for path in ("/healthz", "/login"):
        status, _, error = http_get(f"{CONSOLE}{path}", timeout=10)
        report.check(status == 200, f"console {CONSOLE}{path}", error or f"HTTP {status}")
    status, body, error = http_get(f"{GRAFANA}/api/health", timeout=5)
    database = body.get("database") if isinstance(body, dict) else None
    report.check(status == 200 and database == "ok", f"Grafana {GRAFANA}/api/health", error)
    password = _secret(REPO / "var" / "secrets" / "grafana_admin_password")
    if password is None:
        report.check(False, "Grafana datasource", "no grafana_admin_password (make bootstrap)")
        return
    basic = base64.b64encode(f"admin:{password}".encode()).decode()
    status, body, error = http_get(
        f"{GRAFANA}/api/datasources/uid/extorq-clickhouse/health",
        headers={"Authorization": f"Basic {basic}"},
        timeout=20,
    )
    ok = status == 200 and isinstance(body, dict) and body.get("status") == "OK"
    report.check(
        ok, "Grafana datasource extorq-clickhouse", error or str((body or {}).get("message"))
    )


# ── ClickHouse (read-only, extorq_api_ro) ─────────────────────────────

QUERIES: dict[str, tuple[str, dict[str, Any]]] = {
    "migrations": (
        "SELECT concat(version, '_', name) FROM extorq.schema_migrations FINAL ORDER BY version",
        {},
    ),
    "scenarios": (
        """
        WITH ev AS (
            SELECT alert_id, groupUniqArray(event_id) AS ids
            FROM extorq.alert_evidence FINAL
            WHERE alert_id IN (
                SELECT alert_id FROM extorq.v_alerts WHERE rule_id IN {rules:Array(String)})
            GROUP BY alert_id
        ),
        stored AS (
            SELECT event_id, max(labels['synthetic'] = 'true') AS synthetic
            FROM extorq.events
            WHERE event_id IN (SELECT arrayJoin(ids) FROM ev)
            GROUP BY event_id
        ),
        per_alert AS (
            SELECT ev.alert_id AS alert_id, length(any(ev.ids)) AS n_evidence,
                   countIf(stored.event_id != '') AS n_stored,
                   sumIf(stored.synthetic, stored.event_id != '') AS n_synthetic
            FROM ev ARRAY JOIN ev.ids AS id
            LEFT JOIN stored ON stored.event_id = id
            GROUP BY ev.alert_id
        )
        SELECT a.rule_id, a.alert_id, a.confidence, a.simulation_run_ids,
               ifNull(p.n_evidence, 0), ifNull(p.n_stored, 0), ifNull(p.n_synthetic, 0),
               toString(a.updated_at)
        FROM extorq.v_alerts AS a
        LEFT JOIN per_alert AS p ON p.alert_id = a.alert_id
        WHERE a.rule_id IN {rules:Array(String)}
        ORDER BY a.rule_id, notEmpty(a.simulation_run_ids) DESC, a.updated_at DESC, a.alert_id
        """,
        {"rules": list(MANDATORY_RULES)},
    ),
    "collectors": (
        "SELECT collector_id, collector_type, status, toString(last_success_at), "
        "dateDiff('second', last_success_at, now64(3)), interval_seconds, records_buffered, "
        "JSONExtractRaw(details, 'token_expires_in_seconds'), "
        "dateDiff('second', last_reported_at, now64(3)) "
        "FROM extorq.v_collector_latest ORDER BY collector_id",
        {},
    ),
    "rules": (
        "SELECT rule_id, last_status, toString(last_run_at), "
        "dateDiff('second', last_run_at, now64(3)), runs_24h, failures_24h, missing_sources "
        "FROM extorq.v_rule_latest_run ORDER BY rule_id",
        {},
    ),
    "freshness": (
        "SELECT asset_id, source_type, toString(max(event_time)), uniqExact(event_id) "
        "FROM extorq.events WHERE event_time > now64(3) - INTERVAL 24 HOUR "
        "GROUP BY asset_id, source_type ORDER BY asset_id, source_type",
        {},
    ),
    "pipeline": (
        "SELECT component, instance, status, dateDiff('second', last_reported_at, now64(3)), "
        "queue_depth, dead_letter_total FROM extorq.v_pipeline_latest "
        "WHERE last_reported_at > now64(3) - INTERVAL 1 HOUR ORDER BY component, instance",
        {},
    ),
    "alerts": (
        "SELECT rule_id, count(), toString(max(updated_at)) FROM extorq.v_alerts "
        "GROUP BY rule_id ORDER BY rule_id",
        {},
    ),
    "services": (
        "SELECT asset_id, adapter_support, monitoring_status, count() FROM extorq.v_services "
        "WHERE present = 1 GROUP BY asset_id, adapter_support, monitoring_status "
        "ORDER BY asset_id, adapter_support, monitoring_status",
        {},
    ),
    "simulations": (
        "SELECT scenario_id, run_id, status, toString(started_at) FROM extorq.simulation_runs "
        "FINAL WHERE started_at > now64(3) - INTERVAL 48 HOUR ORDER BY started_at",
        {},
    ),
}

# Runs inside the api container (stdin: {"name": [sql, params]}); prints JSON rows.
_IN_CONTAINER = """
import json, sys
from extorq.storage.clickhouse import get_client
queries = json.load(sys.stdin)
client = get_client("api_ro")
out = {}
for name, (sql, params) in queries.items():
    try:
        out[name] = [list(r) for r in client.query(sql, parameters=params).result_rows]
    except Exception as exc:
        out[name] = {"error": type(exc).__name__}
print(json.dumps(out, default=str))
"""


def _run_local() -> dict[str, Any] | None:
    try:
        from extorq.common.config import Settings
        from extorq.storage.clickhouse import get_client

        client = get_client("api_ro", settings=Settings(home=REPO))
        client.query("SELECT 1")
    except Exception:  # noqa: BLE001 - proxy down: fall back to the api container
        return None
    out: dict[str, Any] = {}
    for name, (sql, params) in QUERIES.items():
        try:
            rows = client.query(sql, parameters=params).result_rows
            out[name] = json.loads(json.dumps([list(r) for r in rows], default=str))
        except Exception as exc:  # noqa: BLE001 - one failing query must not hide the others
            out[name] = {"error": type(exc).__name__}
    return out


def _run_in_api_container() -> dict[str, Any] | None:
    try:
        proc = subprocess.run(
            ["docker", "exec", "-i", "extorq-api-1", "python", "-c", _IN_CONTAINER],
            input=json.dumps(QUERIES),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        result = json.loads(proc.stdout) if proc.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    return result if isinstance(result, dict) else None


def clickhouse_data() -> tuple[str, dict[str, Any] | None]:
    local = _run_local()
    if local is not None:
        return "debug proxy 127.0.0.1:18123", local
    return "read-only queries inside the api container", _run_in_api_container()


def _rows(data: dict[str, Any], name: str, report: Report) -> list[list[Any]]:
    rows = data.get(name)
    if isinstance(rows, dict):
        report.check(False, f"query {name}", str(rows.get("error")))
        return []
    return rows or []


def enabled_host_collectors() -> dict[str, int]:
    """``{collector_id: interval_seconds}`` of the enabled collectors in config/collectors."""
    try:
        from extorq_collectors.sdk.config import load_collector_configs

        configs = load_collector_configs(REPO / "config" / "collectors")
    except Exception:  # noqa: BLE001 - reported by the caller as "unknown"
        return {}
    return {c.collector_id: c.interval_seconds for c in configs}


def repository_rules() -> list[str]:
    try:
        from extorq.detection.registry import load_rules_report

        rules, _problems = load_rules_report(REPO / "rules")
    except Exception:  # noqa: BLE001
        return []
    return sorted(rule.rule_id for rule in rules)


def check_scenarios(report: Report, rows: list[list[Any]]) -> None:
    section("mandatory scenarios (>= 1 alert whose evidence resolves to stored, real events)")
    by_rule: dict[str, list[list[Any]]] = {rule: [] for rule in MANDATORY_RULES}
    for row in rows:
        by_rule.setdefault(str(row[0]), []).append(row)
    for rule in MANDATORY_RULES:
        alerts = by_rule.get(rule, [])
        good = [r for r in alerts if r[4] > 0 and r[5] == r[4] and r[6] == 0]
        if good:
            shown = good[0]  # simulation-backed first, then the newest
            runs = ",".join(shown[3]) or "-"
            detail = (
                f"{len(good)}/{len(alerts)} alerts; e.g. {str(shown[1])[:12]} "
                f"({shown[2]}, evidence {shown[5]}/{shown[4]} stored, sim run {runs}, "
                f"updated {shown[7]})"
            )
        else:
            detail = f"{len(alerts)} alerts, none with fully stored non-synthetic evidence"
        report.check(bool(good), rule, detail)


def check_collectors(report: Report, rows: list[list[Any]]) -> None:
    section("collectors (enabled host collectors must be ok/degraded and fresh)")
    enabled = enabled_host_collectors()
    if not enabled:
        report.check(False, "enabled collectors", "config/collectors could not be loaded")
    seen = {str(r[0]): r for r in rows}
    for collector_id, interval in sorted(enabled.items()):
        row = seen.get(collector_id)
        if row is None:
            report.check(False, collector_id, "no CollectorHealth yet (make collectors-start)")
            continue
        status, age = str(row[2]), row[4]
        limit = max(3 * int(row[5] or interval), MIN_STALE_SECONDS)
        fresh = age is not None and int(age) <= limit
        report.check(
            status in ("ok", "degraded") and fresh,
            collector_id,
            f"{status}, last success {age} s ago (limit {limit} s), buffered {row[6]}",
        )
        if str(row[1]) == "k8s_inventory" and row[7] not in (None, "", "null"):
            try:
                remaining = float(str(row[7])) - float(row[8] or 0)
            except ValueError:
                continue
            report.check(
                remaining > TOKEN_WARN_SECONDS,
                f"{collector_id} credential lifetime",
                f"~{remaining / 3600:.1f} h left (re-mint: infra/kind/kind.sh token, owner B2)",
                warn_only=True,
            )
    for collector_id, row in sorted(seen.items()):
        if collector_id not in enabled:
            report.info(f"{collector_id} ({row[1]}): {row[2]}, last success {row[4]} s ago")


def check_rules(report: Report, rows: list[list[Any]]) -> None:
    section("rules (ran in the last 15 min, no failed run in 24 h)")
    expected = repository_rules()
    if not expected:
        report.check(False, "rules", "rules/ could not be loaded")
    seen = {str(r[0]): r for r in rows}
    for rule_id in expected:
        row = seen.get(rule_id)
        if row is None:
            report.check(False, rule_id, "never ran")
            continue
        age, failures = row[3], int(row[5] or 0)
        recent = age is not None and int(age) <= RULE_RUN_MAX_AGE_SECONDS
        missing = ",".join(row[6]) or "-"
        report.check(
            recent and failures == 0,
            rule_id,
            f"last {row[1]} {age} s ago, {row[4]} runs / {failures} failed in 24 h, "
            f"missing sources {missing}",
        )


def _print_rows(title: str, rows: list[list[Any]], fmt: Callable[[list[Any]], str]) -> None:
    section(title)
    if not rows:
        print("         (none)")
    for row in rows:
        print("         " + fmt(row))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--gateway", default="https://127.0.0.1:8443")
    args = parser.parse_args(argv)
    report = Report()

    check_compose(report)
    check_gateway(report, args.gateway)
    check_endpoints(report)

    via, data = clickhouse_data()
    section(f"ClickHouse as extorq_api_ro ({via})")
    if data is None:
        report.check(False, "ClickHouse reachable", "neither the debug proxy nor the api container")
    else:
        applied = [str(r[0]) for r in _rows(data, "migrations", report)]
        files = sorted(p.stem for p in (REPO / "infra/clickhouse/migrations").glob("[0-9]*.sql"))
        pending = [name for name in files if name not in applied]
        report.check(
            not pending,
            "migrations applied",
            ", ".join(applied) if not pending else f"pending: {', '.join(pending)}",
        )
        check_scenarios(report, _rows(data, "scenarios", report))
        check_collectors(report, _rows(data, "collectors", report))
        check_rules(report, _rows(data, "rules", report))
        _print_rows(
            "events in the last 24 h (asset, source, newest, unique events)",
            _rows(data, "freshness", report),
            lambda r: f"{r[0]:<34} {r[1]:<20} {r[2]} {r[3]:>8}",
        )
        _print_rows(
            "pipeline in the last hour (component, instance, status, age s, queue, dead letters)",
            _rows(data, "pipeline", report),
            lambda r: f"{r[0]:<10} {r[1]:<20} {r[2]:<9} {r[3]:>5} {r[4]:>6} {r[5]:>4}",
        )
        _print_rows(
            "alerts per rule (rule, count, last update)",
            _rows(data, "alerts", report),
            lambda r: f"{r[0]:<9} {r[1]:>5} {r[2]}",
        )
        _print_rows(
            "services (asset, adapter support, monitoring status, count)",
            _rows(data, "services", report),
            lambda r: f"{r[0]:<34} {r[1]:<12} {r[2]:<12} {r[3]:>4}",
        )
        _print_rows(
            "simulation runs in the last 48 h (scenario, run, status, started)",
            _rows(data, "simulations", report),
            lambda r: f"{r[0]:<9} {r[1]:<14} {r[2]:<11} {r[3]}",
        )

    print()
    if report.warnings:
        print("warnings: " + "; ".join(report.warnings))
    if report.failures:
        print(f"NOT READY ({len(report.failures)} failed): " + "; ".join(report.failures))
        return 1
    print("DEMO READY: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
