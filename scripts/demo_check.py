#!/usr/bin/env python3
"""Read-only demo readiness report (``make demo-check``).

Checks, without changing anything (exit 1 when any FAIL check fails; WARN never fails):

* compose services: core + full profile running and healthy (``ai-worker`` optional);
* the ingest gateway (``/healthz``; ``/v1/status`` with the least-privileged
  ``extorq-selftest`` token: contract schema, spool depth, dead letters);
* the analyst API (``/healthz``; authenticated viewer ``GET /api/v1/health``), the
  console (``/healthz``, ``/login``) and Grafana (``/api/health``; the provisioned
  ClickHouse datasource health with the admin account);
* ClickHouse as ``extorq_api_ro`` (debug proxy 127.0.0.1:18123 when it is up, otherwise
  the same read-only queries run inside the ``api`` container, so the proxy can stay
  off during the demo, F-01):

  - every migration file is applied (schema 2.0 needs 0008);
  - telemetry per asset class (macOS, Linux, Kubernetes, GitHub): state records
    (assets, inventory, services) received recently, and events received recently for
    the classes whose sources never go quiet (see :data:`ASSET_CLASSES`);
  - every enabled host collector (``config/collectors``) reports ok (degraded: WARN)
    with a fresh ``last_success_at`` (age <= max(3 x interval, 180 s));
  - every rule in ``rules/`` ran in the last 15 min and has no failed run in 24 h;
  - WARN on quarantined records or refused (401/403) requests in the last 24 h;
  - informational: events per source, pipeline health, alerts per rule, services;

* detection tests: the newest ``var/reports/detection-tests-*.json`` report that covers
  each asset class (``make test-detections``) shows every positive test passed (the rule
  alerted) and every negative control passed (the rule stayed silent).

Prints names, counts, ids and timestamps only: never tokens, passwords or telemetry.
"""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
REPORTS_DIR = REPO / "var" / "reports"
REPORT_SCHEMA = "extorq.detection-tests.report.v2"
REQUIRED_SERVICES = ("clickhouse", "ingest", "writer", "detector", "api", "frontend", "grafana")
OPTIONAL_SERVICES = ("ai-worker",)
RULE_RUN_MAX_AGE_SECONDS = 15 * 60
MIN_STALE_SECONDS = 180
TOKEN_WARN_SECONDS = 24 * 3600
#: Older detection-test reports are still evaluated but flagged.
REPORT_WARN_AGE_SECONDS = 24 * 3600
#: Detection-test reports read at most (newest first).
MAX_REPORTS = 50
#: PLAN section 12: at least five distinct real tests per asset class.
MIN_TESTS_PER_ASSET = 5
API = "http://127.0.0.1:8000"
CONSOLE = "http://127.0.0.1:3000"
GRAFANA = "http://127.0.0.1:3001"


@dataclass(frozen=True)
class AssetClass:
    """Freshness expectations for one monitored asset class."""

    label: str
    #: Namespace of the class's asset ids (``<namespace>:<name>``).
    namespace: str
    #: Max age of the newest state record (assets, inventory, services). Every collector
    #: re-sends its asset at least every 15 min (asset refresh), so 3 x 15 min.
    max_state_age: int = 45 * 60
    #: Max age of the newest event, or None when the class only has events on activity.
    max_event_age: int | None = None


#: Linux journald always has entries (cron, systemd, the collector's own SSH sessions are
#: recorded, labelled self) and the Kubernetes API server writes audit events constantly.
#: macOS unified-log predicates are narrow and GitHub events need repository activity, so
#: for those two classes only the state records are required.
ASSET_CLASSES: dict[str, AssetClass] = {
    "macos": AssetClass("macOS host", "macos"),
    "linux": AssetClass("Ubuntu VM", "linux", max_event_age=15 * 60),
    "kubernetes": AssetClass("Kubernetes cluster", "k8s", max_event_age=15 * 60),
    "github": AssetClass("GitHub repository", "github"),
}


def asset_class_of(namespace: str) -> str:
    """ASSET_CLASSES key for an asset-id namespace (``other`` when unknown)."""
    for key, spec in ASSET_CLASSES.items():
        if spec.namespace == namespace:
            return key
    return "other"


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
    """A secret's value for an authenticated request (never printed)."""
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

#: Asset ids are ``<namespace>:<name>`` (``macos:``, ``linux:``, ``k8s:``, ``github:``); the
#: queries group by that namespace and :func:`asset_class_of` maps it to ASSET_CLASSES.
QUERIES: dict[str, tuple[str, dict[str, Any]]] = {
    "migrations": (
        "SELECT concat(version, '_', name) FROM extorq.schema_migrations FINAL ORDER BY version",
        {},
    ),
    # Newest event per asset namespace (ingestion time: proves the pipeline delivers now).
    "events_by_class": (
        "SELECT splitByChar(':', asset_id)[1] AS namespace, "
        "dateDiff('second', max(ingested_time), now64(3)), uniqExact(event_id) "
        "FROM extorq.events WHERE ingested_time > now64(3) - INTERVAL 24 HOUR "
        "GROUP BY namespace ORDER BY namespace",
        {},
    ),
    # Newest state record (asset, inventory item, service) per asset namespace.
    "state_by_class": (
        "SELECT namespace, min(age) FROM ("
        " SELECT splitByChar(':', asset_id)[1] AS namespace,"
        " dateDiff('second', max(ingested_at), now64(3)) AS age FROM extorq.assets"
        " WHERE ingested_at > now64(3) - INTERVAL 24 HOUR GROUP BY namespace"
        " UNION ALL"
        " SELECT splitByChar(':', asset_id)[1] AS namespace,"
        " dateDiff('second', max(ingested_at), now64(3)) AS age FROM extorq.inventory_items"
        " WHERE ingested_at > now64(3) - INTERVAL 24 HOUR GROUP BY namespace"
        " UNION ALL"
        " SELECT splitByChar(':', ifNull(asset_id, ''))[1] AS namespace,"
        " dateDiff('second', max(ingested_at), now64(3)) AS age FROM extorq.services"
        " WHERE ingested_at > now64(3) - INTERVAL 24 HOUR GROUP BY namespace"
        ") GROUP BY namespace ORDER BY namespace",
        {},
    ),
    "collectors": (
        "SELECT collector_id, collector_type, status, toString(last_success_at), "
        "dateDiff('second', last_success_at, now64(3)), interval_seconds, records_buffered, "
        "JSONExtractRaw(details, 'token_expires_in_seconds'), "
        "dateDiff('second', last_reported_at, now64(3)), "
        "JSONExtractInt(details, 'outbox_dead') "
        "FROM extorq.v_collector_latest ORDER BY collector_id",
        {},
    ),
    "rules": (
        "SELECT rule_id, last_status, toString(last_run_at), "
        "dateDiff('second', last_run_at, now64(3)), runs_24h, failures_24h, missing_sources "
        "FROM extorq.v_rule_latest_run ORDER BY rule_id",
        {},
    ),
    "quarantine": (
        "SELECT producer_id, substring(reason, 1, 80) AS reason_prefix, count() "
        "FROM extorq.ingest_quarantine WHERE received_at > now64(3) - INTERVAL 24 HOUR "
        "GROUP BY producer_id, reason_prefix ORDER BY count() DESC LIMIT 20",
        {},
    ),
    "audit": (
        "SELECT decision, ifNull(authenticated_producer, '-'), substring(reason, 1, 80), count() "
        "FROM extorq.ingest_audit WHERE occurred_at > now64(3) - INTERVAL 24 HOUR "
        "GROUP BY 1, 2, 3 ORDER BY count() DESC LIMIT 20",
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


def _age(seconds: Any) -> str:
    return "never" if seconds is None else f"{int(seconds)} s ago"


def check_telemetry(
    report: Report, events: list[list[Any]], state: list[list[Any]]
) -> dict[str, tuple[int | None, int]]:
    """Per asset class: recent state records, and recent events where sources never pause.

    Returns ``{class: (newest event age or None, events in 24 h)}`` for the caller.
    """
    section("telemetry per asset class (ingested in the last 24 h)")
    event_rows: dict[str, tuple[int, int]] = {}
    for namespace, age, count in ((str(r[0]), int(r[1]), int(r[2])) for r in events):
        key = asset_class_of(namespace)
        previous = event_rows.get(key)
        event_rows[key] = (
            min(age, previous[0]) if previous else age,
            count + (previous[1] if previous else 0),
        )
    state_ages: dict[str, int] = {}
    for namespace, age in ((str(r[0]), int(r[1])) for r in state):
        key = asset_class_of(namespace)
        state_ages[key] = min(age, state_ages.get(key, age))
    seen: dict[str, tuple[int | None, int]] = {}
    for key, spec in ASSET_CLASSES.items():
        event_age, event_count = event_rows.get(key, (None, 0))
        seen[key] = (event_age, event_count)
        state_age = state_ages.get(key)
        state_ok = state_age is not None and state_age <= spec.max_state_age
        report.check(
            state_ok,
            f"{spec.label} ({spec.namespace}:*) state records",
            f"newest {_age(state_age)} (limit {spec.max_state_age} s)",
        )
        if spec.max_event_age is not None:
            fresh = event_age is not None and event_age <= spec.max_event_age
            report.check(
                fresh,
                f"{spec.label} events",
                f"{event_count} in 24 h, newest {_age(event_age)} (limit {spec.max_event_age} s)",
            )
        else:
            report.check(
                event_count > 0,
                f"{spec.label} events",
                f"{event_count} in 24 h, newest {_age(event_age)} (only on activity)",
                warn_only=True,
            )
    other = event_rows.get("other")
    if other:
        report.check(
            False,
            "events of unknown asset classes",
            f"{other[1]} in 24 h (asset ids outside macos:/linux:/k8s:/github:)",
            warn_only=True,
        )
    return seen


def check_collectors(report: Report, rows: list[list[Any]]) -> None:
    section("collectors (enabled host collectors ok and fresh; degraded is a warning)")
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
        detail = (
            f"{status}, last success {age} s ago (limit {limit} s), buffered {row[6]}, "
            f"dead letters {row[9] or 0}"
        )
        if status == "degraded" and fresh:
            report.check(False, collector_id, detail, warn_only=True)
        else:
            report.check(status == "ok" and fresh, collector_id, detail)
        if str(row[1]) == "k8s_inventory" and row[7] not in (None, "", "null"):
            try:
                remaining = float(str(row[7])) - float(row[8] or 0)
            except ValueError:
                continue
            report.check(
                remaining > TOKEN_WARN_SECONDS,
                f"{collector_id} credential lifetime",
                f"~{remaining / 3600:.1f} h left (re-mint: infra/kind/kind.sh token)",
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


def check_ingest_problems(
    report: Report, quarantine: list[list[Any]], audit: list[list[Any]]
) -> None:
    section("ingest problems in the last 24 h (quarantined records, refused requests)")
    total = sum(int(r[2]) for r in quarantine)
    report.check(total == 0, "quarantined records", str(total), warn_only=True)
    for row in quarantine[:10]:
        report.info(f"{row[0]:<26} {int(row[2]):>6}  {row[1]}")
    refused = sum(int(r[3]) for r in audit)
    report.check(refused == 0, "refused requests (401/403)", str(refused), warn_only=True)
    for row in audit[:10]:
        report.info(f"{row[0]:<15} {row[1]:<26} {int(row[3]):>6}  {row[2]}")


# ── detection-test reports (``make test-detections``) ─────────────────

_ASSET_ALIASES = {
    "k8s": "kubernetes",
    "kind": "kubernetes",
    "mac": "macos",
    "darwin": "macos",
    "vm": "linux",
    "ubuntu": "linux",
    "gh": "github",
}
_PASS = {"pass", "passed", "ok", "success", "succeeded"}
_FAIL = {"fail", "failed", "error", "errored", "failure", "timeout", "timed_out"}
_SKIP = {"skip", "skipped", "not_run", "blocked", "unavailable"}


@dataclass(frozen=True)
class TestResult:
    """One detection-test result, normalised from the runner's report."""

    test_id: str
    asset: str
    rule_id: str
    positive: bool | None
    outcome: str  # pass | fail | skip | unknown
    detail: str


def _first(item: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if item.get(key) not in (None, ""):
            return item[key]
    return None


def normalise_asset(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = text.split(":", 1)[0] if ":" in text else text
    return _ASSET_ALIASES.get(text, text) or "unknown"


def normalise_result(item: dict[str, Any]) -> TestResult:
    """Tolerant mapping of one report entry (field names agreed in interface-changes/P.md)."""
    polarity = str(_first(item, "kind", "polarity", "type", "expectation") or "").lower()
    expect_alert = _first(item, "expect_alert", "expected_alert", "should_alert")
    positive: bool | None
    if polarity.startswith("pos"):
        positive = True
    elif polarity.startswith("neg"):
        positive = False
    elif isinstance(expect_alert, bool):
        positive = expect_alert
    else:
        positive = None
    raw = _first(item, "status", "outcome", "result", "verdict")
    passed = item.get("passed")
    if isinstance(raw, str) and raw.strip().lower() in _PASS | _FAIL | _SKIP:
        word = raw.strip().lower()
        outcome = "pass" if word in _PASS else "fail" if word in _FAIL else "skip"
    elif isinstance(passed, bool):
        outcome = "pass" if passed else "fail"
    else:
        outcome = "unknown"
    detail = str(_first(item, "detail", "reason", "message", "error") or "")[:160]
    return TestResult(
        test_id=str(_first(item, "test_id", "id", "name") or "?")[:80],
        asset=normalise_asset(_first(item, "asset", "asset_class", "target")),
        rule_id=str(_first(item, "rule_id", "rule") or "?")[:20],
        positive=positive,
        outcome=outcome,
        detail=detail,
    )


def report_results(document: Any) -> list[TestResult]:
    """Every result of one report document (a list, or a mapping with results/tests)."""
    items: Any = document
    if isinstance(document, dict):
        items = _first(document, "results", "tests", "cases") or []
    if not isinstance(items, list):
        return []
    if isinstance(document, dict) and document.get("schema") == REPORT_SCHEMA:
        results = []
        for item in items:
            if not isinstance(item, dict):
                continue
            positive = item.get("positive")
            negative = item.get("negative")
            verified = isinstance(positive, dict) and any(
                isinstance(alert, dict) and bool(alert.get("verified_evidence"))
                for alert in positive.get("alerts") or []
            )
            common = {k: item.get(k) for k in ("test_id", "asset", "rule_id")}
            for kind, phase in (("positive", positive), ("negative", negative)):
                values = phase if isinstance(phase, dict) else {}
                status = values.get("outcome", "unknown")
                if status == "passed" and (
                    not item.get("rule_version")
                    or not item.get("cleanup_ok")
                    or (kind == "positive" and not verified)
                    or (kind == "negative" and not values.get("conclusive_run"))
                ):
                    status = "failed"
                results.append(normalise_result({**common, "kind": kind, "status": status}))
        return results
    return [normalise_result(item) for item in items if isinstance(item, dict)]


def report_time(document: Any, path: Path) -> float:
    """Epoch seconds the report finished (its own timestamps, else the file mtime)."""
    if isinstance(document, dict):
        stamp = _first(document, "finished_at", "completed_at", "generated_at", "started_at")
        if isinstance(stamp, str):
            try:
                return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
            except ValueError:
                pass
    return path.stat().st_mtime


def newest_per_asset(
    reports: Iterable[tuple[Path, float, list[TestResult]]],
) -> dict[str, tuple[Path, float, list[TestResult]]]:
    """For each asset class, the newest report that contains results for it."""
    chosen: dict[str, tuple[Path, float, list[TestResult]]] = {}
    for path, stamp, results in reports:
        for asset in {r.asset for r in results}:
            current = chosen.get(asset)
            if current is None or stamp > current[1]:
                chosen[asset] = (path, stamp, [r for r in results if r.asset == asset])
    return chosen


def load_reports(directory: Path) -> list[tuple[Path, float, list[TestResult]]]:
    paths = sorted(
        directory.glob("detection-tests-*.json"), key=lambda p: p.stat().st_mtime, reverse=True
    )[:MAX_REPORTS]
    loaded: list[tuple[Path, float, list[TestResult]]] = []
    for path in paths:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(document, dict) or document.get("schema") != REPORT_SCHEMA:
            continue
        loaded.append((path, report_time(document, path), report_results(document)))
    return loaded


def check_detection_tests(report: Report, directory: Path = REPORTS_DIR) -> None:
    section("detection tests (newest report per asset: positives alert, negatives stay silent)")
    reports = load_reports(directory)
    if not reports:
        report.check(False, "detection-test report", "none in var/reports (make test-detections)")
        return
    now = time.time()
    chosen = newest_per_asset(reports)
    for asset in ASSET_CLASSES:
        if asset not in chosen:
            report.check(False, f"{asset} detection tests", "no report covers this asset")
            continue
        path, stamp, results = chosen[asset]
        positives = [r for r in results if r.positive is True]
        negatives = [r for r in results if r.positive is False]
        bad = [r for r in results if r.outcome != "pass" or r.positive is None]
        when = datetime.fromtimestamp(stamp, UTC).isoformat(timespec="seconds")
        detail = (
            f"{sum(r.outcome == 'pass' for r in positives)}/{len(positives)} positives alerted, "
            f"{sum(r.outcome == 'pass' for r in negatives)}/{len(negatives)} negatives silent "
            f"({path.name}, {when})"
        )
        report.check(not bad and bool(positives), f"{asset} detection tests", detail)
        for result in bad[:10]:
            kind = {True: "positive", False: "negative", None: "unknown kind"}[result.positive]
            report.info(
                f"{result.test_id} [{result.rule_id}, {kind}]: {result.outcome}"
                + (f" ({result.detail})" if result.detail else "")
            )
        distinct = {r.test_id for r in positives}
        report.check(
            len(distinct) >= MIN_TESTS_PER_ASSET,
            f"{asset} test coverage",
            f"{len(distinct)} distinct positive tests (PLAN section 12: >= {MIN_TESTS_PER_ASSET})",
        )
        report.check(
            now - stamp <= REPORT_WARN_AGE_SECONDS,
            f"{asset} report age",
            f"{int(now - stamp)} s",
            warn_only=True,
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
        check_telemetry(
            report, _rows(data, "events_by_class", report), _rows(data, "state_by_class", report)
        )
        check_collectors(report, _rows(data, "collectors", report))
        check_rules(report, _rows(data, "rules", report))
        check_ingest_problems(
            report, _rows(data, "quarantine", report), _rows(data, "audit", report)
        )
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
    check_detection_tests(report)

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
