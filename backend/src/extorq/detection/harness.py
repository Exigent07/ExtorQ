"""Rule test harness: run every rule's fixture tests against a real, ephemeral ClickHouse.

``extorq rules test`` (and ``tests/rules``) use this module:

1. start ``clickhouse/clickhouse-server:26.8.42.13`` as container
   ``extorq-c2-rules-ch`` on a random 127.0.0.1 port (random throwaway admin
   password passed through a 0600 env-file that is deleted right after start)
2. apply ``infra/clickhouse/migrations/0001_core_tables.sql`` (and 0003 if present)
   with the official ``clickhouse-client`` inside the container
3. create least-privilege users that mirror PLAN section 4.4: ``c2_rules_ro``
   (readonly=1, SELECT on the six telemetry tables) executes rule SQL and
   ``c2_detect`` reads telemetry/alert tables and writes detection tables
4. for each test case: truncate, insert the fixture records through A's
   ``extorq.storage.rows.to_row`` (time-shifted by whole days so bucket
   alignment is preserved and TTLs never expire them), run the real
   :class:`DetectionEngine` for that rule at a fixed ``now`` and assert the
   expectations (alert / no alert, count, confidence, entities) plus integrity
   invariants (evidence ids exist, alert_evidence holds the full set)
5. remove the container (always, also on failure)

Fixture files are JSONL; each line is a SecurityEvent or an ingest record
``{"kind": ..., "data": ...}``. Fixtures are synthetic and labelled as such.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from extorq.contracts.common import utc_now
from extorq.contracts.event import SecurityEvent
from extorq.contracts.ingest import INGEST_RECORD_ADAPTER, RecordKind
from extorq.detection.clients import ClickHouseConnectClient
from extorq.detection.engine import DetectionEngine, EngineConfig
from extorq.detection.registry import LoadedRule, RuleTestCase, load_rules_report

IMAGE = "clickhouse/clickhouse-server:26.8.42.13"
CONTAINER_NAME = "extorq-c2-rules-ch"
OWNER_LABEL = "extorq.owner=c2"
REPO_ROOT = Path(__file__).resolve().parents[4]
MIGRATIONS = ("0001_core_tables.sql", "0003_findings_views.sql")
RULES_RO_TABLES = (
    "events",
    "assets",
    "inventory_items",
    "finding_observations",
    "scan_runs",
    "simulation_runs",
)
DETECT_SELECT = (
    *RULES_RO_TABLES,
    "collector_health",
    "alerts",
    "alert_evidence",
    "rule_runs",
    "detection_rules",
    "investigation_contexts",
    "context_relationships",
    "v_collector_latest",
    "v_alerts",
    "v_findings_current",
    "v_scan_runs_current",
)
DETECT_INSERT = (
    "alerts",
    "alert_evidence",
    "rule_runs",
    "detection_rules",
    "investigation_contexts",
    "context_relationships",
    "pipeline_health",
)
TRUNCATE_TABLES = (
    "events",
    "alerts",
    "alert_evidence",
    "rule_runs",
    "detection_rules",
    "investigation_contexts",
    "context_relationships",
    "assets",
    "collector_health",
    "finding_observations",
    "scan_runs",
    "simulation_runs",
    "inventory_items",
    "pipeline_health",
)
ToRow = Callable[..., dict[str, Any]]


class HarnessError(RuntimeError):
    pass


def _docker() -> str:
    path = shutil.which("docker")
    if not path:
        raise HarnessError("docker CLI not found; the rule harness needs Docker")
    return path


def docker_available() -> bool:
    try:
        subprocess.run(
            [_docker(), "info", "--format", "{{.ServerVersion}}"],
            check=True,
            capture_output=True,
            timeout=20,
        )
        return True
    except (HarnessError, subprocess.SubprocessError, OSError):
        return False


def _run(args: list[str], *, timeout: float = 120, stdin: bytes | None = None) -> str:
    proc = subprocess.run(args, input=stdin, capture_output=True, timeout=timeout, check=False)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise HarnessError(
            f"{Path(args[0]).name} {args[1]} failed: {err[-1] if err else proc.returncode}"
        )
    return proc.stdout.decode("utf-8", "replace")


class EphemeralClickHouse:
    """A throwaway ClickHouse server bound to 127.0.0.1 on a random port."""

    def __init__(self, name: str = CONTAINER_NAME, image: str = IMAGE) -> None:
        self.name = name
        self.image = image
        self.port: int | None = None
        self._admin_password = secrets.token_urlsafe(24)
        self._passwords = {
            "rules_ro": secrets.token_urlsafe(24),
            "detect": secrets.token_urlsafe(24),
        }
        self._clients: dict[str, ClickHouseConnectClient] = {}

    # lifecycle
    def __enter__(self) -> EphemeralClickHouse:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _remove_stale(self) -> None:
        docker = _docker()
        out = _run(
            [
                docker,
                "ps",
                "-a",
                "--filter",
                f"name=^{self.name}$",
                "--format",
                '{{.Names}} {{.Label "extorq.owner"}}',
            ]
        )
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0] == self.name:
                if len(parts) < 2 or parts[1] != "c2":
                    raise HarnessError(
                        f"container {self.name} exists but is not owned by C2; not touching it"
                    )
                _run([docker, "rm", "-f", self.name])

    def start(self) -> None:
        docker = _docker()
        self._remove_stale()
        with tempfile.TemporaryDirectory(prefix="extorq-c2-") as tmp:
            env_file = Path(tmp) / "ch.env"
            fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write("CLICKHOUSE_USER=c2admin\n")
                handle.write(f"CLICKHOUSE_PASSWORD={self._admin_password}\n")
                handle.write("CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1\n")
            _run(
                [
                    docker,
                    "run",
                    "-d",
                    "--name",
                    self.name,
                    "--label",
                    OWNER_LABEL,
                    "--env-file",
                    str(env_file),
                    "-p",
                    "127.0.0.1::8123",
                    "--ulimit",
                    "nofile=262144:262144",
                    self.image,
                ],
                timeout=180,
            )
        try:
            mapping = _run([docker, "port", self.name, "8123/tcp"]).strip().splitlines()[0]
            self.port = int(mapping.rsplit(":", 1)[1])
            self._wait_ready()
            self._apply_migrations()
            self._create_users()
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        for client in self._clients.values():
            with contextlib.suppress(Exception):  # best-effort cleanup
                client.raw.close()
        self._clients.clear()
        with contextlib.suppress(HarnessError):
            _run([_docker(), "rm", "-f", self.name], timeout=60)

    def _wait_ready(self, timeout: float = 90) -> None:
        deadline = time.monotonic() + timeout
        url = f"http://127.0.0.1:{self.port}/ping"
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=2) as resp:
                    if resp.read().strip() == b"Ok.":
                        return
            except (urllib.error.URLError, OSError, TimeoutError):
                pass
            time.sleep(0.5)
        raise HarnessError("ClickHouse did not become ready")

    def _apply_migrations(self) -> None:
        docker = _docker()
        for name in MIGRATIONS:
            path = REPO_ROOT / "infra" / "clickhouse" / "migrations" / name
            if not path.is_file():
                continue
            _run(
                [docker, "exec", "-i", self.name, "clickhouse-client", "--multiquery"],
                stdin=path.read_bytes(),
                timeout=120,
            )

    def _create_users(self) -> None:
        admin = self.client("admin")
        tables = self._existing_objects(admin)
        ro, detect = self._passwords["rules_ro"], self._passwords["detect"]
        admin.raw.command(
            f"CREATE USER c2_rules_ro IDENTIFIED WITH sha256_password BY '{ro}' "
            "DEFAULT DATABASE extorq SETTINGS readonly = 1"
        )
        admin.raw.command(
            f"CREATE USER c2_detect IDENTIFIED WITH sha256_password BY '{detect}' "
            "DEFAULT DATABASE extorq"
        )
        for table in RULES_RO_TABLES:
            admin.raw.command(f"GRANT SELECT ON extorq.{table} TO c2_rules_ro")
        for table in DETECT_SELECT:
            if table in tables:
                admin.raw.command(f"GRANT SELECT ON extorq.{table} TO c2_detect")
        for table in DETECT_INSERT:
            admin.raw.command(f"GRANT INSERT ON extorq.{table} TO c2_detect")

    @staticmethod
    def _existing_objects(admin: ClickHouseConnectClient) -> set[str]:
        rows = admin.select("SELECT name FROM system.tables WHERE database = 'extorq'").rows
        return {str(r[0]) for r in rows}

    def client(self, role: str) -> ClickHouseConnectClient:
        if role in self._clients:
            return self._clients[role]
        import clickhouse_connect

        user, password = {
            "admin": ("c2admin", self._admin_password),
            "rules_ro": ("c2_rules_ro", self._passwords["rules_ro"]),
            "detect": ("c2_detect", self._passwords["detect"]),
        }[role]
        raw = clickhouse_connect.get_client(
            host="127.0.0.1",
            port=self.port,
            username=user,
            password=password,
            database="extorq",
            connect_timeout=10,
            send_receive_timeout=60,
            autogenerate_session_id=False,
        )
        client = ClickHouseConnectClient(raw)
        self._clients[role] = client
        return client

    def truncate(self) -> None:
        admin = self.client("admin")
        for table in TRUNCATE_TABLES:
            admin.raw.command(f"TRUNCATE TABLE IF EXISTS extorq.{table}")


# ── fixtures ─────────────────────────────────────────────────────────


def load_fixture(path: Path) -> list[tuple[RecordKind, BaseModel]]:
    """Parse and validate a JSONL fixture (SecurityEvent lines or ingest records)."""
    records: list[tuple[RecordKind, BaseModel]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            if "kind" in obj and "data" in obj:
                record = INGEST_RECORD_ADAPTER.validate_python(obj)
                records.append((RecordKind(record.kind), record.data))
            else:
                records.append((RecordKind.EVENT, SecurityEvent.model_validate(obj)))
        except Exception as exc:
            raise HarnessError(f"{path.name}:{number}: invalid fixture record: {exc}") from exc
    return records


def _shift(value: Any, delta: timedelta) -> Any:
    if isinstance(value, datetime):
        return value + delta
    if isinstance(value, dict):
        return {k: _shift(v, delta) for k, v in value.items()}
    if isinstance(value, list):
        return [_shift(v, delta) for v in value]
    return value


def shift_records(
    records: Sequence[tuple[RecordKind, BaseModel]], delta: timedelta
) -> list[tuple[RecordKind, BaseModel]]:
    shifted = []
    for kind, model in records:
        data = _shift(model.model_dump(mode="python"), delta)
        shifted.append((kind, type(model).model_validate(data)))
    return shifted


def anchor_time(records: Sequence[tuple[RecordKind, BaseModel]], case: RuleTestCase) -> datetime:
    if case.now is not None:
        return case.now
    times = [m.event_time for _, m in records if isinstance(m, SecurityEvent)]
    if not times:
        raise HarnessError(f"{case.name}: fixture has no events and no 'now'")
    return max(times) + timedelta(seconds=60)


def day_offset(anchor: datetime, today: datetime | None = None) -> timedelta:
    """Whole-day shift that moves ``anchor`` to yesterday (keeps all bucket alignment)."""
    today = today or utc_now()
    return timedelta(days=(today.date() - anchor.date()).days - 1)


def resolve_to_row() -> ToRow | None:
    try:
        from extorq.storage.rows import to_row
    except ImportError:
        return None
    return to_row


def table_for(kind: RecordKind) -> str:
    try:
        from extorq.storage.rows import TABLE_BY_KIND

        return TABLE_BY_KIND[kind]
    except ImportError:
        return {
            RecordKind.EVENT: "events",
            RecordKind.ASSET: "assets",
            RecordKind.INVENTORY_ITEM: "inventory_items",
            RecordKind.FINDING: "finding_observations",
            RecordKind.SCAN_RUN: "scan_runs",
            RecordKind.COLLECTOR_HEALTH: "collector_health",
            RecordKind.SIMULATION_RUN: "simulation_runs",
        }[kind]


def insert_records(
    client: ClickHouseConnectClient,
    records: Iterable[tuple[RecordKind, BaseModel]],
    to_row: ToRow,
    *,
    ingested_at: datetime | None = None,
    batch_id: str = "fixture",
) -> int:
    by_table: dict[str, list[dict[str, Any]]] = {}
    for kind, model in records:
        row = to_row(
            kind,
            model,
            producer_id="fixture-synthetic",
            batch_id=batch_id,
            ingested_at=ingested_at or utc_now(),
        )
        by_table.setdefault(table_for(kind), []).append(row)
    count = 0
    for table, rows in by_table.items():
        client.insert_rows(table, rows)
        count += len(rows)
    return count


# ── running cases ────────────────────────────────────────────────────


@dataclass
class CaseResult:
    rule_id: str
    name: str
    expect: str
    passed: bool
    message: str
    alerts: list[dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0


def fetch_alerts(client: ClickHouseConnectClient, rule_id: str) -> list[dict[str, Any]]:
    result = client.select(
        "SELECT alert_id, confidence, entities, event_count, evidence_event_ids, "
        "evidence_truncated, simulation_run_ids, created_at, updated_at, summary, group_key "
        "FROM alerts FINAL WHERE rule_id = {r:String} ORDER BY first_seen",
        {"r": rule_id},
    )
    return result.dicts()


def check_integrity(client: ClickHouseConnectClient, alerts: list[dict[str, Any]]) -> list[str]:
    problems: list[str] = []
    for alert in alerts:
        ids = list(alert["evidence_event_ids"])
        found = client.select(
            "SELECT uniqExact(event_id) FROM events WHERE event_id IN {ids:Array(String)}",
            {"ids": ids},
        ).rows[0][0]
        if found != len(set(ids)):
            problems.append(
                f"alert {alert['alert_id']}: {len(ids) - found} evidence ids missing from events"
            )
        stored = client.select(
            "SELECT uniqExact(event_id) FROM alert_evidence WHERE alert_id = {a:String}",
            {"a": alert["alert_id"]},
        ).rows[0][0]
        if stored < len(set(ids)):
            problems.append(
                f"alert {alert['alert_id']}: alert_evidence has {stored} < {len(ids)} rows"
            )
        if alert["event_count"] < len(set(ids)):
            problems.append(f"alert {alert['alert_id']}: event_count below evidence size")
    return problems


def run_case(
    ch: EphemeralClickHouse,
    rule: LoadedRule,
    case: RuleTestCase,
    to_row: ToRow,
    *,
    today: datetime | None = None,
) -> CaseResult:
    started = time.monotonic()
    ch.truncate()
    records = load_fixture(case.fixture)
    delta = day_offset(anchor_time(records, case), today)
    records = shift_records(records, delta)
    insert_records(ch.client("admin"), records, to_row)
    now = anchor_time(records, case) if case.now is None else case.now + delta
    engine = DetectionEngine(
        [rule],
        rules_client=ch.client("rules_ro"),
        read_client=ch.client("detect"),
        write_client=ch.client("detect"),
        config=EngineConfig(instance="rules-harness"),
    )
    runs = engine.run_once(now=now, force=True)
    alerts = fetch_alerts(ch.client("admin"), rule.rule_id)
    problems: list[str] = []
    run = runs[0]
    if run.status.value != "succeeded":
        problems.append(f"rule run {run.status.value}: {run.error}")
    if case.expect == "alert" and not alerts:
        problems.append("expected an alert, got none")
    if case.expect == "no_alert" and alerts:
        problems.append(f"expected no alert, got {len(alerts)}")
    if case.alerts is not None and len(alerts) != case.alerts:
        problems.append(f"expected {case.alerts} alert(s), got {len(alerts)}")
    for alert in alerts:
        if case.confidence and alert["confidence"] != case.confidence:
            problems.append(f"confidence {alert['confidence']} != expected {case.confidence}")
        for key, value in case.entities.items():
            if alert["entities"].get(key) != value:
                problems.append(
                    f"entity {key}={alert['entities'].get(key)!r} != expected {value!r}"
                )
    fixture_sims = {
        m.simulation.run_id for _, m in records if isinstance(m, SecurityEvent) and m.simulation
    }
    if alerts and fixture_sims:
        tagged = set().union(*(set(a["simulation_run_ids"]) for a in alerts))
        if not tagged & fixture_sims:
            problems.append("simulation_run_ids of the fixture were not propagated to the alert")
    problems.extend(check_integrity(ch.client("admin"), alerts))
    summary = [
        {
            "alert_id": a["alert_id"],
            "confidence": a["confidence"],
            "event_count": a["event_count"],
            "entities": dict(a["entities"]),
        }
        for a in alerts
    ]
    return CaseResult(
        rule_id=rule.rule_id,
        name=case.name,
        expect=case.expect,
        passed=not problems,
        message="; ".join(problems) if problems else f"{len(alerts)} alert(s)",
        alerts=summary,
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def run_all(
    root: str | os.PathLike[str] | None = "rules",
    *,
    only: Sequence[str] | None = None,
    to_row: ToRow | None = None,
) -> tuple[list[CaseResult], list[str]]:
    """Validate rules, then run every test case. Returns (results, load problems)."""
    rules, problems = load_rules_report(root)
    selected = [r for r in rules if not only or r.rule_id in set(only)]
    resolved = to_row or resolve_to_row()
    if resolved is None:
        raise HarnessError("extorq.storage.rows.to_row is not available")
    results: list[CaseResult] = []
    with EphemeralClickHouse() as ch:
        for rule in selected:
            if not rule.tests:
                results.append(CaseResult(rule.rule_id, "-", "-", False, "rule declares no tests"))
            for case in rule.tests:
                try:
                    results.append(run_case(ch, rule, case, resolved))
                except Exception as exc:  # noqa: BLE001 - report every case
                    results.append(
                        CaseResult(
                            rule.rule_id,
                            case.name,
                            case.expect,
                            False,
                            f"{type(exc).__name__}: {exc}",
                        )
                    )
    return results, [str(p) for p in problems]


def format_results(results: Sequence[CaseResult], problems: Sequence[str]) -> str:
    lines = [f"LOAD-PROBLEM {p}" for p in problems]
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        lines.append(f"{status} {r.rule_id:<12} {r.name:<36} expect={r.expect:<8} {r.message}")
    passed = sum(r.passed for r in results)
    lines.append(
        f"rules harness: {passed}/{len(results)} cases passed, {len(problems)} load problems"
    )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="extorq rules test")
    parser.add_argument("--rules-dir", default=None)
    parser.add_argument("--only", action="append", help="rule id (repeatable)")
    args = parser.parse_args(argv)
    try:
        results, problems = run_all(args.rules_dir, only=args.only)
    except HarnessError as exc:
        print(f"harness error: {exc}")
        return 2
    print(format_results(results, problems))
    return 0 if results and all(r.passed for r in results) and not problems else 1


__all__ = [
    "CaseResult",
    "EphemeralClickHouse",
    "HarnessError",
    "docker_available",
    "insert_records",
    "load_fixture",
    "main",
    "run_all",
    "run_case",
    "shift_records",
]
