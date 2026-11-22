"""extorq.detection.dryrun on a real (ephemeral) ClickHouse: read-only, engine-identical.

Data: the VM-002 matrix fixture (captured VM records parsed by the Linux collector) and a
SYNTHETIC CORR-002 fixture.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from extorq.contracts.event import SecurityEvent
from extorq.detection import dryrun, harness
from extorq.detection.engine import DetectionEngine, EngineConfig
from extorq.detection.registry import load_rules_report

ROOT = Path(__file__).resolve().parents[2] / "rules"
RULES = {r.rule_id: r for r in load_rules_report(ROOT)[0]}


@pytest.fixture
def clean(clickhouse: harness.EphemeralClickHouse) -> harness.EphemeralClickHouse:
    clickhouse.truncate()
    return clickhouse


def _load(path: Path) -> tuple[list, object, object]:
    records = harness.load_fixture(path)
    times = [m.event_time for _, m in records if isinstance(m, SecurityEvent)]
    records = harness.shift_records(records, harness.day_offset(max(times)))
    times = [m.event_time for _, m in records if isinstance(m, SecurityEvent)]
    return records, min(times) - timedelta(minutes=5), max(times) + timedelta(minutes=5)


COUNTS_SQL = (
    "SELECT (SELECT count() FROM extorq.alerts), (SELECT count() FROM extorq.alert_evidence), "
    "(SELECT count() FROM extorq.rule_runs), (SELECT count() FROM extorq.pipeline_health), "
    "(SELECT count() FROM extorq.detection_rules)"
)


def _counts(ch: harness.EphemeralClickHouse) -> tuple[int, ...]:
    return tuple(int(v) for v in ch.client("admin").select(COUNTS_SQL).rows[0])


def test_dry_run_reports_new_then_stored_and_never_writes(clean, to_row) -> None:
    rule = RULES["VM-002"]
    path = ROOT / "linux" / "tests" / "VM-002" / "positive_matrix_unit_created_enabled.jsonl"
    records, start, end = _load(path)
    harness.insert_records(clean.client("admin"), records, to_row)

    before = _counts(clean)
    lines = dryrun.run(
        rule, start, end, rules_client=clean.client("rules_ro"), read_client=clean.client("detect")
    )
    assert _counts(clean) == before  # nothing written
    assert lines[0].startswith(f"VM-002 v{rule.version}") and "1 row(s)" in lines[0]
    assert any(line.startswith("row 1: alert ") and line.endswith(" NEW") for line in lines)
    assert any("file.audit.watch linux.auditd syscall=openat" in line for line in lines)

    DetectionEngine(
        [rule],
        rules_client=clean.client("rules_ro"),
        read_client=clean.client("detect"),
        write_client=clean.client("detect"),
        config=EngineConfig(instance="rules-harness"),
    ).run_once(now=end, force=True)
    [alert] = harness.fetch_alerts(clean.client("admin"), "VM-002")
    lines = dryrun.run(
        rule, start, end, rules_client=clean.client("rules_ro"), read_client=clean.client("detect")
    )
    stored = f"alert {alert['alert_id']} STORED (v{rule.version}, high"
    assert any(stored in line for line in lines)
    not_produced = f"stored evidence not produced by v{rule.version} in this window: 0"
    assert any(not_produced in line for line in lines)


def test_dry_run_shows_removal_as_context_not_evidence(clean, to_row) -> None:
    rule = RULES["CORR-002"]
    path = (
        ROOT / "correlation" / "tests" / "CORR-002" / "positive_audit_create_removal_context.jsonl"
    )
    records, start, end = _load(path)
    harness.insert_records(clean.client("admin"), records, to_row)
    lines = dryrun.run(
        rule, start, end, rules_client=clean.client("rules_ro"), read_client=clean.client("detect")
    )
    text = "\n".join(lines)
    assert "syscall=unlinkat" not in text  # the removal is never evidence
    assert "feature context_unit_removals=old-agent.service" in text
    assert "1 x file.audit.watch linux.auditd syscall=openat" in text


def test_read_only_client_refuses_writes() -> None:
    class Fake:
        def select(self, sql, parameters=None):  # pragma: no cover - not called
            raise AssertionError

        def insert_rows(self, table, rows):  # pragma: no cover - must never be reached
            raise AssertionError("inner client must not be called")

    with pytest.raises(RuntimeError, match="writes are not allowed"):
        dryrun.ReadOnlyClient(Fake()).insert_rows("alerts", [{}])


def test_parse_time_requires_a_time_zone() -> None:
    assert dryrun.parse_time("2026-11-21T14:00:00Z").tzinfo is not None
    with pytest.raises(Exception, match="time zone"):
        dryrun.parse_time("2026-11-21T14:00:00")
