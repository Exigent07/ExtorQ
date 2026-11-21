"""Engine properties on a real ClickHouse: duplicates, late events, identity, isolation.

All data is the SYNTHETIC VM-001 fixture set (see fixture_builder.py).
"""

from __future__ import annotations

import dataclasses
from datetime import timedelta
from pathlib import Path

import pytest

from extorq.contracts.common import utc_now
from extorq.contracts.event import SecurityEvent
from extorq.detection import harness
from extorq.detection.engine import DetectionEngine, EngineConfig
from extorq.detection.registry import LoadedRule, load_rules_report

ROOT = Path(__file__).resolve().parents[2] / "rules"
RULES = {r.rule_id: r for r in load_rules_report(ROOT)[0]}
BURST = ROOT / "linux" / "tests" / "VM-001" / "positive_burst_external.jsonl"


def _engine(ch: harness.EphemeralClickHouse, *rules: LoadedRule) -> DetectionEngine:
    return DetectionEngine(
        list(rules),
        rules_client=ch.client("rules_ro"),
        read_client=ch.client("detect"),
        write_client=ch.client("detect"),
        config=EngineConfig(instance="rules-harness"),
    )


def _events(path: Path) -> list[tuple]:
    records = harness.load_fixture(path)
    times = [m.event_time for _, m in records if isinstance(m, SecurityEvent)]
    delta = harness.day_offset(max(times))
    return harness.shift_records(records, delta)


def _versions(ch: harness.EphemeralClickHouse, alert_id: str) -> int:
    rows = (
        ch.client("admin")
        .select("SELECT count() FROM alerts WHERE alert_id = {a:String}", {"a": alert_id})
        .rows
    )
    return int(rows[0][0])


def _latest(ch: harness.EphemeralClickHouse, rule_id: str) -> list[dict]:
    return harness.fetch_alerts(ch.client("admin"), rule_id)


@pytest.fixture
def clean(clickhouse: harness.EphemeralClickHouse) -> harness.EphemeralClickHouse:
    clickhouse.truncate()
    return clickhouse


def test_duplicate_inserts_do_not_inflate_counts_or_alerts(clean, to_row) -> None:
    records = _events(BURST)
    now = max(m.event_time for _, m in records) + timedelta(seconds=60)
    admin = clean.client("admin")
    harness.insert_records(admin, records, to_row, batch_id="first")
    harness.insert_records(admin, records, to_row, batch_id="replay")  # at-least-once replay
    raw_rows = admin.select("SELECT count() FROM events").rows[0][0]
    assert raw_rows == 2 * len(records)  # duplicates really are stored twice before merges

    engine = _engine(clean, RULES["VM-001"])
    first = engine.run_once(now=now, force=True)[0]
    alerts = _latest(clean, "VM-001")
    assert len(alerts) == 1
    assert alerts[0]["event_count"] == len(records) == 18
    assert first.alerts_created == 1

    second = engine.run_once(now=now + timedelta(seconds=60), force=True)[0]
    assert second.alerts_created == 0 and second.alerts_updated == 0
    assert _versions(clean, alerts[0]["alert_id"]) == 1  # re-running wrote no new version
    evidence = admin.select(
        "SELECT count(), uniqExact(event_id) FROM alert_evidence WHERE alert_id = {a:String}",
        {"a": alerts[0]["alert_id"]},
    ).rows[0]
    assert tuple(evidence) == (18, 18)


def test_late_events_extend_the_same_alert(clean, to_row) -> None:
    records = _events(BURST)
    events = sorted((r for r in records), key=lambda r: r[1].event_time)
    # Hold back the second connection (port 50101): it arrives late, after the alert exists.
    late = [r for r in events if r[1].network and r[1].network.src_port == 50101]
    early = [r for r in events if r not in late]
    assert len(late) == 3 and len(early) == 15
    admin = clean.client("admin")
    harness.insert_records(admin, early, to_row, batch_id="early")
    now = max(m.event_time for _, m in records) + timedelta(seconds=60)
    engine = _engine(clean, RULES["VM-001"])
    run1 = engine.run_once(now=now, force=True)[0]
    [alert1] = _latest(clean, "VM-001")
    assert run1.alerts_created == 1 and alert1["event_count"] == 15

    harness.insert_records(admin, late, to_row, batch_id="late")
    run2 = engine.run_once(now=now + timedelta(minutes=2), force=True)[0]
    [alert2] = _latest(clean, "VM-001")
    assert run2.alerts_created == 0 and run2.alerts_updated == 1
    assert alert2["alert_id"] == alert1["alert_id"]
    assert alert2["event_count"] == 18
    assert alert2["created_at"] == alert1["created_at"]
    assert alert2["updated_at"] > alert1["updated_at"]
    assert _versions(clean, alert1["alert_id"]) == 2
    stored = admin.select(
        "SELECT uniqExact(event_id) FROM alert_evidence WHERE alert_id = {a:String}",
        {"a": alert1["alert_id"]},
    ).rows[0][0]
    assert stored == 18


def test_identity_is_stable_across_reruns_and_fresh_state(clean, to_row) -> None:
    boundary = ROOT / "linux" / "tests" / "VM-001" / "positive_bucket_boundary.jsonl"
    records = _events(BURST) + _events(boundary)
    admin = clean.client("admin")
    harness.insert_records(admin, records, to_row)
    now = max(m.event_time for _, m in records) + timedelta(seconds=60)
    _engine(clean, RULES["VM-001"]).run_once(now=now, force=True)
    first_ids = sorted(a["alert_id"] for a in _latest(clean, "VM-001"))
    assert len(first_ids) == 2

    # Fresh detector state (no stored alerts), same telemetry, later evaluation time.
    for table in ("alerts", "alert_evidence", "rule_runs"):
        admin.raw.command(f"TRUNCATE TABLE extorq.{table}")
    _engine(clean, RULES["VM-001"]).run_once(now=now + timedelta(minutes=3), force=True)
    assert sorted(a["alert_id"] for a in _latest(clean, "VM-001")) == first_ids


def test_failing_rule_does_not_stop_others_and_is_recorded(clean, to_row) -> None:
    good = RULES["VM-001"]
    broken = dataclasses.replace(
        good,
        metadata=good.metadata.model_copy(update={"rule_id": "ZZ-999"}),
        query_text=good.query_text.replace(
            "assumeNotNull(src_ip)", "assumeNotNull(no_such_column)"
        ),
    )
    harness.insert_records(clean.client("admin"), _events(BURST), to_row)
    now = utc_now()
    runs = {r.rule_id: r for r in _engine(clean, broken, good).run_once(now=now, force=True)}
    assert runs["ZZ-999"].status.value == "failed"
    assert runs["ZZ-999"].error and "no_such_column" in runs["ZZ-999"].error.lower()
    assert runs["VM-001"].status.value == "succeeded"
    stored = (
        clean.client("admin").select("SELECT rule_id, status FROM rule_runs ORDER BY rule_id").rows
    )
    assert [tuple(r) for r in stored] == [("VM-001", "succeeded"), ("ZZ-999", "failed")]


def test_rule_sql_runs_with_readonly_identity(clean) -> None:
    """Even if the static validator were bypassed, rules_ro cannot read or write alerts."""
    good = RULES["VM-001"]
    sneaky = dataclasses.replace(
        good,
        metadata=good.metadata.model_copy(update={"rule_id": "ZZ-998"}),
        query_text="SELECT * FROM alerts WHERE created_at >= {window_start:DateTime64(3, 'UTC')} "
        "AND created_at < {window_end:DateTime64(3, 'UTC')}",
    )
    run = _engine(clean, sneaky).run_once(now=utc_now(), force=True)[0]
    assert run.status.value == "failed"
    assert run.error and ("497" in run.error or "privileges" in run.error.lower())


def test_missing_sources_reported_when_no_telemetry(clean) -> None:
    run = _engine(clean, RULES["VM-001"]).run_once(now=utc_now(), force=True)[0]
    assert run.status.value == "succeeded"
    assert run.missing_sources == ["linux.journald"]
    assert run.rows_matched == 0 and run.alerts_created == 0


def test_detection_rules_registered(clean) -> None:
    engine = _engine(clean, RULES["VM-001"])
    engine.register_rules(list(RULES.values()))
    rows = (
        clean.client("admin")
        .select(
            "SELECT rule_id, version, enabled, query_sha256 "
            "FROM detection_rules FINAL ORDER BY rule_id"
        )
        .dicts()
    )
    by_id = {r["rule_id"]: r for r in rows}
    assert set(by_id) == set(RULES)
    assert by_id["VM-001"]["query_sha256"] == RULES["VM-001"].metadata.query_sha256
    assert all(r["enabled"] == 1 for r in rows)
