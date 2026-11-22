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
from extorq.contracts.identity import service_id
from extorq.contracts.ingest import RecordKind
from extorq.contracts.service import Service, ServiceRef
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


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_duplicate_replay_is_idempotent_for_every_rule(clean, to_row, rule_id) -> None:
    """At-least-once delivery: inserting a positive fixture twice changes nothing."""
    rule = RULES[rule_id]
    case = next(c for c in rule.tests if c.expect == "alert")
    records = harness.load_fixture(case.fixture)
    delta = harness.day_offset(harness.anchor_time(records, case))
    records = harness.shift_records(records, delta)
    now = harness.anchor_time(records, case) if case.now is None else case.now + delta

    def run(copies: int) -> list[tuple[str, int, int]]:
        clean.truncate()
        for i in range(copies):
            harness.insert_records(clean.client("admin"), records, to_row, batch_id=f"copy{i}")
        _engine(clean, rule).run_once(now=now, force=True)
        return sorted(
            (a["alert_id"], a["event_count"], len(a["evidence_event_ids"]))
            for a in _latest(clean, rule_id)
        )

    once = run(1)
    assert once, f"{rule_id}: positive fixture produced no alert"
    assert run(2) == once


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


def test_late_arriving_telemetry_beyond_tolerance_is_caught_up(clean, to_row) -> None:
    """A collector backfilling 2 h of journal: events older than lookback + late tolerance
    are still evaluated because they were ingested after the last run (catch-up)."""
    records = _events(BURST)
    harness.insert_records(clean.client("admin"), records, to_row)
    now = max(m.event_time for _, m in records) + timedelta(hours=2)

    def engine(catchup: int) -> DetectionEngine:
        return DetectionEngine(
            [RULES["VM-001"]],
            rules_client=clean.client("rules_ro"),
            read_client=clean.client("detect"),
            write_client=clean.client("detect"),
            config=EngineConfig(instance="rules-harness", catchup_max_seconds=catchup),
        )

    without = engine(0).run_once(now=now, force=True)[0]
    assert without.alerts_created == 0  # the gap: normal window (20 min) misses the burst

    caught = engine(6 * 3600)
    run = caught.run_once(now=now, force=True)[0]
    assert run.status.value == "succeeded" and run.alerts_created == 1
    assert run.window_start <= min(m.event_time for _, m in records)
    [alert] = _latest(clean, "VM-001")
    assert alert["event_count"] == 18
    again = caught.run_once(now=now + timedelta(minutes=1), force=True)[0]
    assert again.alerts_created == 0 and again.alerts_updated == 0
    assert _versions(clean, alert["alert_id"]) == 1


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


def test_full_rule_window_streams_with_a_one_row_result_page(clean, to_row) -> None:
    rule = RULES["VM-001"]
    boundary = ROOT / "linux" / "tests" / "VM-001" / "positive_bucket_boundary.jsonl"
    records = _events(BURST) + _events(boundary)
    admin = clean.client("admin")
    harness.insert_records(admin, records, to_row)
    now = max(model.event_time for _, model in records) + timedelta(seconds=60)

    baseline = _engine(clean, rule).run_once(now=now, force=True)[0]
    first = sorted((a["alert_id"], a["evidence_event_ids"]) for a in _latest(clean, "VM-001"))
    assert baseline.status.value == "succeeded" and len(first) == 2

    clean.truncate()
    harness.insert_records(admin, records, to_row)
    engine = _engine(clean, rule)
    engine.config.max_rows_per_rule = 1
    streamed = engine.run_once(now=now, force=True)[0]
    assert streamed.status.value == "succeeded"
    assert streamed.rows_matched == baseline.rows_matched
    actual = sorted((a["alert_id"], a["evidence_event_ids"]) for a in _latest(clean, "VM-001"))
    assert actual == first

    replay = engine.run_once(now=now, force=True)[0]
    assert replay.status.value == "succeeded"
    assert (replay.alerts_created, replay.alerts_updated) == (0, 0)
    unresolved = admin.select("SELECT count() FROM alert_evidence WHERE event_time IS NULL").rows[
        0
    ][0]
    assert unresolved == 0


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


def test_alert_service_ids_come_from_evidence_service_refs(clean, to_row) -> None:
    """events.service_id (or the payload's service ref) of the evidence becomes alert.service_ids.

    SYNTHETIC: the burst fixture events get a synthetic ServiceRef for the ssh service, as
    B1's ssh adapter attributes sshd journald lines.
    """
    ssh_service = service_id("linux:lab-vm-01", "host_service", "ssh.service")
    records = [
        (kind, model.model_copy(update={"service": ServiceRef(service_id=ssh_service, name="ssh")}))
        for kind, model in _events(BURST)
    ]
    harness.insert_records(clean.client("admin"), records, to_row)
    now = max(m.event_time for _, m in records) + timedelta(seconds=60)
    run = _engine(clean, RULES["VM-001"]).run_once(now=now, force=True)[0]
    assert run.alerts_created == 1
    [alert] = _latest(clean, "VM-001")
    assert list(alert["service_ids"]) == [ssh_service]


def test_alert_ignores_service_ids_registered_for_another_asset(clean, to_row) -> None:
    """F-IC-6: VM events claiming the macOS ssh service id (registered for macOS) are not
    attributed to that service. SYNTHETIC records."""
    mac_ssh = service_id("macos:workstation-01", "host_service", "com.openssh.sshd")
    records = [
        (kind, model.model_copy(update={"service": ServiceRef(service_id=mac_ssh, name="ssh")}))
        for kind, model in _events(BURST)
    ]
    first = min(m.event_time for _, m in records)
    genuine = Service(
        service_id=mac_ssh,
        asset_id="macos:workstation-01",
        service_kind="host_service",
        service_key="com.openssh.sshd",
        name="ssh",
        category="ssh",
        discovered_via=["launchd_job"],
        adapter_support="implemented",
        monitoring_status="unmonitored",
        first_seen=first,
        last_seen=first,
        observed_by="fixture-synthetic",
    )
    harness.insert_records(clean.client("admin"), [*records, (RecordKind.SERVICE, genuine)], to_row)
    now = max(m.event_time for _, m in records) + timedelta(seconds=60)
    assert _engine(clean, RULES["VM-001"]).run_once(now=now, force=True)[0].alerts_created == 1
    [alert] = _latest(clean, "VM-001")
    assert list(alert["service_ids"]) == []


def test_alert_lists_producing_and_subject_services(clean, to_row) -> None:
    """B1 note 5: unit-file diffs are produced by systemd and ABOUT the unit's service
    (attributes.subject_service_id); the VM-002 alert lists both. SYNTHETIC records."""
    systemd = service_id("linux:lab-vm-01", "host_service", "init.scope")
    unit = service_id("linux:lab-vm-01", "host_service", "extorq-test-0e49c82d82bc.service")
    fixture = ROOT / "linux" / "tests" / "VM-002" / "positive_matrix_unit_created_enabled.jsonl"
    records = []
    for kind, model in _events(fixture):
        if model.event_type.startswith("persistence.systemd."):
            model = model.model_copy(
                update={
                    "service": ServiceRef(service_id=systemd, name="systemd"),
                    "attributes": {**model.attributes, "subject_service_id": unit},
                }
            )
        records.append((kind, model))
    harness.insert_records(clean.client("admin"), records, to_row)
    now = max(m.event_time for _, m in records) + timedelta(seconds=60)
    assert _engine(clean, RULES["VM-002"]).run_once(now=now, force=True)[0].alerts_created == 1
    [alert] = _latest(clean, "VM-002")
    assert sorted(alert["service_ids"]) == sorted([systemd, unit])


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


def test_late_burst_ingested_after_its_window_alerts_exactly_once(clean, to_row) -> None:
    """Regression for the live case of 2026-11-21: a collector backfill delivered a VM-001
    burst about 26 minutes after it happened. The detector had already run over those
    minutes (nothing ingested yet) and its normal 20-minute window no longer reaches them.
    The catch-up must evaluate the burst exactly once: one alert, one stored version, the
    full evidence, and nothing on any later run (inside and beyond the overlap margin).
    Real wall-clock times, because the catch-up keys on events.ingested_time."""
    rule = RULES["VM-001"]
    base = utc_now()
    records = harness.load_fixture(BURST)
    newest = max(m.event_time for _, m in records if isinstance(m, SecurityEvent))
    records = harness.shift_records(records, (base - timedelta(minutes=26)) - newest)
    times = [m.event_time for _, m in records if isinstance(m, SecurityEvent)]
    engine = _engine(clean, rule)  # default EngineConfig: catch-up enabled (6 h horizon)

    # 1. The detector runs while the burst still sits in the collector's outbox.
    early = engine.run_once(now=base, force=True)[0]
    assert early.status.value == "succeeded" and early.rows_matched == 0

    # 2. Backfill: ingested now, 26 minutes after event time.
    harness.insert_records(clean.client("admin"), records, to_row, batch_id="backfill")
    later = base + timedelta(minutes=1)
    normal_start, _ = engine.window_for(rule, later)
    assert max(times) < normal_start  # the normal window alone would never see the burst

    # 3. The next run catches up: exactly one alert with the complete evidence.
    caught = engine.run_once(now=later, force=True)[0]
    assert caught.status.value == "succeeded" and caught.alerts_created == 1
    assert caught.window_start <= min(times)
    [alert] = _latest(clean, "VM-001")
    assert alert["event_count"] == len(records) == 18

    # 4. Later runs re-evaluate inside the overlap margin and then stop: no new alerts,
    #    no new versions, no duplicate evidence.
    for minutes in (2, 4, 10, 20):
        run = engine.run_once(now=base + timedelta(minutes=minutes), force=True)[0]
        assert run.status.value == "succeeded"
        assert (run.alerts_created, run.alerts_updated) == (0, 0), minutes
    assert len(_latest(clean, "VM-001")) == 1
    assert _versions(clean, alert["alert_id"]) == 1
    admin = clean.client("admin")
    stored = admin.select(
        "SELECT count(), uniqExact(event_id) FROM alert_evidence WHERE alert_id = {a:String}",
        {"a": alert["alert_id"]},
    ).rows[0]
    assert tuple(stored) == (18, 18)
    created = admin.select(
        "SELECT sum(alerts_created), count() FROM rule_runs WHERE rule_id = 'VM-001'"
    ).rows[0]
    assert tuple(created) == (1, 6)  # six runs, one alert creation in total
