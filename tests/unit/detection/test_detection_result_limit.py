"""Large rule results preserve the evaluation window and completion watermark."""

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from extorq.contracts.alert import RuleRunStatus
from extorq.detection.alerts import required_columns
from extorq.detection.clients import QueryRows
from extorq.detection.engine import DetectionEngine, EngineConfig
from extorq.detection.registry import load_rules

RULE = next(rule for rule in load_rules() if rule.rule_id == "VM-001")
NOW = datetime(2026, 11, 22, tzinfo=UTC)
EVENT_TIME = NOW - timedelta(minutes=2)
ASSET = "linux:lab-vm-01"


def _page(group: str, eid: str) -> QueryRows:
    return QueryRows(
        list(required_columns(RULE)),
        [],
        [(group, ASSET, "linux_host", EVENT_TIME, EVENT_TIME, 1, [eid], {}, {}, "low", EVENT_TIME)],
    )


@pytest.fixture
def detector() -> tuple[DetectionEngine, MagicMock, MagicMock]:
    db = MagicMock()
    rules_client = MagicMock()
    engine = DetectionEngine(
        [RULE],
        rules_client=rules_client,
        read_client=db,
        write_client=db,
        config=EngineConfig(max_rows_per_rule=1, catchup_max_seconds=0),
    )

    def select(sql: str, params: dict) -> QueryRows:
        rows = []
        if sql.startswith("SELECT event_id, asset_id, event_time, source_type, event_type"):
            rows = [
                (eid, ASSET, EVENT_TIME, "linux.journald", "auth.ssh.login_failed")
                for eid in params["ids"]
            ]
        return QueryRows([], [], rows)

    db.select.side_effect = select
    return engine, db, rules_client


def test_saturated_result_reads_all_batches_at_the_same_window(detector) -> None:
    engine, db, rules_client = detector
    sentinel = QueryRows([], [], [(), ()])
    rules_client.select.return_value = sentinel
    rules_client.select_batches.return_value = (
        result for result in (_page("first", "1" * 32), _page("second", "2" * 32))
    )

    run = engine.evaluate(RULE, NOW)
    assert run.status is RuleRunStatus.SUCCEEDED
    assert run.rows_matched == run.alerts_created == 2
    assert engine._last_success[RULE.rule_id] == NOW
    probe_sql, probe_params = rules_client.select.call_args.args
    stream_sql, stream_params, chunk_size = rules_client.select_batches.call_args.args
    assert chunk_size == 1
    assert probe_params.pop("_extorq_result_limit") == 2
    assert stream_params == probe_params
    assert "LIMIT {_extorq_result_limit:UInt64}" in probe_sql
    assert stream_sql.endswith("ORDER BY group_key, first_seen, bucket_start")
    evidence_inserts = [
        call.args[1][0]
        for call in db.insert_rows.call_args_list
        if call.args[0] == "alert_evidence"
    ]
    assert [row["event_id"] for row in evidence_inserts] == ["1" * 32, "2" * 32]
    assert all(row["event_time"] == EVENT_TIME for row in evidence_inserts)


def test_interrupted_stream_fails_without_advancing_watermark(detector) -> None:
    engine, _, rules_client = detector
    prior = NOW - timedelta(minutes=1)
    rules_client.select.return_value = QueryRows([], [], [])
    assert engine.evaluate(RULE, prior).status is RuleRunStatus.SUCCEEDED

    def interrupted() -> Generator[QueryRows, None, None]:
        yield _page("first", "1" * 32)
        raise ConnectionError("stream interrupted")

    rules_client.select.return_value = QueryRows([], [], [(), ()])
    rules_client.select_batches.return_value = interrupted()
    run = engine.evaluate(RULE, NOW)
    assert run.status is RuleRunStatus.FAILED
    assert run.rows_matched == run.alerts_created == 1
    assert "stream interrupted" in (run.error or "")
    assert engine._last_success[RULE.rule_id] == prior

    rules_client.select.return_value = _page("second", "2" * 32)
    resumed = engine.evaluate(RULE, NOW + timedelta(minutes=1))
    assert resumed.status is RuleRunStatus.SUCCEEDED
    assert (resumed.window_start, resumed.window_end) == (run.window_start, run.window_end)
    assert engine._last_success[RULE.rule_id] == NOW


@pytest.mark.parametrize(
    "evidence_asset,evidence_time",
    [
        ("linux:unrelated", EVENT_TIME),
        (ASSET, NOW),
    ],
)
def test_evidence_from_another_asset_or_window_is_rejected(
    detector, evidence_asset: str, evidence_time: datetime
) -> None:
    engine, db, rules_client = detector
    rules_client.select.return_value = _page("first", "1" * 32)
    db.select.side_effect = [
        QueryRows([], [], []),
        QueryRows(
            [],
            [],
            [("1" * 32, evidence_asset, evidence_time, "linux.journald", "auth.ssh.login_failed")],
        ),
    ]
    run = engine.evaluate(RULE, NOW)
    assert run.status is RuleRunStatus.FAILED
    assert run.alerts_created == 0
    assert "outside" in (run.error or "")
    db.insert_rows.assert_not_called()


def test_rule_cannot_link_an_unrelated_event_type_from_its_source(detector) -> None:
    engine, db, rules_client = detector
    rules_client.select.return_value = _page("first", "1" * 32)
    db.select.side_effect = [
        QueryRows([], [], []),
        QueryRows([], [], [("1" * 32, ASSET, EVENT_TIME, "linux.journald", "auth.sudo.command")]),
    ]
    run = engine.evaluate(RULE, NOW)
    assert run.status is RuleRunStatus.FAILED
    assert "absent from its metadata" in (run.error or "")
    db.insert_rows.assert_not_called()
