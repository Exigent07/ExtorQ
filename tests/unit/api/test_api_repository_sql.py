"""Static safety properties of the API's SQL (no ClickHouse needed).

* Every executed statement is one of the module's static SQL constants.
* The ``{name:Type}`` placeholders of each statement exactly match the parameters the
  repository passes (no value ever reaches SQL text).
* No ``SELECT *``; ``raw`` is never read; ``payload`` only by the single-event query.
* Writes target only ``analyst_state`` / ``analyst_actions`` with explicit column types.
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

import pytest
from api_fakes import NOW

from extorq.api import repository as r

PLACEHOLDER = re.compile(r"\{(\w+):([^}]+)\}")
STATIC_SQL = set(r.ALL_SELECT_SQL) | {r.FINDINGS_VIEW_EXISTS_SQL}


class _Result:
    def __init__(self, rows: list[list[Any]] | None = None) -> None:
        self.result_rows = rows or []

    def named_results(self) -> list[dict[str, Any]]:
        return []


class RecordingClient:
    def __init__(self, *, lifecycle_view: bool = False) -> None:
        self.lifecycle_view = lifecycle_view
        self.queries: list[tuple[str, dict[str, Any] | None]] = []
        self.inserts: list[dict[str, Any]] = []

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> _Result:
        self.queries.append((sql, parameters))
        if sql == r.FINDINGS_VIEW_EXISTS_SQL:
            return _Result([[1 if self.lifecycle_view else 0]])
        return _Result()

    def insert(self, table: str, data: list[list[Any]], **kwargs: Any) -> None:
        self.inserts.append({"table": table, "data": data, **kwargs})


@pytest.fixture
def recording() -> tuple[r.ClickHouseRepository, RecordingClient, RecordingClient]:
    reader, writer = RecordingClient(), RecordingClient()
    repo = r.ClickHouseRepository(
        r.ClientProvider("api_ro", lambda _role: reader),
        r.ClientProvider("api_writer", lambda _role: writer),
    )
    return repo, reader, writer


def _exercise(repo: r.ClickHouseRepository) -> None:
    since, until = NOW - timedelta(days=1), NOW
    alert_filters = r.AlertFilters(since=since, until=until, severities=("high",))
    event_filters = r.EventFilters(since=since, until=until, src_ip="10.0.2.2")
    series = r.SeriesQuery(since=since, until=until, bucket_seconds=300, group_by="severity")
    repo.ping()
    repo.list_assets("linux_host", "", 10, 0)
    repo.all_assets()
    repo.get_asset("linux:lab-vm-01")
    repo.asset_last_events(["linux:lab-vm-01"])
    repo.last_event_by_asset_type()
    repo.collectors("")
    repo.inventory_summary("linux:lab-vm-01")
    repo.event_counts_by_source("linux:lab-vm-01", since, until)
    repo.findings_lifecycle_available()
    repo.list_findings(r.FindingFilters(severities=("high",)), 10, 0)
    repo.finding_severity_counts("")
    repo.rules_latest()
    repo.rule_latest_runs()
    repo.rule_versions("VM-001")
    repo.rule_runs("VM-001", "", 10, 0)
    repo.alert_counts_by_rule()
    repo.alert_status_counts_for_rule("VM-001")
    repo.list_alerts(alert_filters, 10, 0)
    repo.count_alerts(alert_filters)
    repo.get_alert("a" * 32)
    repo.get_analyst_state("a" * 32)
    repo.open_alert_severity_counts("")
    repo.open_alerts_by_asset()
    repo.evidence_refs("a" * 32, 100)
    repo.evidence_total("a" * 32, ["b" * 32])
    repo.events_by_ids(["b" * 32])
    repo.alert_actions("a" * 32, 10)
    repo.assessments_direct("a" * 32, 10)
    repo.list_events(event_filters, 10, 0)
    repo.get_event("b" * 32)
    repo.alerts_citing_event("b" * 32, 10)
    repo.pipeline_latest()
    repo.ai_status_counts(since)
    repo.ai_latest()
    repo.ingest_quarantine_count(since)
    repo.ingest_audit_decisions(since)
    repo.alert_series(series)
    repo.event_series(r.SeriesQuery(since=since, until=until, bucket_seconds=300))
    repo.asset_children("k8s:extorq-lab")
    repo.finding_service_attribution(["c" * 32])
    repo.list_findings(r.FindingFilters(service_id="d" * 32), 10, 0)
    repo.list_services(r.ServiceFilters(asset_id="linux:lab-vm-01", service_kind="k8s_service"), 9)
    repo.get_service("d" * 32)
    repo.service_instances("d" * 32, 10)
    repo.service_event_sources("d" * 32, since, until)
    repo.service_auth_summary("d" * 32, since, until)
    repo.service_auth_sources("d" * 32, since, until, 10)


def test_every_statement_is_static_and_fully_parameterised() -> None:
    executed: set[str] = set()
    for lifecycle_view in (False, True):
        reader = RecordingClient(lifecycle_view=lifecycle_view)
        repo = r.ClickHouseRepository(
            r.ClientProvider("api_ro", lambda _role, c=reader: c),
            r.ClientProvider("api_writer", lambda _role: RecordingClient()),
        )
        _exercise(repo)
        for sql, params in reader.queries:
            assert sql in STATIC_SQL, sql
            placeholders = {name for name, _type in PLACEHOLDER.findall(sql)}
            assert placeholders == set(params or {}), sql
            executed.add(sql)
    # Every SELECT constant is exercised by at least one repository method.
    assert set(r.ALL_SELECT_SQL) <= executed


def test_placeholder_types_are_consistent_within_a_statement() -> None:
    for sql in r.ALL_SELECT_SQL:
        seen: dict[str, str] = {}
        for name, type_ in PLACEHOLDER.findall(sql):
            assert seen.setdefault(name, type_) == type_, (name, sql)


def test_no_select_star_no_raw_and_payload_only_for_single_event() -> None:
    for sql in r.ALL_SELECT_SQL:
        assert not re.search(r"SELECT\s+\*", sql, re.IGNORECASE), sql
        assert not re.search(r"\braw\b", sql), sql
        if sql is not r.EVENT_GET_SQL:
            assert "payload" not in sql, sql
    assert "payload" in r.EVENT_GET_SQL


def test_writes_only_target_analyst_tables_with_explicit_types(
    recording: tuple[r.ClickHouseRepository, RecordingClient, RecordingClient],
) -> None:
    repo, reader, writer = recording
    repo.insert_analyst_action(
        {
            "action_id": "x" * 32,
            "occurred_at": NOW,
            "actor": "alice",
            "role": "analyst",
            "action": "alert_state_changed",
            "alert_id": "a" * 32,
            "details": "{}",
        }
    )
    repo.insert_analyst_state(
        {
            "alert_id": "a" * 32,
            "status": "acknowledged",
            "assignee": None,
            "note": None,
            "updated_by": "alice",
            "updated_at": NOW,
        }
    )
    assert [i["table"] for i in writer.inserts] == ["analyst_actions", "analyst_state"]
    for insert in writer.inserts:
        assert insert["database"] == "extorq"
        assert len(insert["column_names"]) == len(insert["column_type_names"])
    assert reader.inserts == []  # the read-only identity never writes


def test_datetimes_from_the_driver_are_normalised_to_aware_utc() -> None:
    naive = NOW.replace(tzinfo=None)

    class _Naive:
        def named_results(self) -> list[dict[str, Any]]:
            return [{"t": naive, "arr": [naive], "n": 1}]

    rows = r._rows(_Naive())
    assert rows[0]["t"] == NOW
    assert rows[0]["t"].tzinfo is not None
    assert rows[0]["arr"][0] == NOW
