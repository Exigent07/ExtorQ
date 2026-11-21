"""Budget guard, cooldowns and ai_assessments persistence (fake ClickHouse, no network)."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from ai_fakes import FakeClickHouse, answering_client, enabled_settings, jev_key, ssh_context

from extorq.ai import store
from extorq.ai.budget import (
    BudgetExceeded,
    BudgetGuard,
    BudgetUnavailable,
    CooldownTracker,
    cooldown_remaining,
    utc_day_start,
)
from extorq.ai.jev import JevTriageProvider
from extorq.contracts.ai import AIAssessment, AIProvider, AIStatus, AITask
from extorq.contracts.common import HealthStatus
from extorq.contracts.health import PipelineHealth

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)


# ── budget guard ──────────────────────────────────────────────────────


def test_cap_counts_persisted_inflight_and_unsaved_attempts() -> None:
    guard = BudgetGuard(AIProvider.GEMINI, 3, clock=lambda: NOW)
    first = guard.try_reserve(lambda day: 1)  # 1 persisted + this reservation
    second = guard.try_reserve(lambda day: 1)
    with pytest.raises(BudgetExceeded) as excinfo:
        guard.try_reserve(lambda day: 1)
    assert "3/3" in str(excinfo.value)
    first.finish(persisted=True)  # now counted by the store (still 1 in the fake)
    third = guard.try_reserve(lambda day: 1)
    second.finish(persisted=False)  # storage failed: keeps counting today
    third.finish(persisted=False)
    with pytest.raises(BudgetExceeded):
        guard.try_reserve(lambda day: 1)


def test_reservation_finish_is_idempotent() -> None:
    guard = BudgetGuard(AIProvider.JEV, 1, clock=lambda: NOW)
    reservation = guard.try_reserve(lambda day: 0)
    reservation.finish(persisted=True)
    reservation.finish(persisted=False)
    assert guard.used_estimate(0) == 0


def test_unreadable_usage_fails_closed() -> None:
    guard = BudgetGuard(AIProvider.JEV, 300, clock=lambda: NOW)

    def broken(day: datetime) -> int:
        raise ConnectionError("clickhouse down")

    with pytest.raises(BudgetUnavailable, match="ConnectionError"):
        guard.try_reserve(broken)


def test_unsaved_attempts_reset_on_a_new_utc_day() -> None:
    clock = {"now": NOW}
    guard = BudgetGuard(AIProvider.JEV, 1, clock=lambda: clock["now"])
    guard.try_reserve(lambda day: 0).finish(persisted=False)
    with pytest.raises(BudgetExceeded):
        guard.try_reserve(lambda day: 0)
    clock["now"] = NOW + timedelta(days=1)
    seen: list[datetime] = []
    guard.try_reserve(lambda day: seen.append(day) or 0)
    assert seen == [utc_day_start(NOW + timedelta(days=1))]


def test_concurrent_reservations_never_exceed_the_cap() -> None:
    guard = BudgetGuard(AIProvider.GEMINI, 5, clock=lambda: NOW)
    granted: list[object] = []
    lock = threading.Lock()

    def worker() -> None:
        try:
            r = guard.try_reserve(lambda day: 0)
        except BudgetExceeded:
            return
        with lock:
            granted.append(r)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(granted) == 5


def test_cooldown_remaining() -> None:
    assert cooldown_remaining(None, NOW, 300) == 0
    assert cooldown_remaining(NOW - timedelta(seconds=100), NOW, 300) == 200
    assert cooldown_remaining(NOW - timedelta(seconds=400), NOW, 300) == 0
    assert cooldown_remaining(NOW, NOW, 0) == 0
    tracker = CooldownTracker()
    tracker.note("x", NOW)
    assert tracker.last("x") == NOW
    assert tracker.last("y") is None


# ── store ─────────────────────────────────────────────────────────────


def _assessment(status: AIStatus = AIStatus.OK) -> AIAssessment:
    provider = JevTriageProvider(
        enabled_settings(),
        key=jev_key(),
        client_factory=lambda k, s: answering_client(sc=0.9 if status is AIStatus.OK else 0.1),
        clock=lambda: NOW,
    )
    return provider.assess(ssh_context(), "system:ai-worker")


def _select_row(a: AIAssessment, requested_model: str) -> tuple[Any, ...]:
    row = dict(
        zip(
            store.ASSESSMENT_COLUMNS,
            store.assessment_to_row(a, requested_model=requested_model),
            strict=True,
        )
    )
    columns = [c.strip() for c in store._SELECT_COLUMNS.split(",")]
    values = [row[c] for c in columns]
    # clickhouse-connect returns DateTime64 as naive UTC datetimes
    values[columns.index("created_at")] = a.created_at.replace(tzinfo=None)
    return tuple(values)


def test_row_round_trip() -> None:
    original = _assessment()
    rebuilt, requested = store.row_to_assessment(_select_row(original, "jev-1.14.0"))
    assert rebuilt == original
    assert requested == "jev-1.14.0"


def test_row_flattens_recommendation_and_bounds_counters() -> None:
    a = _assessment().model_copy(update={"input_tokens": 2**40})
    row = dict(zip(store.ASSESSMENT_COLUMNS, store.assessment_to_row(a), strict=True))
    assert row["recommendation"] == "priority_investigation"
    assert row["uncertain"] == 0
    assert row["input_tokens"] == 2**32 - 1
    output = json.loads(row["output"])
    assert set(output) == {"requested_model", "triage", "summary", "validation"}


def test_save_assessment_inserts_one_row_with_declared_columns() -> None:
    ch = FakeClickHouse()
    store.save_assessment(ch, _assessment(), requested_model="jev-1.14.0")
    (insert,) = ch.inserts
    assert insert["table"] == "ai_assessments" and insert["database"] == "extorq"
    assert insert["columns"] == list(store.ASSESSMENT_COLUMNS)
    assert len(insert["rows"]) == 1


def test_queries_bind_every_value_as_a_parameter() -> None:
    hostile = "x' OR 1=1 --"

    def handler(sql: str, params: dict[str, Any]) -> list[tuple[Any, ...]]:
        if "uniqExact(assessment_id) FROM" in sql:
            return [(0,)]
        if "max(created_at), count()" in sql:
            return [(None, 0)]
        return []

    ch = FakeClickHouse(handler)
    store.count_attempts_since(ch, AIProvider.GEMINI, NOW)
    store.last_attempt_at(ch, alert_id=hostile, provider=AIProvider.GEMINI, task=AITask.SUMMARY)
    store.list_assessments(ch, hostile)
    store.find_reusable(
        ch,
        alert_id=hostile,
        provider=AIProvider.JEV,
        task=AITask.TRIAGE,
        prompt_version="triage-v1",
        context_input_hash="0" * 64,
        model="jev-1.14.0",
    )
    store.pending_triage(
        ch,
        prompt_version="triage-v1",
        limit=10_000,
        max_failed=3,
        backoff_seconds=600,
        max_age_hours=72,
    )
    for sql, _params in ch.queries:
        assert hostile not in sql
        assert "{" in sql  # server-side parameters
    limits = [p["limit"] for _, p in ch.queries if "limit" in p]
    assert all(1 <= value <= 500 for value in limits)


def test_count_attempts_uses_attempt_statuses_since_day_start() -> None:
    ch = FakeClickHouse(lambda sql, params: [(7,)])
    assert store.count_attempts_since(ch, AIProvider.JEV, NOW) == 7
    sql, params = ch.queries[0]
    assert "uniqExact(assessment_id)" in sql
    assert params["since_ms"] == int(NOW.timestamp() * 1000)
    assert set(params["statuses"]) == set(store.ATTEMPT_STATUSES)
    assert "disabled" not in params["statuses"] and "budget_exceeded" not in params["statuses"]


def test_find_reusable_matches_requested_or_reported_model() -> None:
    a = _assessment()
    row = _select_row(a, "jev-1.14.0")
    ch = FakeClickHouse(lambda sql, params: [row])
    found = store.find_reusable(
        ch,
        alert_id=a.alert_id,
        provider=AIProvider.JEV,
        task=AITask.TRIAGE,
        prompt_version="triage-v1",
        context_input_hash=a.context_input_hash,
        model="jev-1.14.0",
    )
    assert found == a
    assert (
        store.find_reusable(
            ch,
            alert_id=a.alert_id,
            provider=AIProvider.JEV,
            task=AITask.TRIAGE,
            prompt_version="triage-v1",
            context_input_hash=a.context_input_hash,
            model="jev-2.0.0",
        )
        is None
    )


def test_unreadable_rows_are_skipped() -> None:
    good = _select_row(_assessment(), "jev-1.14.0")
    bad = (*good[:9], "{not json", *good[10:])
    ch = FakeClickHouse(lambda sql, params: [bad, good])
    with pytest.raises(json.JSONDecodeError):
        store.row_to_assessment(bad)
    # json errors are ValueErrors: skipped and logged, the readable row survives
    assert len(store.list_assessments(ch, "a" * 32)) == 1


def test_last_attempt_none_without_rows() -> None:
    ch = FakeClickHouse(lambda sql, params: [(datetime(1970, 1, 1), 0)])
    assert (
        store.last_attempt_at(
            ch, alert_id="a" * 32, provider=AIProvider.GEMINI, task=AITask.SUMMARY
        )
        is None
    )


def test_pipeline_health_row() -> None:
    ch = FakeClickHouse()
    health = PipelineHealth(
        component="ai_worker",
        instance="test:1",
        reported_at=NOW,
        status=HealthStatus.DISABLED,
        details={"reason": "EXTORQ_JEV_ENABLED is false"},
    )
    store.save_pipeline_health(ch, health)
    (insert,) = ch.inserts
    assert insert["table"] == "pipeline_health"
    row = dict(zip(insert["columns"], insert["rows"][0], strict=True))
    assert row["component"] == "ai_worker" and row["status"] == "disabled"
    assert json.loads(row["details"]) == {"reason": "EXTORQ_JEV_ENABLED is false"}
