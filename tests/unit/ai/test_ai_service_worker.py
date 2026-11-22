"""AIService (CLI path), context loading and the ai-worker loop (fakes, no network)."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any

import pytest
from ai_fakes import (
    FakeClickHouse,
    FakeJevClient,
    answering_client,
    enabled_settings,
    jev_key,
    ssh_context,
)

from extorq.ai import context_source, service, store
from extorq.ai import worker as worker_mod
from extorq.ai.budget import BudgetGuard
from extorq.ai.context_source import ContextLoadError
from extorq.ai.jev import JevTriageProvider
from extorq.ai.service import AIService, ContextNotFound, ContextUnavailable, InvalidAlertId
from extorq.ai.settings import AISettings
from extorq.contracts.ai import AIProvider, AIStatus
from extorq.contracts.common import HealthStatus
from extorq.contracts.context import InvestigationContext

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
CTX = ssh_context()


class Storage:
    """Fake ClickHouse answering the AI store's queries from in-memory state."""

    def __init__(self, *, attempts_today: int = 0) -> None:
        self.attempts_today = attempts_today
        self.reusable_rows: list[tuple[Any, ...]] = []
        self.ch = FakeClickHouse(self.handle)

    def handle(self, sql: str, params: dict[str, Any]) -> list[tuple[Any, ...]]:
        if "uniqExact(assessment_id) FROM" in sql:
            return [(self.attempts_today,)]
        if "context_input_hash = {input_hash:String}" in sql:
            return self.reusable_rows
        return []

    def reuse_first_insert(self) -> None:
        """Make the first stored assessment visible to ``store.find_reusable``."""
        values = self.ch.inserts[0]["rows"][0]
        row = dict(zip(store.ASSESSMENT_COLUMNS, values, strict=True))
        columns = [c.strip() for c in store._SELECT_COLUMNS.split(",")]
        self.reusable_rows = [tuple(row[c] for c in columns)]


def _service(
    storage: Storage,
    monkeypatch: pytest.MonkeyPatch,
    *,
    ctx: InvestigationContext | None = CTX,
    settings: AISettings | None = None,
    client: Any = None,
) -> tuple[AIService, FakeJevClient]:
    monkeypatch.setattr(service, "load_latest_context", lambda client, alert_id: ctx)
    monkeypatch.setattr(service, "build_and_save_context", lambda r, w, alert_id: None)
    monkeypatch.setattr(
        service, "shared_guard", lambda p, cap: BudgetGuard(p, cap, clock=lambda: NOW)
    )
    s = settings or enabled_settings()
    jev_client = client or answering_client()
    jev = JevTriageProvider(
        s, key=jev_key(), client_factory=lambda k, st: jev_client, clock=lambda: NOW
    )
    svc = AIService(s, read_client=storage.ch, write_client=storage.ch, jev=jev, clock=lambda: NOW)
    return svc, jev_client


# ── AIService.request_triage ──────────────────────────────────────────


def test_invalid_alert_id_is_rejected_before_any_io(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage()
    svc, client = _service(storage, monkeypatch)
    for bad in ("", "ABC", "x" * 32, "0" * 31, "'; DROP TABLE alerts; --"):
        with pytest.raises(InvalidAlertId):
            svc.request_triage(bad, "analyst:alice")
    assert storage.ch.queries == [] and client.calls == []


def test_missing_context_raises_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    svc, _ = _service(Storage(), monkeypatch, ctx=None)
    with pytest.raises(ContextNotFound):
        svc.request_triage("a" * 32, "analyst:alice")


def test_context_for_another_alert_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    svc, _ = _service(Storage(), monkeypatch)
    with pytest.raises(ContextUnavailable):
        svc.request_triage("b" * 32, "analyst:alice")


def test_storage_failure_while_loading_context_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    svc, _ = _service(Storage(), monkeypatch)

    def broken(client: Any, alert_id: str) -> Any:
        raise ConnectionError("clickhouse down")

    monkeypatch.setattr(service, "load_latest_context", broken)
    with pytest.raises(ContextUnavailable, match="ConnectionError"):
        svc.request_triage(CTX.alert_id, "analyst:alice")


def test_triage_success_is_persisted_with_the_write_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = Storage()
    svc, client = _service(storage, monkeypatch)
    assessment = svc.request_triage(CTX.alert_id, "analyst:alice")
    assert assessment.status is AIStatus.OK
    assert assessment.provider is AIProvider.JEV
    assert len(client.calls) == 1
    (insert,) = storage.ch.inserts
    assert insert["table"] == "ai_assessments"
    row = dict(zip(insert["columns"], insert["rows"][0], strict=True))
    assert row["assessment_id"] == assessment.assessment_id
    assert row["requested_by"] == "analyst:alice"
    assert '"requested_model":"jev-1.14.0"' in row["output"]


def test_existing_triage_for_same_context_is_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage()
    svc, client = _service(storage, monkeypatch)
    first = svc.request_triage(CTX.alert_id, "analyst:alice")
    storage.reuse_first_insert()
    second = svc.request_triage(CTX.alert_id, "analyst:bob")
    assert second.assessment_id == first.assessment_id
    assert len(client.calls) == 1, "no second paid call"
    assert len(storage.ch.inserts) == 1


def test_disabled_provider_is_refused_without_storage(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage()
    svc, client = _service(storage, monkeypatch, settings=AISettings(jev_enabled=False))
    assessment = svc.request_triage(CTX.alert_id, "analyst:alice")
    assert assessment.status is AIStatus.DISABLED
    assert assessment.error == "EXTORQ_JEV_ENABLED is false"
    assert client.calls == [] and storage.ch.inserts == []


def test_daily_cap_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage(attempts_today=300)
    svc, client = _service(storage, monkeypatch)
    assessment = svc.request_triage(CTX.alert_id, "analyst:alice")
    assert assessment.status is AIStatus.BUDGET_EXCEEDED
    assert assessment.error is not None and "daily_cap_reached (300/300" in assessment.error
    assert client.calls == [] and storage.ch.inserts == []


def test_unverifiable_budget_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage()
    svc, client = _service(storage, monkeypatch)
    storage.ch.fail_queries = True
    assessment = svc.request_triage(CTX.alert_id, "analyst:alice")
    assert assessment.status is AIStatus.ERROR
    assert assessment.error is not None and assessment.error.startswith("budget_check_unavailable")
    assert client.calls == []


def test_result_is_returned_even_when_storage_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage()
    storage.ch.fail_inserts = True
    svc, client = _service(storage, monkeypatch)
    assessment = svc.request_triage(CTX.alert_id, "analyst:alice")
    assert assessment.status is AIStatus.OK and len(client.calls) == 1
    # The unsaved attempt still counts against today's cap in this process.
    guard = BudgetGuard(AIProvider.JEV, 1, clock=lambda: NOW)
    monkeypatch.setattr(service, "shared_guard", lambda p, cap: guard)
    guard.try_reserve(lambda day: 0).finish(persisted=False)
    capped = svc.request_triage(CTX.alert_id, "analyst:alice")
    assert capped.status is AIStatus.BUDGET_EXCEEDED and len(client.calls) == 1


def test_concurrent_requests_for_one_alert_make_one_call(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage()
    svc, client = _service(storage, monkeypatch)
    original = svc._persist

    def persist_and_publish(assessment: Any) -> bool:
        stored = original(assessment)
        storage.reuse_first_insert()  # visible to the next caller, as in ClickHouse
        return stored

    monkeypatch.setattr(svc, "_persist", persist_and_publish)
    results: list[str] = []

    def run() -> None:
        results.append(svc.request_triage(CTX.alert_id, "analyst:alice").assessment_id)

    threads = [threading.Thread(target=run) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(client.calls) == 1
    assert len(set(results)) == 1, "every caller receives the one stored assessment"


# ── context loading ───────────────────────────────────────────────────


def test_fallback_context_loader_validates_stored_body(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(context_source, "optional_attr", lambda module, name: None)
    ch = FakeClickHouse(lambda sql, params: [(CTX.model_dump_json(),)])
    assert context_source.load_latest_context(ch, CTX.alert_id) == CTX
    sql, params = ch.queries[0]
    assert "{alert_id:String}" in sql and params == {"alert_id": CTX.alert_id}
    broken = FakeClickHouse(lambda sql, params: [('{"alert_id": "x"}',)])
    with pytest.raises(ContextLoadError, match="failed validation"):
        context_source.load_latest_context(broken, CTX.alert_id)
    empty = FakeClickHouse(lambda sql, params: [])
    assert context_source.load_latest_context(empty, CTX.alert_id) is None


def test_correlation_store_is_preferred_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def loader(client: Any, alert_id: str) -> Any:
        calls.append(alert_id)
        return CTX.model_dump(mode="json")  # tolerated: dict is validated

    monkeypatch.setattr(
        context_source,
        "optional_attr",
        lambda module, name: loader if name == "load_latest_context" else None,
    )
    assert context_source.load_latest_context(FakeClickHouse(), CTX.alert_id) == CTX
    assert calls == [CTX.alert_id]


# ── ai-worker ─────────────────────────────────────────────────────────


class WorkerStorage(Storage):
    """Queue semantics of ``store.pending_triage``: stored rows leave the queue, ``exclude``
    keys are filtered, newest-first order is the list order."""

    def __init__(self, pending: list[tuple[str, str, str]], **kw: Any) -> None:
        super().__init__(**kw)
        self.pending = pending

    def _stored(self) -> set[str]:
        keys: set[str] = set()
        for insert in self.ch.inserts:
            if insert["table"] == "ai_assessments":
                for values in insert["rows"]:
                    row = dict(zip(insert["columns"], values, strict=True))
                    keys.add(store.pending_key(row["alert_id"], row["context_input_hash"]))
        return keys

    def open_items(self) -> list[tuple[str, str, str]]:
        stored = self._stored()
        return [p for p in self.pending if store.pending_key(p[0], p[2]) not in stored]

    def handle(self, sql: str, params: dict[str, Any]) -> list[tuple[Any, ...]]:
        if "SELECT count()" in sql and "investigation_contexts" in sql:
            return [(len(self.open_items()),)]
        if "SELECT l.alert_id, l.context_id, l.input_hash" in sql:
            excluded = set(params["exclude"])
            rows = [p for p in self.open_items() if store.pending_key(p[0], p[2]) not in excluded]
            return list(rows[: params["limit"]])
        return super().handle(sql, params)


def _worker(
    storage: WorkerStorage, *, settings: AISettings | None = None, client: Any = None
) -> worker_mod.TriageWorker:
    s = settings or enabled_settings()
    jev_client = client or answering_client()
    provider = JevTriageProvider(
        s, key=jev_key(), client_factory=lambda k, st: jev_client, clock=lambda: NOW
    )
    return worker_mod.TriageWorker(
        read_client=storage.ch,
        write_client=storage.ch,
        settings=s,
        provider=provider,
        guard=BudgetGuard(AIProvider.JEV, s.jev_daily_cap, clock=lambda: NOW),
        context_loader=lambda client, alert_id: CTX if alert_id == CTX.alert_id else None,
        clock=lambda: NOW,
        instance="test:1",
    )


def test_worker_disabled_makes_no_calls_and_reports_disabled() -> None:
    storage = WorkerStorage([(CTX.alert_id, CTX.context_id, CTX.input_hash)])
    w = _worker(storage, settings=AISettings(jev_enabled=False))
    w.run_forever(once=True)
    (insert,) = storage.ch.inserts
    assert insert["table"] == "pipeline_health"
    row = dict(zip(insert["columns"], insert["rows"][0], strict=True))
    assert row["status"] == "disabled" and row["component"] == "ai_worker"
    assert "EXTORQ_JEV_ENABLED is false" in row["details"]
    assert storage.ch.queries == []


def test_worker_triages_pending_contexts_and_reports_health() -> None:
    other = "c" * 32
    storage = WorkerStorage(
        [(CTX.alert_id, CTX.context_id, CTX.input_hash), (other, "d" * 32, "e" * 64)]
    )
    w = _worker(storage)
    stats = w.run_cycle()
    assert stats.processed == 1 and stats.saved == 1 and stats.skipped == 1
    assert stats.queue_depth == 2
    assert stats.status is HealthStatus.OK
    (insert,) = storage.ch.inserts
    row = dict(zip(insert["columns"], insert["rows"][0], strict=True))
    assert row["requested_by"] == "system:ai-worker"
    health = w.health(stats)
    assert health.component == "ai_worker"
    assert health.written_total == 1 and health.queue_depth == 2


def test_worker_stops_at_the_daily_cap() -> None:
    storage = WorkerStorage([(CTX.alert_id, CTX.context_id, CTX.input_hash)], attempts_today=300)
    stats = _worker(storage).run_cycle()
    assert stats.processed == 0 and stats.budget_denied == 1
    assert stats.status is HealthStatus.DEGRADED
    assert "daily_cap_reached" in stats.reason


def test_worker_counts_write_errors_and_provider_failures() -> None:
    storage = WorkerStorage([(CTX.alert_id, CTX.context_id, CTX.input_hash)])
    storage.ch.fail_inserts = True

    class Broken:
        def system_one(self, *a: Any, **k: Any) -> Any:
            raise TimeoutError("slow")

    stats = _worker(storage, client=Broken()).run_cycle()
    assert stats.processed == 1 and stats.write_errors == 1
    assert stats.by_status == {"error": 1}
    assert stats.status is HealthStatus.DEGRADED


def test_worker_cycle_failure_is_reported_not_raised() -> None:
    storage = WorkerStorage([])
    storage.ch.fail_queries = True
    w = _worker(storage)
    w.run_forever(once=True)  # must not raise
    (insert,) = storage.ch.inserts
    row = dict(zip(insert["columns"], insert["rows"][0], strict=True))
    assert row["status"] == "failed"
    assert "cycle_failed (ConnectionError)" in row["details"]


def test_worker_respects_stop_event() -> None:
    storage = WorkerStorage([(CTX.alert_id, CTX.context_id, CTX.input_hash)])
    w = _worker(storage)
    w.stop_event.set()
    stats = w.run_cycle()
    assert stats.processed == 0


def test_correlation_store_rejections_become_context_load_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from extorq.correlation.store import ContextIntegrityError, ContextStoreError

    def make(exc: BaseException) -> Any:
        def loader(client: Any, alert_id: str) -> Any:
            raise exc

        return loader

    for exc in (ContextIntegrityError("hash mismatch"), ContextStoreError("invalid")):
        loader = make(exc)
        monkeypatch.setattr(
            context_source,
            "optional_attr",
            lambda module, name, loader=loader: {
                "load_latest_context": loader,
                "ContextStoreError": ContextStoreError,
            }.get(name),
        )
        with pytest.raises(ContextLoadError, match=type(exc).__name__):
            context_source.load_latest_context(FakeClickHouse(), CTX.alert_id)
    # Connectivity problems are not "bad context" problems: they propagate unchanged.
    loader = make(ConnectionError("down"))
    monkeypatch.setattr(
        context_source,
        "optional_attr",
        lambda module, name: {
            "load_latest_context": loader,
            "ContextStoreError": ContextStoreError,
        }.get(name),
    )
    with pytest.raises(ConnectionError):
        context_source.load_latest_context(FakeClickHouse(), CTX.alert_id)


def test_worker_skips_a_poison_context_and_continues() -> None:
    bad = "f" * 32
    storage = WorkerStorage(
        [(bad, "1" * 32, "2" * 64), (CTX.alert_id, CTX.context_id, CTX.input_hash)]
    )
    w = _worker(storage)

    def loader(client: Any, alert_id: str) -> Any:
        if alert_id == bad:
            raise ContextLoadError("correlation store rejected the stored context (X)")
        return CTX

    w.context_loader = loader
    stats = w.run_cycle()
    assert stats.skipped == 1 and stats.processed == 1 and stats.saved == 1
    assert stats.invalid == 1


def test_worker_instance_name_comes_from_platform_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    class Settings:
        instance_name = "ai-worker"

    monkeypatch.setattr(worker_mod, "optional_attr", lambda module, name: lambda: Settings())
    assert worker_mod._instance_name() == "ai-worker"

    def broken() -> Any:
        raise ValueError("both JEV_API_KEY and JEV_API_KEY_FILE are set")

    monkeypatch.setattr(worker_mod, "optional_attr", lambda module, name: broken)
    assert worker_mod._instance_name() is None
    monkeypatch.setattr(worker_mod, "optional_attr", lambda module, name: None)
    assert worker_mod._instance_name() is None


# ── ai-worker robustness (session 3 review findings) ──────────────────


def _ctx_for(alert_id: str) -> InvestigationContext:
    """CTX under another alert id (SYNTHETIC; the queue key differs by alert id)."""
    return CTX.model_copy(
        update={"alert_id": alert_id, "alert": CTX.alert.model_copy(update={"alert_id": alert_id})}
    )


def _unreadable(n: int, start: int = 1) -> list[tuple[str, str, str]]:
    return [(f"{i:032x}", f"{i:032x}", f"{i:064x}") for i in range(start, start + n)]


def _loader_for(good: dict[str, InvestigationContext], loads: list[str]) -> Any:
    def loader(client: Any, alert_id: str) -> InvestigationContext | None:
        loads.append(alert_id)
        if alert_id in good:
            return good[alert_id]
        raise ContextLoadError("correlation store rejected the stored context (X)")

    return loader


def test_worker_pages_past_a_block_of_unreadable_contexts() -> None:
    bad = _unreadable(5)
    good = {a: _ctx_for(a) for a in ("a" * 32, "b" * 32)}
    storage = WorkerStorage(bad + [(a, c.context_id, c.input_hash) for a, c in good.items()])
    client = answering_client()
    w = _worker(storage, settings=enabled_settings(ai_worker_batch_size=2), client=client)
    loads: list[str] = []
    w.context_loader = _loader_for(good, loads)
    stats = w.run_cycle()
    assert (stats.scanned, stats.invalid, stats.skipped) == (7, 5, 5)
    assert (stats.processed, stats.saved) == (2, 2) and len(client.calls) == 2
    assert stats.status is HealthStatus.DEGRADED
    assert "5 unreadable context(s) skipped" in stats.reason
    details = w.health(stats).details
    assert details["cycle_invalid_contexts"] == 5 and details["invalid_contexts_total"] == 5
    # Next cycle: the unreadable contexts are excluded by the query itself and never re-loaded.
    loads.clear()
    again = w.run_cycle()
    assert loads == [] and (again.processed, again.invalid) == (0, 0)
    assert again.status is HealthStatus.OK and again.queue_depth == 5
    last_page = [p for sql, p in storage.ch.queries if "SELECT l.alert_id" in sql][-1]
    assert {store.pending_key(a, h) for a, _, h in bad} <= set(last_page["exclude"])


def test_worker_scan_limit_bounds_a_cycle_and_the_queue_still_progresses() -> None:
    bad = _unreadable(6)
    good = {"a" * 32: _ctx_for("a" * 32)}
    storage = WorkerStorage([*bad, ("a" * 32, good["a" * 32].context_id, CTX.input_hash)])
    settings = enabled_settings(ai_worker_batch_size=2, ai_worker_max_scan_per_cycle=4)
    w = _worker(storage, settings=settings)
    loads: list[str] = []
    w.context_loader = _loader_for(good, loads)
    first = w.run_cycle()
    assert (first.scanned, first.invalid, first.processed) == (4, 4, 0)
    second = w.run_cycle()
    assert (second.scanned, second.invalid, second.processed) == (3, 2, 1)
    assert len(loads) == 7, "every context is loaded exactly once"


def test_worker_keeps_a_paid_result_and_retries_only_the_write() -> None:
    storage = WorkerStorage([(CTX.alert_id, CTX.context_id, CTX.input_hash)])
    storage.ch.fail_inserts = True
    now = [1000.0]
    client = answering_client()
    settings = enabled_settings(
        ai_worker_write_retry_base_seconds=10, ai_worker_write_retry_max_seconds=40
    )
    w = _worker(storage, settings=settings, client=client)
    w.monotonic = lambda: now[0]
    first = w.run_cycle()
    assert (first.processed, first.write_errors, len(client.calls)) == (1, 1, 1)
    assert w.awaiting_storage == 1 and first.status is HealthStatus.DEGRADED
    assert "new provider calls paused" in first.reason
    assert w.guard.used_estimate(0) == 1, "the unsaved attempt still counts toward the cap"
    assert w.health(first).details["awaiting_storage"] == 1
    # Before the backoff expires: no write retry and, above all, no new paid call.
    now[0] += 5
    second = w.run_cycle()
    assert (second.write_retries, second.processed, len(client.calls)) == (0, 0, 1)
    # Backoff expired, storage still down: one write retry, the delay doubles, still no call.
    now[0] += 10
    third = w.run_cycle()
    assert (third.write_retries, third.write_errors, len(client.calls)) == (1, 1, 1)
    delay = w.next_retry_in()
    assert delay is not None and 20.0 <= delay <= 22.0  # 2 x 10 s, jitter <= 10 %
    # Storage recovers: the cached result is written; nothing is sent to the provider again.
    storage.ch.fail_inserts = False
    now[0] += 25
    fourth = w.run_cycle()
    assert (fourth.retried_saved, fourth.saved, w.awaiting_storage) == (1, 1, 0)
    assert len(client.calls) == 1 and fourth.status is HealthStatus.OK
    assert w.guard.used_estimate(0) == 0, "stored later: no longer counted in-process"
    (insert,) = [i for i in storage.ch.inserts if i["table"] == "ai_assessments"]
    assert dict(zip(insert["columns"], insert["rows"][0], strict=True))["alert_id"] == CTX.alert_id
    assert w.totals.written == 1 and w.totals.write_errors == 2


def test_worker_drops_a_result_after_max_write_attempts_and_never_calls_again() -> None:
    storage = WorkerStorage([(CTX.alert_id, CTX.context_id, CTX.input_hash)])
    storage.ch.fail_inserts = True
    now = [0.0]
    client = answering_client()
    settings = enabled_settings(
        ai_worker_write_max_attempts=2, ai_worker_write_retry_base_seconds=1
    )
    w = _worker(storage, settings=settings, client=client)
    w.monotonic = lambda: now[0]
    w.run_cycle()  # paid call + first failed write
    now[0] += 5
    dropped = w.run_cycle()  # second failed write: result dropped
    assert w.awaiting_storage == 0 and w.totals.dropped_results == 1
    assert w.health(dropped).details["results_dropped_total"] == 1
    storage.ch.fail_inserts = False
    now[0] += 5
    later = w.run_cycle()
    assert later.processed == 0 and len(client.calls) == 1, "never sent to the provider again"


def test_worker_skips_a_replaced_context_that_is_already_triaged() -> None:
    stale = (CTX.alert_id, CTX.context_id, "9" * 64)  # queue still names an older hash
    storage = WorkerStorage([stale])
    client = answering_client()
    w = _worker(storage, client=client)
    first = w.run_cycle()  # the loader returns the current context: it is triaged once
    assert first.processed == 1 and len(client.calls) == 1
    values = storage.ch.inserts[0]["rows"][0]
    row = dict(zip(store.ASSESSMENT_COLUMNS, values, strict=True))
    columns = [c.strip() for c in store._SELECT_COLUMNS.split(",")]
    storage.reusable_rows = [tuple(row[c] for c in columns)]
    second = w.run_cycle()  # same stale queue entry: already triaged, no second call
    assert (second.processed, second.skipped) == (0, 1) and len(client.calls) == 1
