"""AIService (API/CLI path), context loading and the ai-worker loop (fakes, no network)."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from ai_fakes import (
    FakeClickHouse,
    FakeGeminiClient,
    FakeGeminiResponse,
    answering_client,
    enabled_settings,
    gemini_key,
    jev_key,
    ssh_context,
    summary_json,
)

from extorq.ai import context_source, service, store
from extorq.ai import worker as worker_mod
from extorq.ai.budget import BudgetGuard, CooldownTracker
from extorq.ai.context_source import ContextLoadError
from extorq.ai.gemini import GeminiSummaryProvider
from extorq.ai.jev import JevTriageProvider
from extorq.ai.service import AIService, ContextNotFound, ContextUnavailable, InvalidAlertId
from extorq.ai.settings import AISettings
from extorq.contracts.ai import AIProvider, AIStatus
from extorq.contracts.common import HealthStatus
from extorq.contracts.context import InvestigationContext

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
CTX = ssh_context()


def _gemini_client() -> FakeGeminiClient:
    def respond(contents: Any, config: Any) -> FakeGeminiResponse:
        import json

        line = contents.split("ALLOWED_EVIDENCE_IDS (cite only these): ")[1].split("\n")[0]
        return FakeGeminiResponse(summary_json(json.loads(line)))

    return FakeGeminiClient(respond)


class Storage:
    """Fake ClickHouse answering the AI store's queries from in-memory state."""

    def __init__(self, *, attempts_today: int = 0, last_attempt: datetime | None = None) -> None:
        self.attempts_today = attempts_today
        self.last_attempt = last_attempt
        self.reusable_rows: list[tuple[Any, ...]] = []
        self.ch = FakeClickHouse(self.handle)

    def handle(self, sql: str, params: dict[str, Any]) -> list[tuple[Any, ...]]:
        if "uniqExact(assessment_id) FROM" in sql:
            return [(self.attempts_today,)]
        if "max(created_at), count()" in sql:
            if self.last_attempt is None:
                return [(datetime(1970, 1, 1), 0)]
            return [(self.last_attempt.replace(tzinfo=None), 1)]
        if "context_input_hash = {input_hash:String}" in sql:
            return self.reusable_rows
        return []


def _service(
    storage: Storage,
    monkeypatch: pytest.MonkeyPatch,
    *,
    ctx: InvestigationContext | None = CTX,
    settings: AISettings | None = None,
    gemini_client: FakeGeminiClient | None = None,
) -> tuple[AIService, FakeGeminiClient]:
    monkeypatch.setattr(service, "load_latest_context", lambda client, alert_id: ctx)
    monkeypatch.setattr(service, "build_and_save_context", lambda r, w, alert_id: None)
    monkeypatch.setattr(
        service, "shared_guard", lambda p, cap: BudgetGuard(p, cap, clock=lambda: NOW)
    )
    s = settings or enabled_settings()
    client = gemini_client or _gemini_client()
    gemini = GeminiSummaryProvider(
        s, key=gemini_key(), client_factory=lambda k, st: client, clock=lambda: NOW
    )
    svc = AIService(
        s,
        read_client=storage.ch,
        write_client=storage.ch,
        gemini=gemini,
        cooldowns=CooldownTracker(),
        clock=lambda: NOW,
    )
    return svc, client


# ── AIService.request_summary ─────────────────────────────────────────


def test_invalid_alert_id_is_rejected_before_any_io(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage()
    svc, client = _service(storage, monkeypatch)
    for bad in ("", "ABC", "x" * 32, "0" * 31, "'; DROP TABLE alerts; --"):
        with pytest.raises(InvalidAlertId):
            svc.request_summary(bad, "analyst:alice")
    assert storage.ch.queries == [] and client.calls == []


def test_missing_context_raises_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    svc, _ = _service(Storage(), monkeypatch, ctx=None)
    with pytest.raises(ContextNotFound):
        svc.request_summary("a" * 32, "analyst:alice")


def test_context_for_another_alert_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    svc, _ = _service(Storage(), monkeypatch)
    with pytest.raises(ContextUnavailable):
        svc.request_summary("b" * 32, "analyst:alice")


def test_storage_failure_while_loading_context_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    svc, _ = _service(Storage(), monkeypatch)

    def broken(client: Any, alert_id: str) -> Any:
        raise ConnectionError("clickhouse down")

    monkeypatch.setattr(service, "load_latest_context", broken)
    with pytest.raises(ContextUnavailable, match="ConnectionError"):
        svc.request_summary(CTX.alert_id, "analyst:alice")


def test_summary_success_is_persisted_with_the_write_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = Storage()
    svc, client = _service(storage, monkeypatch)
    assessment = svc.request_summary(CTX.alert_id, "analyst:alice")
    assert assessment.status is AIStatus.OK
    assert len(client.calls) == 1
    (insert,) = storage.ch.inserts
    assert insert["table"] == "ai_assessments"
    row = dict(zip(insert["columns"], insert["rows"][0], strict=True))
    assert row["assessment_id"] == assessment.assessment_id
    assert row["requested_by"] == "analyst:alice"
    assert '"requested_model":"gemini-3.6-flash"' in row["output"]


def test_existing_summary_for_same_context_is_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage()
    svc, client = _service(storage, monkeypatch)
    first = svc.request_summary(CTX.alert_id, "analyst:alice")
    values = storage.ch.inserts[0]["rows"][0]
    row = dict(zip(store.ASSESSMENT_COLUMNS, values, strict=True))
    columns = [c.strip() for c in store._SELECT_COLUMNS.split(",")]
    storage.reusable_rows = [tuple(row[c] for c in columns)]
    second = svc.request_summary(CTX.alert_id, "analyst:bob")
    assert second.assessment_id == first.assessment_id
    assert len(client.calls) == 1, "no second paid call"
    assert len(storage.ch.inserts) == 1


def test_disabled_provider_is_refused_without_storage(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage()
    svc, client = _service(storage, monkeypatch, settings=AISettings())
    assessment = svc.request_summary(CTX.alert_id, "analyst:alice")
    assert assessment.status is AIStatus.DISABLED
    assert assessment.error == "EXTORQ_GEMINI_ENABLED is false"
    assert client.calls == [] and storage.ch.inserts == []


def test_cooldown_after_a_recent_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage(last_attempt=NOW - timedelta(seconds=30))
    svc, client = _service(storage, monkeypatch)
    assessment = svc.request_summary(CTX.alert_id, "analyst:alice")
    assert assessment.status is AIStatus.BUDGET_EXCEEDED
    assert assessment.error is not None and assessment.error.startswith("cooldown_active")
    assert "90 s" in assessment.error  # default cooldown 120 s, last attempt 30 s ago
    assert client.calls == [] and storage.ch.inserts == []


def test_in_process_cooldown_covers_unsaved_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage()
    storage.ch.fail_inserts = True
    svc, client = _service(storage, monkeypatch)
    first = svc.request_summary(CTX.alert_id, "analyst:alice")
    assert first.status is AIStatus.OK  # result returned even though storage failed
    second = svc.request_summary(CTX.alert_id, "analyst:alice")
    assert second.status is AIStatus.BUDGET_EXCEEDED
    assert len(client.calls) == 1


def test_daily_cap_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage(attempts_today=50)
    svc, client = _service(storage, monkeypatch)
    assessment = svc.request_summary(CTX.alert_id, "analyst:alice")
    assert assessment.status is AIStatus.BUDGET_EXCEEDED
    assert assessment.error is not None and "daily_cap_reached (50/50" in assessment.error
    assert client.calls == []


def test_unverifiable_budget_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage()
    svc, client = _service(storage, monkeypatch)
    storage.ch.fail_queries = True
    assessment = svc.request_summary(CTX.alert_id, "analyst:alice")
    assert assessment.status is AIStatus.ERROR
    assert assessment.error is not None and assessment.error.startswith("budget_check_unavailable")
    assert client.calls == []


def test_concurrent_requests_for_one_alert_make_one_call(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage()
    svc, client = _service(storage, monkeypatch)
    results: list[AIStatus] = []

    def run() -> None:
        results.append(svc.request_summary(CTX.alert_id, "analyst:alice").status)

    threads = [threading.Thread(target=run) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(client.calls) == 1
    assert results.count(AIStatus.OK) == 1
    assert results.count(AIStatus.BUDGET_EXCEEDED) == 4  # cooldown


def test_request_triage_uses_the_jev_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = Storage()
    svc, _ = _service(storage, monkeypatch)
    jev_client = answering_client()
    svc._jev = JevTriageProvider(
        enabled_settings(), key=jev_key(), client_factory=lambda k, s: jev_client, clock=lambda: NOW
    )
    assessment = svc.request_triage(CTX.alert_id)
    assert assessment.status is AIStatus.OK
    assert assessment.provider is AIProvider.JEV
    assert len(storage.ch.inserts) == 1
    storage.attempts_today = 300
    storage.reusable_rows = []
    capped = svc.request_triage(CTX.alert_id)
    assert capped.status is AIStatus.BUDGET_EXCEEDED


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
    def __init__(self, pending: list[tuple[str, str, str]], **kw: Any) -> None:
        super().__init__(**kw)
        self.pending = pending

    def handle(self, sql: str, params: dict[str, Any]) -> list[tuple[Any, ...]]:
        if "SELECT count()" in sql and "investigation_contexts" in sql:
            return [(len(self.pending),)]
        if "SELECT l.alert_id, l.context_id, l.input_hash" in sql:
            return self.pending[: params["limit"]]
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
    w = _worker(storage, settings=AISettings())
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
