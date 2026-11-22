"""In-process response cache: TTL, single flight, invalidation, labels (SYNTHETIC data)."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from api_fakes import (
    NOW,
    FakeIntegrations,
    FakeRepository,
    alert_row,
    asset_row,
    collector_row,
    rule_row,
)
from fastapi.testclient import TestClient

from extorq.api.app import create_app
from extorq.api.cache import CACHE_AGE_HEADER, CACHE_HEADER, ResponseCache
from extorq.api.settings import ApiSettings


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class CountingRepository:
    """Counts every repository method call (each stands for at least one query)."""

    def __init__(self, inner: FakeRepository) -> None:
        self._inner = inner
        self.reads = 0

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)
        if not callable(attr):
            return attr

        def counted(*args: Any, **kwargs: Any) -> Any:
            self.reads += 1
            return attr(*args, **kwargs)

        return counted


# ── ResponseCache ────────────────────────────────────────────────────────────────


def test_hit_within_ttl_and_recompute_after_expiry() -> None:
    clock = FakeClock()
    cache = ResponseCache(15, clock=clock)
    calls: list[int] = []

    def compute() -> int:
        calls.append(1)
        return len(calls)

    assert cache.get_or_compute("k", compute)[0] == 1
    clock.now += 14.9
    value, result = cache.get_or_compute("k", compute)
    assert (value, result.hit) == (1, True)
    assert result.age_seconds == pytest.approx(14.9)
    clock.now += 0.1  # age == TTL: expired
    value, result = cache.get_or_compute("k", compute)
    assert (value, result.hit) == (2, False)
    assert (cache.hits, cache.misses) == (1, 2)


def test_disabled_cache_always_computes() -> None:
    cache = ResponseCache(0)
    assert not cache.enabled
    values = iter(range(10))
    assert cache.get_or_compute("k", lambda: next(values))[0] == 0
    assert cache.get_or_compute("k", lambda: next(values))[0] == 1
    assert len(cache) == 0


def test_errors_are_not_cached() -> None:
    cache = ResponseCache(15, clock=FakeClock())

    def boom() -> int:
        raise ConnectionError("synthetic")

    with pytest.raises(ConnectionError):
        cache.get_or_compute("k", boom)
    assert cache.get_or_compute("k", lambda: 7)[0] == 7
    assert len(cache) == 1


def test_clear_drops_entries_and_discards_computations_started_before() -> None:
    cache = ResponseCache(15, clock=FakeClock())
    cache.get_or_compute("a", lambda: 1)
    cache.clear()
    assert len(cache) == 0

    def compute_while_a_mutation_clears() -> int:
        cache.clear()  # an analyst mutation lands while this response is being computed
        return 2

    assert cache.get_or_compute("b", compute_while_a_mutation_clears)[0] == 2
    assert len(cache) == 0  # not stored: it may predate the mutation
    assert cache.get_or_compute("b", lambda: 3)[0] == 3


def test_size_is_bounded_oldest_first() -> None:
    cache = ResponseCache(15, max_entries=2, clock=FakeClock())
    for key in ("a", "b", "c"):
        cache.get_or_compute(key, lambda value=key: value)  # type: ignore[misc]
    assert len(cache) == 2
    assert cache.get_or_compute("a", lambda: "recomputed")[0] == "recomputed"
    assert cache.get_or_compute("c", lambda: "x")[1].hit is True


def test_concurrent_misses_compute_once() -> None:
    cache = ResponseCache(15)
    started = threading.Event()
    release = threading.Event()
    calls: list[int] = []

    def slow() -> str:
        calls.append(1)
        started.set()
        release.wait(5)
        return "value"

    results: list[tuple[str, bool]] = []

    def worker() -> None:
        value, result = cache.get_or_compute("k", slow)
        results.append((value, result.hit))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    threads[0].start()
    assert started.wait(5)
    for thread in threads[1:]:
        thread.start()
    time.sleep(0.05)
    release.set()
    for thread in threads:
        thread.join(5)
    assert len(calls) == 1
    assert sorted(results) == [("value", False)] + [("value", True)] * 5


# ── endpoints ────────────────────────────────────────────────────────────────────


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def counting(repo: FakeRepository) -> CountingRepository:
    return CountingRepository(repo)


@pytest.fixture
def cached_client(
    tmp_path: Path,
    token: str,
    repo: FakeRepository,
    counting: CountingRepository,
    integrations: FakeIntegrations,
    clock: FakeClock,
) -> TestClient:
    settings = ApiSettings(service_token_file=tmp_path / "api_service_token")
    assert settings.cache_ttl_seconds == 15  # production default
    repo.assets = [asset_row()]
    repo.collector_rows = [collector_row()]
    repo.alerts = [alert_row("a1")]
    repo.rules = [rule_row()]
    app = create_app(
        settings=settings,
        repository=counting,
        integrations=integrations,
        clock=lambda: NOW,
        response_cache=ResponseCache(settings.cache_ttl_seconds, clock=clock),
    )
    return TestClient(app)


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/overview",
        "/api/v1/health",
        "/api/v1/assets",
        "/api/v1/assets/linux%3Alab-vm-01",
        "/api/v1/assets/linux%3Alab-vm-01/services",
        "/api/v1/services",
        "/api/v1/rules",
    ],
)
def test_aggregate_endpoints_are_served_from_cache(
    cached_client: TestClient,
    analyst: dict[str, str],
    viewer: dict[str, str],
    counting: CountingRepository,
    clock: FakeClock,
    path: str,
) -> None:
    first = cached_client.get(path, headers=analyst)
    assert first.status_code == 200
    assert first.headers[CACHE_HEADER] == "miss"
    reads = counting.reads
    assert reads > 0
    clock.now += 12
    # Another user and role: the response does not depend on the caller.
    second = cached_client.get(path, headers=viewer)
    assert second.status_code == 200
    assert second.headers[CACHE_HEADER] == "hit"
    assert second.headers[CACHE_AGE_HEADER] == "12"
    assert second.json() == first.json()
    assert counting.reads == reads  # no storage access
    assert second.headers["x-content-type-options"] == "nosniff"  # security headers kept
    clock.now += 3
    third = cached_client.get(path, headers=viewer)
    assert third.headers[CACHE_HEADER] == "miss"
    assert counting.reads == 2 * reads


def test_query_parameters_are_part_of_the_key(
    cached_client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    def label(**params: Any) -> str:
        response = cached_client.get("/api/v1/assets", headers=viewer, params=params or None)
        assert response.status_code == 200
        return str(response.headers[CACHE_HEADER])

    assert label() == "miss"
    assert label(include_retired="true") == "miss"
    assert label(limit=50) == "hit"  # the validated default: same key
    assert label(limit=10) == "miss"
    assert label(asset_type="linux_host") == "miss"
    assert sum(1 for name, _ in repo.calls if name == "collectors") == 4


def test_analyst_state_change_invalidates_the_cache(
    cached_client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    before = cached_client.get("/api/v1/overview", headers=analyst).json()
    assert before["open_alerts"]["total"] == 1
    alert_id = repo.alerts[0]["alert_id"]
    response = cached_client.post(
        f"/api/v1/alerts/{alert_id}/state",
        headers=analyst,
        json={"status": "closed_benign", "note": "synthetic"},
    )
    assert response.status_code == 200
    after = cached_client.get("/api/v1/overview", headers=analyst)
    assert after.headers[CACHE_HEADER] == "miss"
    assert after.json()["open_alerts"]["total"] == 0


def test_failed_state_change_keeps_the_cache(
    cached_client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    cached_client.get("/api/v1/overview", headers=analyst)
    repo.fail_state_insert = True
    alert_id = repo.alerts[0]["alert_id"]
    response = cached_client.post(
        f"/api/v1/alerts/{alert_id}/state", headers=analyst, json={"status": "acknowledged"}
    )
    assert response.status_code == 503
    assert cached_client.get("/api/v1/overview", headers=analyst).headers[CACHE_HEADER] == "hit"


def test_storage_errors_are_not_cached(
    cached_client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    from clickhouse_connect.driver.exceptions import DatabaseError

    real: Callable[[], list[dict[str, Any]]] = repo.all_assets

    def boom() -> Any:
        raise DatabaseError("Code: 60. synthetic")

    repo.all_assets = boom  # type: ignore[method-assign]
    assert cached_client.get("/api/v1/overview", headers=analyst).status_code == 503
    repo.all_assets = real  # type: ignore[method-assign]
    response = cached_client.get("/api/v1/overview", headers=analyst)
    assert response.status_code == 200
    assert response.headers[CACHE_HEADER] == "miss"


def test_mutations_and_per_alert_reads_are_never_cached(
    cached_client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    alert_id = repo.alerts[0]["alert_id"]
    detail = cached_client.get(f"/api/v1/alerts/{alert_id}", headers=analyst)
    assert detail.status_code == 200
    assert CACHE_HEADER not in detail.headers  # httpx headers are case-insensitive
    assert CACHE_HEADER not in cached_client.get("/api/v1/alerts", headers=analyst).headers


def test_cache_off_is_labelled(client: TestClient, analyst: dict[str, str]) -> None:
    # conftest's settings disable the cache (TTL 0).
    assert client.get("/api/v1/overview", headers=analyst).headers[CACHE_HEADER] == "off"


def test_health_quota_exhaustion_is_429_not_unreachable(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    from clickhouse_connect.driver.exceptions import DatabaseError

    repo.ping_error = DatabaseError(
        "Received ClickHouse exception, code: 201, server response: Code: 201. "
        "DB::Exception: Quota for user `synthetic` for 60s has been exceeded: "
        "queries = 6001/6000. (QUOTA_EXCEEDED)"
    )
    response = client.get("/api/v1/health", headers=analyst)
    assert response.status_code == 429
    assert response.headers["retry-after"] == "30"
    assert "synthetic" not in response.text
