"""Fixtures for analyst API unit tests (fake repository; no ClickHouse, no network)."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from api_fakes import NOW, FakeIntegrations, FakeRepository
from fastapi.testclient import TestClient

from extorq.api.app import create_app
from extorq.api.settings import ApiSettings


@pytest.fixture
def token(tmp_path: Path) -> str:
    # Random per test run; written to a 0600 temp file like the real secret.
    value = secrets.token_urlsafe(32)
    path = tmp_path / "api_service_token"
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(0o600)
    return value


@pytest.fixture
def settings(tmp_path: Path, token: str) -> ApiSettings:
    # The response cache is off here so tests may change the fake store between two calls;
    # test_api_cache.py and test_api_lifecycle.py cover the cache with a TTL.
    return ApiSettings(service_token_file=tmp_path / "api_service_token", cache_ttl_seconds=0)


@pytest.fixture
def repo() -> FakeRepository:
    return FakeRepository()


@pytest.fixture
def integrations() -> FakeIntegrations:
    return FakeIntegrations()


@pytest.fixture
def app_factory(
    settings: ApiSettings, repo: FakeRepository, integrations: FakeIntegrations
) -> Callable[..., Any]:
    def make(**overrides: Any) -> Any:
        kwargs: dict[str, Any] = {
            "settings": settings,
            "repository": repo,
            "integrations": integrations,
            "clock": lambda: NOW,
        }
        kwargs.update(overrides)
        return create_app(**kwargs)

    return make


@pytest.fixture
def client(app_factory: Callable[..., Any]) -> TestClient:
    return TestClient(app_factory())


@pytest.fixture
def analyst(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-ExtorQ-User": "alice",
        "X-ExtorQ-Role": "analyst",
    }


@pytest.fixture
def viewer(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-ExtorQ-User": "victor",
        "X-ExtorQ-Role": "viewer",
    }
