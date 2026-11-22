"""Analyst API authorization invariants (PLAN 5.2; owner of the API: D1).

* Every route except the unauthenticated liveness probe depends on the service
  principal (``Authorization: Bearer <service token>`` + user/role headers).
* Every mutating route (anything but GET/HEAD) additionally requires ``analyst``.
* Behaviour: no token -> 401, wrong token -> 401, missing user -> 401, unknown
  role -> 403, viewer mutation -> 403. These checks never reach ClickHouse:
  authorization dependencies run before any handler.

The token used here is SYNTHETIC (random per test run) and lives in a temporary
file. Skipped when the API package is not importable.
"""

from __future__ import annotations

import importlib.util
import secrets
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

if importlib.util.find_spec("extorq.api.app") is None:  # pragma: no cover - depends on D1
    pytest.skip("extorq.api not present yet (owner: D1)", allow_module_level=True)

from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from extorq.api.app import create_app
from extorq.api.auth import get_principal, require_analyst

#: Routes that are intentionally unauthenticated (method, path).
PUBLIC_ROUTES = frozenset({("GET", "/healthz")})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _dependency_calls(dependant: Any) -> set[Any]:
    calls: set[Any] = set()
    for sub in dependant.dependencies:
        calls.add(sub.call)
        calls |= _dependency_calls(sub)
    return calls


def _walk(
    routes: list[Any], prefix: str = "", inherited: tuple[Any, ...] = ()
) -> Iterator[tuple[str, str, set[Any]]]:
    for route in routes:
        if isinstance(route, APIRoute):
            calls = _dependency_calls(route.dependant)
            calls |= {getattr(dep, "dependency", None) for dep in inherited}
            for method in route.methods:
                yield method, prefix + route.path, calls
        elif hasattr(route, "original_router"):  # FastAPI included-router wrapper
            context = route.include_context
            yield from _walk(
                route.original_router.routes,
                prefix + (context.prefix or ""),
                inherited + tuple(context.dependencies or ()),
            )
        elif hasattr(route, "routes"):
            yield from _walk(list(route.routes), prefix + getattr(route, "path", ""), inherited)


@pytest.fixture
def service_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    token = "synthetic-test-token-" + secrets.token_urlsafe(24)
    token_file = tmp_path / "api_service_token"
    token_file.write_text(token, encoding="utf-8")
    token_file.chmod(0o600)
    monkeypatch.setenv("EXTORQ_API_SERVICE_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("EXTORQ_API_SERVICE_TOKEN", raising=False)
    return token


@pytest.fixture
def app(service_token: str) -> FastAPI:
    return create_app()


def test_every_route_requires_the_service_principal(app: FastAPI) -> None:
    routes = list(_walk(list(app.routes)))
    assert routes, "no routes discovered"
    unprotected = [
        f"{method} {path}"
        for method, path, calls in routes
        if (method, path) not in PUBLIC_ROUTES
        and get_principal not in calls
        and require_analyst not in calls
    ]
    assert not unprotected, f"routes without authentication: {unprotected}"


def test_every_mutation_requires_the_analyst_role(app: FastAPI) -> None:
    weak = [
        f"{method} {path}"
        for method, path, calls in _walk(list(app.routes))
        if method not in SAFE_METHODS and require_analyst not in calls
    ]
    assert not weak, f"mutating routes without the analyst role: {weak}"


def _client(app: FastAPI) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


def test_missing_and_wrong_tokens_are_rejected(app: FastAPI) -> None:
    client = _client(app)
    headers = {"X-ExtorQ-User": "alice", "X-ExtorQ-Role": "analyst"}
    assert client.get("/api/v1/alerts", headers=headers).status_code == 401
    wrong = {**headers, "Authorization": "Bearer not-the-token"}
    assert client.get("/api/v1/alerts", headers=wrong).status_code == 401


def test_identity_headers_are_validated(app: FastAPI, service_token: str) -> None:
    client = _client(app)
    auth = {"Authorization": f"Bearer {service_token}"}
    assert (
        client.get("/api/v1/alerts", headers={**auth, "X-ExtorQ-Role": "viewer"}).status_code == 401
    )
    bad_user = {**auth, "X-ExtorQ-User": "<script>", "X-ExtorQ-Role": "viewer"}
    assert client.get("/api/v1/alerts", headers=bad_user).status_code == 401
    bad_role = {**auth, "X-ExtorQ-User": "alice", "X-ExtorQ-Role": "admin"}
    assert client.get("/api/v1/alerts", headers=bad_role).status_code == 403


def test_viewer_cannot_mutate(app: FastAPI, service_token: str) -> None:
    client = _client(app)
    viewer = {
        "Authorization": f"Bearer {service_token}",
        "X-ExtorQ-User": "victor",
        "X-ExtorQ-Role": "viewer",
    }
    alert_id = "0" * 32
    state = client.post(
        f"/api/v1/alerts/{alert_id}/state", headers=viewer, json={"status": "acknowledged"}
    )
    assert state.status_code == 403


def test_retired_summary_route_is_unavailable_to_analysts(app: FastAPI, service_token: str) -> None:
    response = _client(app).post(
        f"/api/v1/alerts/{'0' * 32}/summary",
        headers={
            "Authorization": f"Bearer {service_token}",
            "X-ExtorQ-User": "analyst",
            "X-ExtorQ-Role": "analyst",
        },
        json={},
    )
    assert response.status_code == 404


def test_error_responses_never_echo_the_token(app: FastAPI, service_token: str) -> None:
    client = _client(app)
    response = client.get(
        "/api/v1/alerts",
        headers={"Authorization": f"Bearer {service_token}", "X-ExtorQ-Role": "viewer"},
    )
    assert service_token not in response.text
