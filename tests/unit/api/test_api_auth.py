"""Authentication, roles, security headers and request limits."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from api_fakes import FakeRepository, alert_row
from fastapi.testclient import TestClient

from extorq.api.settings import ApiSettings

OVERVIEW = "/api/v1/overview"


def test_healthz_needs_no_auth_and_reveals_nothing(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_missing_bearer_is_401_with_challenge(client: TestClient) -> None:
    response = client.get(OVERVIEW, headers={"X-ExtorQ-User": "a", "X-ExtorQ-Role": "viewer"})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["detail"] == "missing or invalid bearer token"


def test_wrong_token_is_401(client: TestClient, analyst: dict[str, str]) -> None:
    headers = {**analyst, "Authorization": "Bearer " + "x" * 43}
    assert client.get(OVERVIEW, headers=headers).status_code == 401


def test_non_bearer_scheme_is_401(client: TestClient, analyst: dict[str, str], token: str) -> None:
    headers = {**analyst, "Authorization": f"Basic {token}"}
    assert client.get(OVERVIEW, headers=headers).status_code == 401


def test_token_is_never_echoed(client: TestClient, analyst: dict[str, str], token: str) -> None:
    for headers in (analyst, {**analyst, "X-ExtorQ-Role": "root"}):
        response = client.get(OVERVIEW, headers=headers)
        assert token not in response.text
        assert token not in str(response.headers)


@pytest.mark.parametrize("user", [None, "", "<script>", "a b", "x" * 129, "-leading"])
def test_missing_or_malformed_user_is_401(
    client: TestClient, analyst: dict[str, str], user: str | None
) -> None:
    headers = dict(analyst)
    if user is None:
        del headers["X-ExtorQ-User"]
    else:
        headers["X-ExtorQ-User"] = user
    assert client.get(OVERVIEW, headers=headers).status_code in (401, 422)


@pytest.mark.parametrize("role", [None, "", "admin", "Analyst", "ANALYST"])
def test_missing_or_unknown_role_is_403(
    client: TestClient, analyst: dict[str, str], role: str | None
) -> None:
    headers = dict(analyst)
    if role is None:
        del headers["X-ExtorQ-Role"]
    else:
        headers["X-ExtorQ-Role"] = role
    response = client.get(OVERVIEW, headers=headers)
    assert response.status_code == 403
    assert "X-ExtorQ-Role" in response.json()["detail"]


def test_viewer_can_read(client: TestClient, viewer: dict[str, str]) -> None:
    assert client.get(OVERVIEW, headers=viewer).status_code == 200


def test_viewer_cannot_mutate_and_nothing_is_written(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    alert = alert_row()
    repo.alerts.append(alert)
    alert_id = alert["alert_id"]
    state = client.post(
        f"/api/v1/alerts/{alert_id}/state", headers=viewer, json={"status": "acknowledged"}
    )
    assert state.status_code == 403
    assert state.json()["detail"] == "this action requires the analyst role"
    assert repo.writes == []


def test_unconfigured_server_token_fails_closed(
    app_factory: Callable[..., Any], tmp_path: Path, analyst: dict[str, str]
) -> None:
    app = app_factory(settings=ApiSettings(service_token_file=tmp_path / "absent"))
    response = TestClient(app).get(OVERVIEW, headers=analyst)
    assert response.status_code == 503
    assert response.json()["detail"] == "API service token is not configured on the server"


def test_short_server_token_is_treated_as_unconfigured(
    app_factory: Callable[..., Any], tmp_path: Path
) -> None:
    short = tmp_path / "short"
    short.write_text("too-short", encoding="utf-8")
    app = app_factory(settings=ApiSettings(service_token_file=short))
    headers = {
        "Authorization": "Bearer too-short",
        "X-ExtorQ-User": "alice",
        "X-ExtorQ-Role": "analyst",
    }
    assert TestClient(app).get(OVERVIEW, headers=headers).status_code == 503


def test_security_headers_and_request_id_on_success_and_error(
    client: TestClient, analyst: dict[str, str]
) -> None:
    for response in (
        client.get(OVERVIEW, headers=analyst),
        client.get(OVERVIEW),
        client.get("/api/v1/alerts/" + "0" * 32, headers=analyst),
    ):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-frame-options"] == "DENY"
        assert "default-src 'none'" in response.headers["content-security-policy"]
        assert len(response.headers["x-request-id"]) >= 8


def test_inbound_request_id_is_kept_only_when_well_formed(
    client: TestClient, analyst: dict[str, str]
) -> None:
    good = client.get(OVERVIEW, headers={**analyst, "X-Request-ID": "req-12345678"})
    bad = client.get(OVERVIEW, headers={**analyst, "X-Request-ID": "bad id\r\nx"})
    assert good.headers["x-request-id"] == "req-12345678"
    assert bad.headers["x-request-id"] != "bad id\r\nx"


def test_error_body_carries_request_id(client: TestClient, analyst: dict[str, str]) -> None:
    response = client.get("/api/v1/alerts/" + "0" * 32, headers=analyst)
    assert response.status_code == 404
    assert response.json()["request_id"] == response.headers["x-request-id"]


def test_oversized_body_is_rejected_before_parsing(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    alert = alert_row()
    repo.alerts.append(alert)
    body = b'{"status":"acknowledged","note":"' + b"a" * 70_000 + b'"}'
    response = client.post(
        f"/api/v1/alerts/{alert['alert_id']}/state",
        headers={**analyst, "Content-Type": "application/json"},
        content=body,
    )
    assert response.status_code == 413
    assert repo.writes == []


def test_chunked_oversized_body_is_rejected(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    alert = alert_row()
    repo.alerts.append(alert)

    def chunks() -> Any:
        yield b'{"status":"acknowledged","note":"'
        for _ in range(20):
            yield b"b" * 8192
        yield b'"}'

    response = client.post(
        f"/api/v1/alerts/{alert['alert_id']}/state",
        headers={**analyst, "Content-Type": "application/json"},
        content=chunks(),
    )
    assert response.status_code == 413
    assert repo.writes == []


def test_unexpected_storage_error_is_503_without_details(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    from clickhouse_connect.driver.exceptions import DatabaseError

    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise DatabaseError("Code: 60. secret SQL text here")

    repo.all_assets = boom  # type: ignore[method-assign]
    response = client.get(OVERVIEW, headers=analyst)
    assert response.status_code == 503
    assert response.json()["detail"] == "storage query failed or unavailable"
    assert "SQL" not in response.text
    assert response.headers["x-content-type-options"] == "nosniff"


def test_storage_quota_exhaustion_is_429_with_retry_after(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    """ClickHouse QUOTA_EXCEEDED (code 201) is load, not an outage: 429 + Retry-After so the
    console does not retry at once (it retries 503), and nothing of the error leaks."""
    from clickhouse_connect.driver.exceptions import DatabaseError

    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise DatabaseError(
            "Received ClickHouse exception, code: 201, server response: Code: 201. "
            "DB::Exception: Quota for user `synthetic` for 60s has been exceeded: "
            "queries = 1201/1200. (QUOTA_EXCEEDED)"
        )

    repo.all_assets = boom  # type: ignore[method-assign]
    response = client.get(OVERVIEW, headers=analyst)
    assert response.status_code == 429
    assert response.headers["retry-after"] == "30"
    assert "quota" in response.json()["detail"]
    assert "synthetic" not in response.text and "1201" not in response.text
    assert response.headers["x-content-type-options"] == "nosniff"


def test_unexpected_error_is_generic_500(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("internal detail that must not leak")

    repo.all_assets = boom  # type: ignore[method-assign]
    response = client.get(OVERVIEW, headers=analyst)
    assert response.status_code == 500
    assert response.json()["detail"] == "internal error"
    assert "must not leak" not in response.text


def test_validation_errors_do_not_reflect_input(
    client: TestClient, analyst: dict[str, str]
) -> None:
    response = client.get(
        "/api/v1/alerts", headers=analyst, params={"severity": "<img src=x onerror=1>"}
    )
    assert response.status_code == 422
    assert "onerror" not in response.text


def test_docs_and_openapi_are_not_served_by_default(client: TestClient) -> None:
    assert client.get("/api/v1/openapi.json").status_code == 404
    assert client.get("/api/v1/docs").status_code == 404
    assert client.get("/docs").status_code == 404
