"""GitHubClient: headers, pagination, ETag/304, rate limits, retries, limits (synthetic)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from extorq_collectors.github.client import (
    API_VERSION,
    GitHubClient,
    GitHubConflict,
    GitHubForbidden,
    GitHubNotFound,
    GitHubRateLimited,
    GitHubResponseError,
    GitHubTransientError,
    GitHubUnauthorized,
    parse_link_header,
)

API = "https://api.github.com"
# Synthetic, token-shaped test value (never a real credential).
FAKE_TOKEN = "ghp_" + "S" * 36

Handler = Callable[[httpx.Request], httpx.Response]


class Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def make_client(handler: Handler, clock: Clock | None = None, **kwargs: Any) -> GitHubClient:
    clock = clock or Clock()
    return GitHubClient(
        FAKE_TOKEN,
        transport=httpx.MockTransport(handler),
        sleep=clock.sleep,
        clock=clock.time,
        rng=lambda: 0.5,
        **kwargs,
    )


def json_response(
    status: int, payload: Any, headers: dict[str, str] | None = None
) -> httpx.Response:
    return httpx.Response(status, json=payload, headers=headers or {})


def test_headers_and_repr_never_expose_token() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return json_response(200, {"ok": True})

    client = make_client(handler)
    assert client.get("/repos/o/r").data == {"ok": True}
    request = seen[0]
    assert request.method == "GET"
    assert request.headers["accept"] == "application/vnd.github+json"
    assert request.headers["x-github-api-version"] == API_VERSION == "2022-11-28"
    assert request.headers["authorization"] == f"Bearer {FAKE_TOKEN}"
    assert request.headers["user-agent"].startswith("extorq-github-collector/")
    assert FAKE_TOKEN not in repr(client)
    assert FAKE_TOKEN not in str(client)


def test_rejects_unsafe_construction_and_paths() -> None:
    with pytest.raises(ValueError):
        GitHubClient(FAKE_TOKEN, base_url="http://api.github.com")
    with pytest.raises(ValueError):
        GitHubClient("ghp_with space " + "x" * 30)
    client = make_client(lambda r: json_response(200, {}))
    with pytest.raises(ValueError):
        client.get("https://evil.example/repos")
    with pytest.raises(ValueError):
        client.get("repos/o/r")


def test_parse_link_header() -> None:
    value = f'<{API}/x?page=2>; rel="next", <{API}/x?page=5>; rel="last"'
    assert parse_link_header(value) == {"next": f"{API}/x?page=2", "last": f"{API}/x?page=5"}
    assert parse_link_header(None) == {}
    assert parse_link_header("garbage") == {}


def paged_handler(total: int, per_page: int, *, next_host: str = "api.github.com") -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", "1"))
        items = list(range((page - 1) * per_page, min(total, page * per_page)))
        headers = {}
        if page * per_page < total:
            url = f"https://{next_host}/items?per_page={per_page}&page={page + 1}"
            headers["link"] = f'<{url}>; rel="next"'
        return json_response(200, items, headers)

    return handler


def test_pagination_follows_link_header_across_pages() -> None:
    client = make_client(paged_handler(total=7, per_page=3))
    result = client.paginate("/items", params={"per_page": 3})
    assert result.items == list(range(7))
    assert result.pages == 3
    assert result.truncated is False
    assert client.request_count == 3


def test_pagination_is_bounded_by_max_pages() -> None:
    client = make_client(paged_handler(total=50, per_page=5))
    result = client.paginate("/items", params={"per_page": 5}, max_pages=2)
    assert result.items == list(range(10))
    assert result.truncated is True
    assert client.request_count == 2


def test_pagination_stop_predicate_ends_after_current_page() -> None:
    client = make_client(paged_handler(total=50, per_page=5))
    result = client.paginate("/items", params={"per_page": 5}, stop=lambda item: item == 7)
    assert result.items == list(range(10))
    # Stopping at a checkpoint item is intentional, not truncation.
    assert result.truncated is False
    assert client.request_count == 2


def test_pagination_link_to_another_origin_is_refused() -> None:
    client = make_client(paged_handler(total=10, per_page=5, next_host="evil.example"))
    with pytest.raises(GitHubResponseError, match="outside the API origin"):
        client.paginate("/items")


def test_pagination_items_key_and_shape_validation() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(200, {"total_count": 2, "workflow_runs": [{"id": 1}, {"id": 2}]})

    client = make_client(handler)
    result = client.paginate("/runs", items_key="workflow_runs")
    assert [r["id"] for r in result.items] == [1, 2]
    assert result.first["total_count"] == 2
    with pytest.raises(GitHubResponseError, match="JSON array"):
        client.paginate("/runs")


def test_conditional_request_304_is_reported_and_counted() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.headers.get("if-none-match") == 'W/"abc"':
            return httpx.Response(304, headers={"etag": 'W/"abc"'})
        return json_response(200, {"v": 1}, {"etag": 'W/"abc"'})

    client = make_client(handler)
    first = client.get("/repos/o/r")
    assert first.etag == 'W/"abc"' and not first.not_modified
    second = client.get("/repos/o/r", etag=first.etag)
    assert second.not_modified and second.data is None and second.etag == 'W/"abc"'
    assert seen[1].headers["if-none-match"] == 'W/"abc"'
    assert "if-none-match" not in seen[0].headers
    assert client.not_modified_count == 1


def test_paginate_with_etag_304_returns_unchanged_listing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(304, headers={"etag": 'W/"list"'})

    client = make_client(handler)
    result = client.paginate("/runs", etag='W/"list"', items_key="workflow_runs")
    assert result.not_modified and result.items == [] and result.etag == 'W/"list"'


def test_unconditional_304_is_not_a_complete_empty_listing() -> None:
    client = make_client(lambda _request: httpx.Response(304))
    with pytest.raises(GitHubResponseError, match="unexpected 304"):
        client.paginate("/runs", items_key="workflow_runs")
    assert client.not_modified_count == 0


def test_primary_rate_limit_waits_until_reset_then_retries() -> None:
    clock = Clock()
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return json_response(
                403,
                {"message": "API rate limit exceeded for user ID 1."},
                {
                    "x-ratelimit-remaining": "0",
                    "x-ratelimit-limit": "5000",
                    "x-ratelimit-reset": str(int(clock.now) + 20),
                },
            )
        return json_response(
            200,
            {"ok": True},
            {"x-ratelimit-remaining": "4999", "x-ratelimit-reset": str(int(clock.now) + 3600)},
        )

    client = make_client(handler, clock, max_rate_limit_wait=60)
    assert client.get("/repos/o/r").data == {"ok": True}
    assert len(calls) == 2
    assert sum(clock.sleeps) == pytest.approx(21, abs=1)
    assert client.rate_limit.remaining == 4999


def test_primary_rate_limit_beyond_budget_raises_without_blocking() -> None:
    clock = Clock()

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            403,
            {"message": "API rate limit exceeded"},
            {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(clock.now) + 1800)},
        )

    client = make_client(handler, clock, max_rate_limit_wait=60)
    with pytest.raises(GitHubRateLimited) as info:
        client.get("/repos/o/r")
    assert info.value.retry_at is not None and info.value.retry_at > clock.now + 1700
    assert clock.sleeps == []


def test_known_exhaustion_is_not_sent_until_reset() -> None:
    clock = Clock()
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return json_response(
            200, {}, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(clock.now) + 600)}
        )

    client = make_client(handler, clock, max_rate_limit_wait=60)
    client.get("/a")  # succeeds but leaves the budget exhausted
    with pytest.raises(GitHubRateLimited, match="not sent"):
        client.get("/b")
    assert calls == ["/a"]


def test_secondary_rate_limit_retry_after_is_honoured() -> None:
    clock = Clock()
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return json_response(
                403,
                {"message": "You have exceeded a secondary rate limit."},
                {"retry-after": "7"},
            )
        return json_response(200, [])

    client = make_client(handler, clock)
    client.get("/x")
    assert clock.sleeps == [7.0]
    assert client.rate_limit.secondary_hits == 1


def test_secondary_rate_limit_without_headers_backs_off_at_least_a_minute() -> None:
    clock = Clock()
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return json_response(429, {"message": "too many requests"})
        return json_response(200, [])

    client = make_client(handler, clock, max_rate_limit_wait=120)
    client.get("/x")
    assert clock.sleeps == [60.0]


def test_secondary_rate_limit_wait_beyond_budget_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(403, {"message": "You have exceeded a secondary rate limit"})

    client = make_client(handler, max_rate_limit_wait=30)
    with pytest.raises(GitHubRateLimited):
        client.get("/x")


def test_rate_limit_retries_are_bounded() -> None:
    clock = Clock()
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return json_response(403, {"message": "secondary rate limit"}, {"retry-after": "1"})

    client = make_client(handler, clock, max_attempts=3)
    with pytest.raises(GitHubRateLimited):
        client.get("/x")
    assert len(calls) == 3
    assert clock.sleeps == [1.0, 1.0]


def test_server_errors_are_retried_with_bounded_backoff() -> None:
    clock = Clock()
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return json_response(502, {"message": "Bad gateway"})

    client = make_client(handler, clock, max_attempts=3, backoff_base=1.0, backoff_cap=30.0)
    with pytest.raises(GitHubTransientError):
        client.get("/x")
    assert len(calls) == 3
    # jittered exponential backoff with rng()=0.5 -> factor 0.75
    assert clock.sleeps == [0.75, 1.5]


def test_network_errors_are_retried_then_reported_without_details() -> None:
    clock = Clock()
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) < 3:
            raise httpx.ConnectTimeout("timed out", request=request)
        return json_response(200, {"ok": True})

    client = make_client(handler, clock)
    assert client.get("/x").data == {"ok": True}
    assert len(calls) == 3

    def always(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"boom {FAKE_TOKEN}", request=request)

    client = make_client(always, Clock())
    with pytest.raises(GitHubTransientError) as info:
        client.get("/x")
    assert FAKE_TOKEN not in str(info.value)
    assert "ConnectError" in str(info.value)


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (401, GitHubUnauthorized),
        (404, GitHubNotFound),
        (410, GitHubNotFound),
        (409, GitHubConflict),
        (403, GitHubForbidden),
    ],
)
def test_error_statuses_map_to_typed_errors(status: int, error: type[Exception]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            status,
            {"message": "Resource not accessible by personal access token"},
            {"x-accepted-github-permissions": "administration=read"},
        )

    client = make_client(handler)
    with pytest.raises(error) as info:
        client.get("/repos/o/r/branches/main/protection")
    if status in (403, 404):
        assert "administration=read" in info.value.gap_reason  # type: ignore[attr-defined]


def test_error_messages_are_sanitised() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(404, {"message": "Not\x1b[31m Found\n" + "x" * 500})

    client = make_client(handler)
    with pytest.raises(GitHubNotFound) as info:
        client.get("/x")
    assert "\x1b" not in str(info.value) and "\n" not in str(info.value)
    assert len(info.value.message) <= 200


def test_response_size_is_capped() -> None:
    big = json.dumps(["x" * 1000] * 200).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=big)

    client = make_client(handler, max_response_bytes=10_000)
    with pytest.raises(GitHubResponseError, match="exceeds"):
        client.get("/x")


def test_invalid_json_is_a_response_error() -> None:
    client = make_client(lambda r: httpx.Response(200, content=b"<html>"))
    with pytest.raises(GitHubResponseError, match="not valid JSON"):
        client.get("/x")


def test_raw_content_and_204() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/raw":
            assert request.headers["accept"] == "application/vnd.github.raw+json"
            return httpx.Response(200, content=b"name: CI\n")
        return httpx.Response(204)

    client = make_client(handler)
    assert client.get_text("/raw", max_bytes=100) == "name: CI\n"
    assert client.get("/vulnerability-alerts").data is None
    with pytest.raises(GitHubResponseError):
        oversized = make_client(lambda r: httpx.Response(200, content=b"x" * 101))
        oversized.get_text("/raw", max_bytes=100)


def test_text_prefix_reads_at_most_the_bound_and_reports_truncation() -> None:
    body = b"permissions: write-all\n" + b"#" * 5000

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept"] == "application/vnd.github.raw+json"
        # Declared length larger than the bound must not fail a prefix read.
        return httpx.Response(200, content=body, headers={"content-length": str(len(body))})

    client = make_client(handler)
    text, truncated = client.get_text_prefix("/raw", max_bytes=100)
    assert truncated is True and text == body[:100].decode()
    small, cut = client.get_text_prefix("/raw", max_bytes=len(body))
    assert cut is False and small == body.decode()
    # Error bodies keep the strict cap and typed errors.
    missing = make_client(lambda r: httpx.Response(404, json={"message": "Not Found"}))
    with pytest.raises(GitHubNotFound):
        missing.get_text_prefix("/raw", max_bytes=100)
    with pytest.raises(ValueError):
        client.get_text_prefix("https://evil.example/raw", max_bytes=100)
    # Non-raw requests never silently truncate JSON.
    big_json = make_client(lambda r: httpx.Response(200, content=body), max_response_bytes=100)
    with pytest.raises(GitHubResponseError, match="exceeds"):
        big_json.get("/raw")


def test_rate_limit_and_token_metadata_headers_are_recorded() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            200,
            {},
            {
                "x-ratelimit-remaining": "4321",
                "x-ratelimit-limit": "5000",
                "x-ratelimit-reset": "1800003600",
                "x-ratelimit-used": "679",
                "x-ratelimit-resource": "core",
                "x-oauth-scopes": "repo, workflow, read:org",
                "github-authentication-token-expiration": "2026-12-01 00:00:00 UTC",
            },
        )

    client = make_client(handler)
    client.get("/x")
    assert client.rate_limit.remaining == 4321 and client.rate_limit.limit == 5000
    assert client.rate_limit.reset_at == 1800003600.0 and client.rate_limit.resource == "core"
    assert client.token_scopes == ("repo", "workflow", "read:org")
    assert client.token_expiration == "2026-12-01 00:00:00 UTC"
