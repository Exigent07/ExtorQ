"""Read-only Kubernetes API client (extorq_collectors.kubernetes.api).

All credentials here are SYNTHETIC test values (fake CA text, fake token strings);
no request leaves the process (httpx.MockTransport).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from extorq_collectors.kubernetes.api import (
    KubeApiError,
    KubeClient,
    KubeConfigError,
    KubeConnection,
    KubeForbidden,
    KubeGone,
    KubeUnauthorized,
    KubeUnavailable,
    jwt_expiry,
    read_token,
    token_expiry,
    unauthorized_reason,
)

SYNTHETIC_CA = (
    "-----BEGIN CERTIFICATE-----\nU1lOVEhFVElDLU5PVC1BLUNFUlQ=\n-----END CERTIFICATE-----\n"
)
SYNTHETIC_TOKEN = "synthetic-test-token-not-a-credential"


def write_kubeconfig(
    tmp_path: Path,
    *,
    server: str = "https://127.0.0.1:6443",
    user: dict[str, Any] | None = None,
    cluster_extra: dict[str, Any] | None = None,
) -> Path:
    token_file = tmp_path / "inventory.token"
    token_file.write_text(SYNTHETIC_TOKEN + "\n")
    token_file.chmod(0o600)
    doc = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "name": "c",
                "cluster": {
                    "server": server,
                    "certificate-authority-data": base64.b64encode(SYNTHETIC_CA.encode()).decode(),
                    **(cluster_extra or {}),
                },
            }
        ],
        "users": [
            {"name": "u", "user": user if user is not None else {"tokenFile": str(token_file)}}
        ],
        "contexts": [{"name": "ctx", "context": {"cluster": "c", "user": "u"}}],
        "current-context": "ctx",
    }
    path = tmp_path / "kubeconfig"
    path.write_text(json.dumps(doc))  # JSON is valid YAML
    return path


def client_for(
    tmp_path: Path, handler: Callable[[httpx.Request], httpx.Response], **kwargs: Any
) -> tuple[KubeClient, list[float]]:
    sleeps: list[float] = []
    conn = KubeConnection.from_kubeconfig(write_kubeconfig(tmp_path))
    client = KubeClient(
        conn, transport=httpx.MockTransport(handler), sleep=sleeps.append, rng=lambda: 0.5, **kwargs
    )
    return client, sleeps


def test_kubeconfig_loads_token_file_identity(tmp_path: Path) -> None:
    conn = KubeConnection.from_kubeconfig(write_kubeconfig(tmp_path))
    assert conn.server == "https://127.0.0.1:6443"
    assert conn.token_file == tmp_path / "inventory.token"
    assert "BEGIN CERTIFICATE" in conn.ca_pem
    assert SYNTHETIC_TOKEN not in repr(conn)


@pytest.mark.parametrize(
    ("user", "message"),
    [
        ({"client-certificate-data": "eA==", "client-key-data": "eA=="}, "client-certificate-data"),
        ({"token": "inline"}, "token"),
        ({"exec": {"command": "x"}}, "exec"),
        ({}, "no tokenFile"),
    ],
)
def test_kubeconfig_refuses_anything_but_a_token_file(
    tmp_path: Path, user: dict[str, Any], message: str
) -> None:
    with pytest.raises(KubeConfigError, match=message):
        KubeConnection.from_kubeconfig(write_kubeconfig(tmp_path, user=user))


@pytest.mark.parametrize(
    "server", ["http://127.0.0.1:6443", "https://10.0.0.5:6443", "https://kubernetes.example.com"]
)
def test_kubeconfig_requires_https_loopback(tmp_path: Path, server: str) -> None:
    with pytest.raises(KubeConfigError, match="loopback"):
        KubeConnection.from_kubeconfig(write_kubeconfig(tmp_path, server=server))


def test_kubeconfig_refuses_insecure_skip_verify(tmp_path: Path) -> None:
    with pytest.raises(KubeConfigError, match="insecure"):
        KubeConnection.from_kubeconfig(
            write_kubeconfig(tmp_path, cluster_extra={"insecure-skip-tls-verify": True})
        )


def test_missing_kubeconfig_points_to_kind_token(tmp_path: Path) -> None:
    with pytest.raises(KubeConfigError, match=r"kind\.sh token"):
        KubeConnection.from_kubeconfig(tmp_path / "absent")


def test_read_token_validation(tmp_path: Path) -> None:
    path = tmp_path / "t"
    path.write_text("a b")
    with pytest.raises(KubeConfigError):
        read_token(path)
    path.write_text("")
    with pytest.raises(KubeConfigError):
        read_token(path)
    path.write_text("x" * 20000)
    with pytest.raises(KubeConfigError, match="too large"):
        read_token(path)


def test_token_expiry_reads_exp_claim_of_a_synthetic_jwt(tmp_path: Path) -> None:
    def b64(data: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    path = tmp_path / "t"
    path.write_text(f"{b64({'alg': 'none'})}.{b64({'exp': 1795280000})}.synthetic-signature")
    assert token_expiry(path) == datetime.fromtimestamp(1795280000, UTC)
    path.write_text("not-a-jwt")
    assert token_expiry(path) is None


def test_list_paginates_and_sends_the_bearer_token(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.params.get("continue") == "page2":
            return httpx.Response(
                200, json={"items": [{"n": 3}], "metadata": {"resourceVersion": "12"}}
            )
        return httpx.Response(
            200,
            json={
                "items": [{"n": 1}, {"n": 2}],
                "metadata": {"continue": "page2", "resourceVersion": "11"},
            },
        )

    client, _ = client_for(tmp_path, handler, page_size=2)
    result = client.list("/api/v1/pods")
    assert [i["n"] for i in result.items] == [1, 2, 3]
    assert result.pages == 2 and result.resource_version == "12"
    assert all(r.method == "GET" for r in seen)
    assert seen[0].headers["authorization"] == f"Bearer {SYNTHETIC_TOKEN}"
    assert seen[0].url.params["limit"] == "2"


def test_list_restarts_after_410_gone(tmp_path: Path) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if request.url.params.get("continue") == "stale":
            return httpx.Response(410, json={"kind": "Status", "reason": "Expired"})
        if calls["n"] == 1:
            return httpx.Response(
                200, json={"items": [{"n": 1}], "metadata": {"continue": "stale"}}
            )
        return httpx.Response(200, json={"items": [{"n": 1}, {"n": 2}], "metadata": {}})

    client, _ = client_for(tmp_path, handler)
    result = client.list("/api/v1/events")
    assert result.relists == 1 and [i["n"] for i in result.items] == [1, 2]
    assert client.stats.relists == 1


def test_list_gives_up_after_bounded_relists(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("continue"):
            return httpx.Response(410, json={"reason": "Expired"})
        return httpx.Response(200, json={"items": [], "metadata": {"continue": "x"}})

    client, _ = client_for(tmp_path, handler, max_relists=2)
    with pytest.raises(KubeGone):
        client.list("/api/v1/pods")


def test_status_codes_map_to_typed_errors_without_secrets(tmp_path: Path) -> None:
    for status, exc_type in ((401, KubeUnauthorized), (403, KubeForbidden), (404, KubeApiError)):

        def handler(_request: httpx.Request, status: int = status) -> httpx.Response:
            return httpx.Response(
                status,
                json={
                    "kind": "Status",
                    "reason": "Forbidden",
                    "message": "secret detail " + SYNTHETIC_TOKEN,
                },
            )

        client, sleeps = client_for(tmp_path, handler)
        with pytest.raises(exc_type) as info:
            client.get("/api/v1/secrets")
        assert SYNTHETIC_TOKEN not in str(info.value)
        assert "secret detail" not in str(info.value)  # Status message bodies are not echoed
        assert sleeps == []  # not retried


def test_retries_transient_errors_with_backoff(tmp_path: Path) -> None:
    responses = iter(
        [
            httpx.Response(503),
            httpx.Response(429, headers={"Retry-After": "2"}),
            httpx.Response(200, json={"gitVersion": "v1.37.0"}),
        ]
    )
    client, sleeps = client_for(tmp_path, lambda _r: next(responses), max_attempts=3)
    assert client.get("/version") == {"gitVersion": "v1.37.0"}
    assert len(sleeps) == 2 and sleeps[1] >= 2.0
    assert client.stats.retries == 2


def test_transport_errors_exhaust_into_unavailable(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client, sleeps = client_for(tmp_path, handler, max_attempts=3)
    with pytest.raises(KubeUnavailable, match="3 attempts"):
        client.get("/version")
    assert len(sleeps) == 2


def test_rejects_non_api_paths(tmp_path: Path) -> None:
    client, _ = client_for(tmp_path, lambda _r: httpx.Response(200, json={}))
    with pytest.raises(ValueError):
        client.get("https://evil.example/api")
    with pytest.raises(ValueError):
        client.get("/api/../../etc")


def test_token_file_is_reread_for_rotation(tmp_path: Path) -> None:
    tokens: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        tokens.append(request.headers["authorization"])
        return httpx.Response(200, json={"items": [], "metadata": {}})

    client, _ = client_for(tmp_path, handler)
    client.list("/api/v1/pods")
    (tmp_path / "inventory.token").write_text("synthetic-rotated-token")
    client.list("/api/v1/pods")
    assert tokens == [f"Bearer {SYNTHETIC_TOKEN}", "Bearer synthetic-rotated-token"]


# ── token rotation and 401 handling (all tokens SYNTHETIC) ────────────


def synthetic_jwt(exp: int, marker: str = "a") -> str:
    """An unsigned JWT-shaped string with an ``exp`` claim (not a credential)."""

    def b64(data: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return f"{b64({'alg': 'none'})}.{b64({'exp': exp, 'sub': marker})}.synthetic-signature"


def test_401_retries_once_with_a_token_re_minted_meanwhile(tmp_path: Path) -> None:
    """kind.sh token replaced the file while the request with the old token was in flight."""
    old = synthetic_jwt(1_700_000_000, "old")  # expired
    new = synthetic_jwt(4_000_000_000, "new")
    token_file = tmp_path / "inventory.token"
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["authorization"])
        if request.headers["authorization"] == f"Bearer {new}":
            return httpx.Response(200, json={"items": [], "metadata": {}})
        token_file.write_text(new + "\n")  # the re-mint lands during the rejected request
        return httpx.Response(401, json={"kind": "Status", "reason": "Unauthorized"})

    client, sleeps = client_for(tmp_path, handler)
    token_file.write_text(old)
    assert client.list("/api/v1/pods").items == []
    assert seen == [f"Bearer {old}", f"Bearer {new}"]
    assert client.stats.token_reloads == 1 and sleeps == []


def test_401_with_an_unchanged_token_fails_fast_and_says_it_expired(tmp_path: Path) -> None:
    expired = synthetic_jwt(1_700_000_000)  # 2023-11-14T22:13:20Z
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.headers["authorization"])
        return httpx.Response(401, json={"kind": "Status", "reason": "Unauthorized"})

    client, sleeps = client_for(tmp_path, handler)
    (tmp_path / "inventory.token").write_text(expired)
    with pytest.raises(KubeUnauthorized) as info:
        client.get("/version")
    message = str(info.value)
    assert "token expired at 2023-11-14T22:13:20Z" in message
    assert "kind.sh token" in message and "no restart needed" in message
    assert expired not in message and "synthetic-signature" not in message
    assert len(calls) == 1 and sleeps == [] and client.stats.token_reloads == 0


def test_401_after_the_reload_is_final(tmp_path: Path) -> None:
    """Both the old and the re-minted token rejected: exactly one retry, then 401."""
    token_file = tmp_path / "inventory.token"
    tokens = iter([synthetic_jwt(4_000_000_000, "second"), synthetic_jwt(4_000_000_000, "third")])
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        token_file.write_text(next(tokens))  # rotates on every request
        return httpx.Response(401, json={"kind": "Status", "reason": "Unauthorized"})

    client, _ = client_for(tmp_path, handler)
    token_file.write_text(synthetic_jwt(4_000_000_000, "first"))
    with pytest.raises(KubeUnauthorized, match="rejected before its expiry"):
        client.get("/version")
    assert calls["n"] == 2 and client.stats.token_reloads == 1


def test_unauthorized_reason_uses_the_exp_claim_only() -> None:
    now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
    expired = synthetic_jwt(int(datetime(2026, 11, 22, 11, 0, tzinfo=UTC).timestamp()))
    valid = synthetic_jwt(int(datetime(2026, 11, 24, 7, 0, tzinfo=UTC).timestamp()))
    assert unauthorized_reason(expired, now) == "token expired at 2026-11-22T11:00:00Z"
    assert unauthorized_reason(valid, now).startswith(
        "token rejected before its expiry 2026-11-24T07:00:00Z"
    )
    assert unauthorized_reason("not-a-jwt", now) == "token rejected; expiry unknown"
    assert jwt_expiry("a.%%%.b") is None
