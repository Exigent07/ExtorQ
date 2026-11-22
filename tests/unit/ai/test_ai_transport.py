"""Provider HTTP clients ignore proxy / CA / key-log environment overrides (no network).

The real SDK request paths (google-genai ``generate_content``, typesafe ``system_one``) run
against ``httpx2.MockTransport`` under a hostile environment: proxy variables, an invalid
``SSL_CERT_FILE``/``SSL_CERT_DIR``, ``SSLKEYLOGFILE``, a backend switch and base-URL overrides.
Keys used here are obviously fake.
"""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any

import httpx2
import pytest
from ai_fakes import enabled_settings

from extorq.ai import gemini, jev, transport

GOOGLE = httpx2.URL("https://generativelanguage.googleapis.com/v1/models/x:generateContent")
FAKE_KEY = "offline-test-key-" + "7" * 16
_ORIGINAL_SYNC = transport.sync_client


@pytest.fixture
def hostile_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "attacker-ca.pem"))  # does not exist
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path / "attacker-ca.d"))
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "keylog.txt"))
    monkeypatch.setenv("GOOGLE_GENAI_HTTP_CLIENT", "httpx")
    monkeypatch.setenv("GOOGLE_GEMINI_BASE_URL", "https://attacker.invalid/")
    monkeypatch.setenv("TYPESAFE_BASE_URL", "https://attacker.invalid")
    return tmp_path


def _mock_clients(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    """Keep every production client option; only swap the network for a mock transport."""

    def sync_client(timeout_seconds: float, *, transport: Any = None) -> httpx2.Client:
        return _ORIGINAL_SYNC(timeout_seconds, transport=httpx2.MockTransport(handler))

    monkeypatch.setattr(transport, "sync_client", sync_client)


def test_tls_context_ignores_ca_and_keylog_environment(hostile_env: Path) -> None:
    ctx = transport.tls_context()  # would raise if it tried to load the missing SSL_CERT_FILE
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert ctx.keylog_filename is None
    assert ctx.cert_store_stats()["x509_ca"] > 0  # certifi bundle, not the environment's


def test_clients_ignore_proxy_variables_and_never_follow_redirects(
    hostile_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = transport.sync_client(5.0)
    assert client.trust_env is False
    assert client.follow_redirects is False
    assert client._transport_for_url(GOOGLE) is client._transport  # no proxy mount
    aclient = transport.async_client(5.0)
    assert aclient.trust_env is False and aclient.follow_redirects is False
    # Positive controls: an SDK-default client honours the same environment: it loads the
    # CA bundle named by SSL_CERT_FILE (missing here) ...
    with pytest.raises(FileNotFoundError):
        httpx2.Client()
    monkeypatch.delenv("SSL_CERT_FILE")
    monkeypatch.delenv("SSL_CERT_DIR")
    default = httpx2.Client()
    # ... and routes the request through the proxy from HTTPS_PROXY.
    assert default._transport_for_url(GOOGLE) is not default._transport


def test_redirect_is_returned_not_followed(hostile_env: Path) -> None:
    seen: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(str(request.url))
        return httpx2.Response(302, headers={"location": "https://attacker.invalid/steal"})

    client = transport.sync_client(5.0, transport=httpx2.MockTransport(handler))
    response = client.get("https://api.typesafe.ai/v1/systemone")
    assert response.status_code == 302
    assert seen == ["https://api.typesafe.ai/v1/systemone"]


def test_gemini_sdk_sends_only_through_the_pinned_client(
    hostile_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        body = {
            "candidates": [
                {
                    "content": {"parts": [{"text": '{"ok": true}'}], "role": "model"},
                    "finishReason": "STOP",
                }
            ],
            "usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 3},
            "modelVersion": "gemini-3.6-flash",
            "responseId": "resp-offline-1",
        }
        return httpx2.Response(200, json=body)

    _mock_clients(monkeypatch, handler)
    settings = enabled_settings()
    client = gemini._default_client_factory(FAKE_KEY, settings)
    api = client._api_client  # type: ignore[attr-defined]
    assert api._httpx_client.trust_env is False
    assert api._httpx_client.follow_redirects is False
    assert api._async_httpx_client.trust_env is False
    assert api._use_aiohttp() is False
    assert api._websocket_ssl_ctx["ssl"].keylog_filename is None
    response = client.models.generate_content(
        model=settings.gemini_model, contents="hello", config=gemini.build_generate_config(settings)
    )
    assert response.text == '{"ok": true}'
    (request,) = seen
    assert request.url.host == "generativelanguage.googleapis.com"
    assert request.url.path == f"/v1/models/{settings.gemini_model}:generateContent"


def test_jev_sdk_sends_only_through_the_pinned_client(
    hostile_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(str(request.url))
        return httpx2.Response(400, json={"error": {"type": "invalid_request_error"}})

    _mock_clients(monkeypatch, handler)
    client = jev._default_client_factory(FAKE_KEY, enabled_settings())
    http_client = client._http_client  # type: ignore[attr-defined]
    assert http_client.trust_env is False and http_client.follow_redirects is False
    question = jev.question_set(jev.Domain.GENERIC).questions[0]
    with pytest.raises(Exception) as excinfo:
        client.system_one({"probe": 1}, {question.name: question.to_sdk()}, model="jev-1.14.0")
    assert type(excinfo.value).__name__ == "TypeSafeBadRequestError"
    assert seen == [f"{jev.JEV_BASE_URL}/v1/systemone"]


def test_request_lines_are_not_logged() -> None:
    import logging

    transport.sync_client(5.0)
    assert logging.getLogger("httpx2").getEffectiveLevel() >= logging.WARNING
