"""PlatformIntegrations: how the API treats stored contexts and Jev configuration.

SYNTHETIC: the correlation store and the AI settings are replaced with stand-ins; nothing
talks to ClickHouse or reads a key.
"""

from __future__ import annotations

from typing import Any

import pytest
from api_fakes import hexid, make_context

from extorq.api.errors import ApiError
from extorq.api.integrations import JEV_TRIAGE, PlatformIntegrations
from extorq.correlation import store


class _Repo:
    """Only what PlatformIntegrations.load_context uses."""

    def read_client(self) -> object:
        return object()


def test_unreadable_stored_context_is_treated_as_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """A context stored under an older contract does not validate: the route rebuilds it."""

    def unreadable(_client: Any, _alert_id: str) -> None:
        raise store.ContextStoreError("stored context failed validation (3 error(s))")

    monkeypatch.setattr(store, "load_latest_context", unreadable)
    assert PlatformIntegrations().load_context(_Repo(), hexid("a1")) is None  # type: ignore[arg-type]


def test_integrity_failure_is_an_error_never_rebuilt(monkeypatch: pytest.MonkeyPatch) -> None:
    def tampered(_client: Any, _alert_id: str) -> None:
        raise store.ContextIntegrityError("stored context x does not match its input_hash")

    monkeypatch.setattr(store, "load_latest_context", tampered)
    with pytest.raises(ApiError, match="integrity check"):
        PlatformIntegrations().load_context(_Repo(), hexid("a1"))  # type: ignore[arg-type]


def test_valid_stored_context_is_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    context = make_context(hexid("a1"))
    monkeypatch.setattr(store, "load_latest_context", lambda _c, _a: context)
    assert PlatformIntegrations().load_context(_Repo(), hexid("a1")) == context  # type: ignore[arg-type]


def test_ai_configuration_reports_jev_only_and_never_a_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from extorq.ai import settings as ai_settings

    class _Key:
        state = ai_settings.KeyState.CONFIGURED

    class _Settings:
        jev_enabled = True

    monkeypatch.setattr(ai_settings, "get_ai_settings", lambda: _Settings())
    monkeypatch.setattr(ai_settings, "resolve_key", lambda *_a, **_k: _Key())
    configuration, source = PlatformIntegrations().ai_configuration()
    assert configuration == {JEV_TRIAGE: {"configured": True, "enabled": True}}
    assert JEV_TRIAGE == ("typesafe-jev", "triage")
    assert "ai-worker may differ" in source


def test_ai_configuration_failure_is_unknown_not_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from extorq.ai import settings as ai_settings

    def broken() -> None:
        raise RuntimeError("synthetic settings failure")

    monkeypatch.setattr(ai_settings, "get_ai_settings", broken)
    configuration, source = PlatformIntegrations().ai_configuration()
    assert configuration == {}
    assert source.startswith("unavailable")
