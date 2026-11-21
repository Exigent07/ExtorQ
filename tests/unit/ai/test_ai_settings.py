"""Settings, flags and key resolution: keys are never exposed."""

from __future__ import annotations

from pathlib import Path

import pytest

from extorq.ai import settings as ai_settings
from extorq.ai.settings import AISettings, KeyState, resolve_key, startup_report

SECRET = "unit-test-secret-value-1234567890"  # synthetic test credential


def test_ai_disabled_by_default() -> None:
    s = AISettings()
    assert s.jev_enabled is False
    assert s.gemini_enabled is False
    assert s.jev_model == "jev-1.14.0"
    assert s.gemini_model == "gemini-3.6-flash"
    assert s.jev_daily_cap == 300
    assert s.gemini_daily_cap == 50


def test_flags_and_caps_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EXTORQ_JEV_ENABLED", "true")
    monkeypatch.setenv("EXTORQ_GEMINI_DAILY_CAP", "7")
    s = AISettings()
    assert s.jev_enabled is True
    assert s.gemini_daily_cap == 7


def test_invalid_model_id_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EXTORQ_JEV_MODEL", "jev latest; rm -rf /")
    with pytest.raises(ValueError):
        AISettings()


def test_key_from_file_takes_precedence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    key_file = tmp_path / "jev_api_key"
    key_file.write_text(SECRET + "\n", encoding="utf-8")
    monkeypatch.setenv("JEV_API_KEY_FILE", str(key_file))
    monkeypatch.setenv("JEV_API_KEY", "other-value-should-not-win-123")
    key = resolve_key("JEV_API_KEY")
    assert key.state is KeyState.CONFIGURED
    assert key.source == "file"
    assert key.value is not None and key.value.get_secret_value() == SECRET


def test_key_never_in_repr_or_description(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", SECRET)
    key = resolve_key("GEMINI_API_KEY")
    assert key.usable
    assert SECRET not in repr(key)
    assert SECRET not in str(key)
    assert SECRET not in key.describe()


def test_unreadable_and_malformed_keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("JEV_API_KEY_FILE", str(tmp_path / "missing"))
    assert resolve_key("JEV_API_KEY").state is KeyState.UNREADABLE
    monkeypatch.delenv("JEV_API_KEY_FILE")
    monkeypatch.setenv("JEV_API_KEY", "has space inside")
    malformed = resolve_key("JEV_API_KEY")
    assert malformed.state is KeyState.MALFORMED
    assert "has space" not in malformed.describe()


def test_dotenv_dev_fallback_and_api_opt_out(tmp_path: Path) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text(f"JEV_API_KEY={SECRET}\nOTHER=1\n", encoding="utf-8")
    assert resolve_key("JEV_API_KEY", dotenv_path=str(dotenv)).source == "dotenv"
    assert (
        resolve_key("JEV_API_KEY", dotenv_path=str(dotenv), use_dotenv=False).state
        is KeyState.MISSING
    )
    assert resolve_key("GEMINI_API_KEY", dotenv_path=str(dotenv)).state is KeyState.MISSING


def test_platform_settings_preferred(monkeypatch: pytest.MonkeyPatch) -> None:
    from pydantic import SecretStr

    monkeypatch.setattr(ai_settings, "_platform_key", lambda name: SecretStr(SECRET))
    key = resolve_key("JEV_API_KEY")
    assert key.source == "platform"
    assert key.usable


def test_startup_report_has_states_not_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JEV_API_KEY", SECRET)
    report = startup_report(AISettings())
    assert report["jev_key"] == "configured"
    assert report["gemini_key"] == "missing"
    assert SECRET not in repr(report)
