"""AI feature flags, limits and provider credentials.

Non-secret settings use the ``EXTORQ_`` prefix (pydantic-settings), e.g.
``EXTORQ_JEV_ENABLED=true``. Both providers are **disabled by default**: ExtorQ
works completely without AI.

Provider keys are resolved in this order, and are never logged, printed or
included in error messages (only the variable *name* is ever reported):

1. the platform settings (``extorq.common.config.Settings.jev_api_key`` /
   ``gemini_api_key``, owned by agent A), which accept ``JEV_API_KEY`` /
   ``EXTORQ_JEV_API_KEY`` and the ``*_FILE`` variants (compose mounts the keys as
   ``/run/secrets/...``);
2. if the platform settings are unavailable or cannot be constructed: ExtorQ-AI's
   own reading of ``<NAME>_FILE`` and then ``<NAME>``;
3. local development only: the same names loaded programmatically from a dotenv
   file (``EXTORQ_AI_DOTENV``, default ``.env`` in the working directory; set it to
   an empty value to disable this path). Only ``JEV_API_KEY`` and ``GEMINI_API_KEY``
   are read from it. Container images contain no ``.env`` (``.dockerignore``), so
   compose services always use the ``*_FILE`` secrets; the API's configuration
   report calls :func:`resolve_key` with ``use_dotenv=False``.

``JEV_API_KEY`` is passed explicitly to ``TypeSafeClient(api_key=...)``; the SDK's
own ``TYPESAFE_API_KEY`` variable is never consulted because ExtorQ never builds
a client without an explicit key.

Reconciliation note: the platform settings object (``extorq.common.config``,
owned by agent A) reads the same environment variables; these AI-specific fields
live here so the AI package stays importable and testable on its own (see
docs/team/interface-changes/E.md).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from extorq.ai._compat import optional_attr

#: Upper bound on the size of a key file; anything larger is rejected unread.
MAX_SECRET_FILE_BYTES = 4096
_MODEL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{1,127}$"


class AISettings(BaseSettings):
    """Non-secret AI configuration (environment prefix ``EXTORQ_``)."""

    model_config = SettingsConfigDict(
        env_prefix="EXTORQ_", extra="ignore", frozen=True, hide_input_in_errors=True
    )

    # ── feature flags ───────────────────────────────────────────────
    jev_enabled: bool = False
    gemini_enabled: bool = False

    # ── models (pinned) ─────────────────────────────────────────────
    jev_model: str = Field(default="jev-1.14.0", pattern=_MODEL_ID_PATTERN)
    gemini_model: str = Field(default="gemini-3.6-flash", pattern=_MODEL_ID_PATTERN)

    # ── timeouts and bounded retries ────────────────────────────────
    #: Per HTTP attempt.
    jev_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    #: Total budget for one Jev call including retries and backoff.
    jev_retry_budget_seconds: float = Field(default=25.0, gt=0, le=300)
    jev_max_retries: int = Field(default=2, ge=0, le=5)
    #: Per HTTP attempt (also sent as the server deadline). Observed summary latency with
    #: thinking level "low" was 20-35 s, so 30 s cut off a live attempt; 60 s keeps one
    #: attempt within the console's 90 s wait.
    gemini_timeout_seconds: float = Field(default=60.0, gt=0, le=300)
    #: Attempts including the first one (1 = no retry). The SDK retries timeouts too, and a
    #: retried generation doubles cost and exceeds the console wait, so the default is 1;
    #: a failed attempt is returned as rate_limited / timeout / error and can be re-requested.
    gemini_max_attempts: int = Field(default=1, ge=1, le=5)
    gemini_max_output_tokens: int = Field(default=8192, ge=1024, le=65536)
    #: "none" sends no thinking configuration at all.
    gemini_thinking_level: Literal["none", "minimal", "low", "medium", "high"] = "low"
    #: Sent as GenerateContentConfig.store; False asks the API not to log the request.
    gemini_store_requests: bool = False

    # ── budgets ─────────────────────────────────────────────────────
    jev_daily_cap: int = Field(default=300, ge=0, le=10_000)
    gemini_daily_cap: int = Field(default=50, ge=0, le=1_000)
    #: Minimum time between summary attempts for one alert. Successful summaries are reused
    #: per context hash without a call, so this mainly bounds retries after failures.
    gemini_alert_cooldown_seconds: int = Field(default=120, ge=0, le=86_400)

    # ── input size caps (characters of serialised provider input) ───
    jev_max_state_chars: int = Field(default=24_000, ge=2_000, le=200_000)
    gemini_max_prompt_chars: int = Field(default=60_000, ge=4_000, le=400_000)
    #: Raw evidence excerpts are dropped unless explicitly enabled.
    ai_include_excerpts: bool = False
    #: Let AIService ask the correlation builder for a context when none is stored.
    ai_build_missing_context: bool = True

    # ── ai-worker ───────────────────────────────────────────────────
    ai_worker_interval_seconds: int = Field(default=30, ge=5, le=3_600)
    ai_worker_batch_size: int = Field(default=10, ge=1, le=100)
    ai_worker_max_failed_attempts: int = Field(default=3, ge=1, le=10)
    ai_worker_retry_backoff_seconds: int = Field(default=600, ge=0, le=86_400)
    ai_worker_max_context_age_hours: int = Field(default=72, ge=1, le=720)
    #: Contexts examined per cycle while looking for ``ai_worker_batch_size`` usable ones:
    #: unreadable contexts are skipped and the queue is paged past them.
    ai_worker_max_scan_per_cycle: int = Field(default=50, ge=1, le=1_000)
    #: A paid result whose write failed is kept in memory and only the write is retried, with
    #: exponential backoff from the base to the max delay; new provider calls pause meanwhile.
    ai_worker_write_retry_base_seconds: int = Field(default=15, ge=1, le=3_600)
    ai_worker_write_retry_max_seconds: int = Field(default=600, ge=1, le=86_400)
    #: After this many failed writes the result is dropped (logged, counted in health) and that
    #: context is never sent to the provider again by this process.
    ai_worker_write_max_attempts: int = Field(default=12, ge=1, le=1_000)


class KeyState(StrEnum):
    CONFIGURED = "configured"
    MISSING = "missing"
    MALFORMED = "malformed"
    UNREADABLE = "unreadable"


@dataclass(frozen=True)
class ProviderKey:
    """A resolved provider key. ``repr`` never shows the value."""

    name: str
    state: KeyState
    value: SecretStr | None = None
    source: Literal["platform", "file", "env", "dotenv", "none"] = "none"

    @property
    def usable(self) -> bool:
        return self.state is KeyState.CONFIGURED and self.value is not None

    def describe(self) -> str:
        """Human-readable status naming the variable only (never the value)."""
        if self.state is KeyState.CONFIGURED:
            return f"{self.name} configured (source: {self.source})"
        if self.state is KeyState.MISSING:
            return f"{self.name} not configured"
        if self.state is KeyState.MALFORMED:
            return f"{self.name} is malformed"
        return f"{self.name}_FILE is unreadable"


class _DotenvKeys(BaseSettings):
    """Reads only the two provider key names from a dotenv file (dev convenience)."""

    model_config = SettingsConfigDict(extra="ignore", hide_input_in_errors=True)

    jev_api_key: SecretStr | None = Field(default=None, validation_alias="JEV_API_KEY")
    gemini_api_key: SecretStr | None = Field(default=None, validation_alias="GEMINI_API_KEY")


def _valid_key(raw: str) -> bool:
    return 8 <= len(raw) <= 512 and raw.isascii() and raw.isprintable() and " " not in raw


def _read_key_file(path_value: str) -> str | None:
    path = Path(path_value)
    try:
        if not path.is_file() or path.stat().st_size > MAX_SECRET_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None


_PLATFORM_FIELDS = {"JEV_API_KEY": "jev_api_key", "GEMINI_API_KEY": "gemini_api_key"}


def _platform_key(name: str) -> SecretStr | None:
    """The key from A's platform settings; None if unset, unavailable or unconstructible."""
    get_settings = optional_attr("extorq.common.config", "get_settings")
    field_name = _PLATFORM_FIELDS.get(name)
    if get_settings is None or field_name is None:
        return None
    try:
        value = getattr(get_settings(), field_name, None)
    except Exception:  # noqa: BLE001 - e.g. ConfigError for an unrelated secret: fall back
        return None
    return value if isinstance(value, SecretStr) else None


def resolve_key(
    name: str,
    *,
    dotenv_path: str | None = None,
    use_dotenv: bool = True,
    use_platform: bool = True,
) -> ProviderKey:
    """Resolve ``name`` (``JEV_API_KEY`` / ``GEMINI_API_KEY``) without ever exposing it."""
    if use_platform:
        platform = _platform_key(name)
        if platform is not None:
            raw = platform.get_secret_value().strip()
            if raw:
                if not _valid_key(raw):
                    return ProviderKey(name, KeyState.MALFORMED, source="platform")
                return ProviderKey(name, KeyState.CONFIGURED, SecretStr(raw), "platform")

    file_path = os.environ.get(f"{name}_FILE", "").strip()
    if file_path:
        from_file = _read_key_file(file_path)
        if from_file is None:
            return ProviderKey(name, KeyState.UNREADABLE, source="file")
        if not _valid_key(from_file):
            return ProviderKey(name, KeyState.MALFORMED, source="file")
        return ProviderKey(name, KeyState.CONFIGURED, SecretStr(from_file), "file")

    env_value = os.environ.get(name, "").strip()
    if env_value:
        if not _valid_key(env_value):
            return ProviderKey(name, KeyState.MALFORMED, source="env")
        return ProviderKey(name, KeyState.CONFIGURED, SecretStr(env_value), "env")

    if use_dotenv:
        path = (
            dotenv_path if dotenv_path is not None else os.environ.get("EXTORQ_AI_DOTENV", ".env")
        )
        if path and Path(path).is_file():
            try:
                loaded = _DotenvKeys(_env_file=path)
            except Exception:  # noqa: BLE001 - a broken dotenv must never surface its content
                return ProviderKey(name, KeyState.UNREADABLE, source="dotenv")
            secret = loaded.jev_api_key if name == "JEV_API_KEY" else loaded.gemini_api_key
            if secret is not None:
                raw = secret.get_secret_value().strip()
                if raw:
                    if not _valid_key(raw):
                        return ProviderKey(name, KeyState.MALFORMED, source="dotenv")
                    return ProviderKey(name, KeyState.CONFIGURED, SecretStr(raw), "dotenv")
    return ProviderKey(name, KeyState.MISSING)


@lru_cache(maxsize=1)
def get_ai_settings() -> AISettings:
    """Process-wide AI settings (cached; call ``get_ai_settings.cache_clear()`` in tests)."""
    return AISettings()


@lru_cache(maxsize=4)
def get_provider_key(name: Literal["JEV_API_KEY", "GEMINI_API_KEY"]) -> ProviderKey:
    """Process-wide cached key resolution (call ``get_provider_key.cache_clear()`` in tests)."""
    return resolve_key(name)


def startup_report(settings: AISettings | None = None) -> dict[str, str]:
    """Configuration summary safe to log: flags, models and key *states* only."""
    s = settings or get_ai_settings()
    jev = get_provider_key("JEV_API_KEY")
    gemini = get_provider_key("GEMINI_API_KEY")
    return {
        "jev_enabled": str(s.jev_enabled).lower(),
        "jev_model": s.jev_model,
        "jev_key": jev.state.value,
        "gemini_enabled": str(s.gemini_enabled).lower(),
        "gemini_model": s.gemini_model,
        "gemini_key": gemini.state.value,
    }
