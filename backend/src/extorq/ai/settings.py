"""Jev feature flag, limits and API key resolution.

Non-secret settings use the ``EXTORQ_`` prefix (pydantic-settings), e.g.
``EXTORQ_JEV_ENABLED=true``. Jev is **disabled by default**: ExtorQ works completely
without AI.

The key ``JEV_API_KEY`` is resolved in this order, and is never logged, printed or
included in error messages (only the variable *name* and its state are reported):

1. the platform settings (``extorq.common.config.Settings.jev_api_key``, owned by
   agent A), which accept ``JEV_API_KEY`` / ``EXTORQ_JEV_API_KEY`` and the ``*_FILE``
   variants (compose mounts the key as ``/run/secrets/...``);
2. if the platform settings are unavailable or cannot be constructed: this module's
   own reading of ``JEV_API_KEY_FILE`` and then ``JEV_API_KEY``;
3. local development only: ``JEV_API_KEY`` loaded programmatically from a dotenv file
   (``EXTORQ_AI_DOTENV``, default ``.env`` in the working directory; set it to an empty
   value to disable this path). No other name is read from that file. Container images
   contain no ``.env`` (``.dockerignore``), so compose services always use the file
   secret; the API's configuration report calls :func:`resolve_key` with
   ``use_dotenv=False``.

The key is passed explicitly to ``TypeSafeClient(api_key=...)``; the SDK's own
``TYPESAFE_API_KEY`` variable is never consulted because ExtorQ never builds a client
without an explicit key.

Why AI settings live here and not in ``extorq.common.config``: the AI package must stay
importable and testable on its own, and the platform settings may fail to construct for
reasons unrelated to AI (e.g. another missing secret). Step 1 still prefers them.
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

#: The only provider key ExtorQ resolves. Other names are refused so this module can never
#: be used as a generic reader of secret-bearing environment variables.
JEV_KEY_NAME = "JEV_API_KEY"
KeyName = Literal["JEV_API_KEY"]
#: Upper bound on the size of a key file; anything larger is rejected unread.
MAX_SECRET_FILE_BYTES = 4096
_MODEL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{1,127}$"


class AISettings(BaseSettings):
    """Non-secret Jev configuration (environment prefix ``EXTORQ_``)."""

    model_config = SettingsConfigDict(
        env_prefix="EXTORQ_", extra="ignore", frozen=True, hide_input_in_errors=True
    )

    # ── feature flag and model ──────────────────────────────────────
    jev_enabled: bool = False
    #: Pinned model id; the id the provider reports is stored with every assessment.
    jev_model: str = Field(default="jev-1.14.0", pattern=_MODEL_ID_PATTERN)

    # ── timeouts and bounded retries ────────────────────────────────
    #: Per HTTP attempt.
    jev_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    #: Total budget for one Jev call including retries and backoff.
    jev_retry_budget_seconds: float = Field(default=25.0, gt=0, le=300)
    jev_max_retries: int = Field(default=2, ge=0, le=5)

    # ── budget ──────────────────────────────────────────────────────
    #: Provider attempts per UTC day, counted from ``ai_assessments`` (fail closed).
    jev_daily_cap: int = Field(default=300, ge=0, le=10_000)

    # ── input size cap (characters of the serialised Jev state) ─────
    jev_max_state_chars: int = Field(default=24_000, ge=2_000, le=200_000)
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
    """A resolved provider key. ``repr`` never shows the value (``SecretStr``)."""

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
    """Reads only ``JEV_API_KEY`` from a dotenv file (local development convenience)."""

    model_config = SettingsConfigDict(extra="ignore", hide_input_in_errors=True)

    jev_api_key: SecretStr | None = Field(default=None, validation_alias=JEV_KEY_NAME)


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


def _platform_key() -> SecretStr | None:
    """The key from A's platform settings; None if unset, unavailable or unconstructible."""
    get_settings = optional_attr("extorq.common.config", "get_settings")
    if get_settings is None:
        return None
    try:
        value = getattr(get_settings(), "jev_api_key", None)
    except Exception:  # noqa: BLE001 - e.g. ConfigError for an unrelated secret: fall back
        return None
    return value if isinstance(value, SecretStr) else None


def _checked(raw: str, source: Literal["platform", "file", "env", "dotenv"]) -> ProviderKey:
    if not _valid_key(raw):
        return ProviderKey(JEV_KEY_NAME, KeyState.MALFORMED, source=source)
    return ProviderKey(JEV_KEY_NAME, KeyState.CONFIGURED, SecretStr(raw), source)


def resolve_key(
    name: str = JEV_KEY_NAME,
    *,
    dotenv_path: str | None = None,
    use_dotenv: bool = True,
    use_platform: bool = True,
) -> ProviderKey:
    """Resolve ``JEV_API_KEY`` without ever exposing it (see the module docstring).

    ``name`` exists for call sites that name the key explicitly; any other name raises
    ``ValueError`` (ExtorQ has no other AI provider).
    """
    if name != JEV_KEY_NAME:
        raise ValueError(f"unknown AI provider key name {name!r}; only {JEV_KEY_NAME} exists")
    if use_platform:
        platform = _platform_key()
        if platform is not None:
            raw = platform.get_secret_value().strip()
            if raw:
                return _checked(raw, "platform")

    file_path = os.environ.get(f"{JEV_KEY_NAME}_FILE", "").strip()
    if file_path:
        from_file = _read_key_file(file_path)
        if from_file is None:
            return ProviderKey(JEV_KEY_NAME, KeyState.UNREADABLE, source="file")
        return _checked(from_file, "file")

    env_value = os.environ.get(JEV_KEY_NAME, "").strip()
    if env_value:
        return _checked(env_value, "env")

    if use_dotenv:
        path = (
            dotenv_path if dotenv_path is not None else os.environ.get("EXTORQ_AI_DOTENV", ".env")
        )
        if path and Path(path).is_file():
            try:
                loaded = _DotenvKeys(_env_file=path)
            except Exception:  # noqa: BLE001 - a broken dotenv must never surface its content
                return ProviderKey(JEV_KEY_NAME, KeyState.UNREADABLE, source="dotenv")
            if loaded.jev_api_key is not None:
                raw = loaded.jev_api_key.get_secret_value().strip()
                if raw:
                    return _checked(raw, "dotenv")
    return ProviderKey(JEV_KEY_NAME, KeyState.MISSING)


@lru_cache(maxsize=1)
def get_ai_settings() -> AISettings:
    """Process-wide AI settings (cached; call ``get_ai_settings.cache_clear()`` in tests)."""
    return AISettings()


@lru_cache(maxsize=1)
def get_provider_key(name: KeyName = "JEV_API_KEY") -> ProviderKey:
    """Process-wide cached key resolution (call ``get_provider_key.cache_clear()`` in tests)."""
    return resolve_key(name)


def startup_report(settings: AISettings | None = None) -> dict[str, str]:
    """Configuration summary safe to log: flag, model and key *state* only."""
    s = settings or get_ai_settings()
    return {
        "jev_enabled": str(s.jev_enabled).lower(),
        "jev_model": s.jev_model,
        "jev_key": get_provider_key(JEV_KEY_NAME).state.value,
        "jev_daily_cap": str(s.jev_daily_cap),
    }
