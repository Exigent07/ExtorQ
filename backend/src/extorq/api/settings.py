"""Analyst API settings.

Environment variables (prefix ``EXTORQ_API_``):

* ``EXTORQ_API_SERVICE_TOKEN_FILE``: path of the file holding the API service token
  (preferred; compose mounts it as a secret). Default when unset:
  ``var/secrets/api_service_token`` relative to the working directory.
* ``EXTORQ_API_SERVICE_TOKEN``: the token itself (discouraged; use the file).
* ``EXTORQ_API_ENABLE_DOCS``: serve ``/api/v1/openapi.json`` and ``/api/v1/docs`` (default off).
* ``EXTORQ_API_MAX_BODY_BYTES``, ``EXTORQ_API_PIPELINE_STALE_SECONDS``,
  ``EXTORQ_API_SUMMARY_REQUESTS_PER_MINUTE``, ``EXTORQ_API_SERVICE_STALE_SECONDS``,
  ``EXTORQ_API_ASSET_STALE_SECONDS``, ``EXTORQ_API_ASSET_RETIRE_SECONDS``,
  ``EXTORQ_API_CACHE_TTL_SECONDS``, ``EXTORQ_API_CACHE_MAX_ENTRIES``: operational bounds
  (see field docs).

ClickHouse credentials are not read here: :func:`extorq.storage.clickhouse.get_client`
(owned by the platform layer) resolves the ``api_ro`` / ``api_writer`` identities and
their password files.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_TOKEN_FILE = Path("var/secrets/api_service_token")
#: Minimum accepted service-token length; shorter tokens are treated as misconfiguration.
MIN_TOKEN_LENGTH = 32
#: The four monitored asset classes. A class with no asset is reported as "missing" in the
#: overview (a configuration expectation, not telemetry).
EXPECTED_ASSET_TYPES: tuple[str, ...] = (
    "macos_host",
    "linux_host",
    "kubernetes_cluster",
    "github_repository",
)


class ApiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="EXTORQ_API_", extra="ignore", frozen=True)

    service_token: SecretStr | None = None
    service_token_file: Path | None = None
    enable_docs: bool = False
    #: Requests with a larger body are rejected with 413 before parsing.
    max_body_bytes: int = Field(default=64 * 1024, ge=1024, le=1024 * 1024)
    #: A pipeline component whose latest health report is older than this is "stale".
    pipeline_stale_seconds: int = Field(default=300, ge=30, le=86400)
    #: Per-user bound on POST /alerts/{id}/summary (protects the paid AI budget from UI loops).
    summary_requests_per_minute: int = Field(default=6, ge=1, le=120)
    #: Window used for AI provider health statistics.
    ai_health_window_hours: int = Field(default=24, ge=1, le=24 * 30)
    #: A service/instance record not refreshed by discovery for longer than this is
    #: reported as stale, and a service reported ``monitored`` is then shown as
    #: ``degraded`` (coverage cannot be confirmed). ``EXTORQ_API_SERVICE_STALE_SECONDS``.
    service_stale_seconds: int = Field(default=3600, ge=60, le=7 * 86400)
    #: Asset lifecycle ``stale``: not observed (asset record refresh or event) for longer than
    #: this, or 3 x the shortest interval of its reporting collectors when that is longer.
    #: ``EXTORQ_API_ASSET_STALE_SECONDS``.
    asset_stale_seconds: int = Field(default=3600, ge=60, le=7 * 86400)
    #: Asset lifecycle ``retired``: no collector covering the asset reported within this
    #: window (or 3 x its interval when longer) and the asset was not observed within it.
    #: ``EXTORQ_API_ASSET_RETIRE_SECONDS`` (default 24 h).
    asset_retire_seconds: int = Field(default=86400, ge=3600, le=90 * 86400)
    #: Seconds an aggregate response (overview, health, assets, services, rules) is served
    #: from the in-process cache; 0 disables caching. ``EXTORQ_API_CACHE_TTL_SECONDS``.
    cache_ttl_seconds: float = Field(default=15.0, ge=0.0, le=60.0)
    #: Upper bound of cached responses (oldest evicted first). ``EXTORQ_API_CACHE_MAX_ENTRIES``.
    cache_max_entries: int = Field(default=128, ge=1, le=4096)


def resolve_token_source(settings: ApiSettings) -> tuple[str, Path | None]:
    """Describe where the service token comes from (names only, never the value)."""
    if settings.service_token_file is not None:
        return "EXTORQ_API_SERVICE_TOKEN_FILE", settings.service_token_file
    if settings.service_token is not None:
        return "EXTORQ_API_SERVICE_TOKEN", None
    return "default token file", DEFAULT_TOKEN_FILE


def read_service_token(settings: ApiSettings) -> str | None:
    """Return the configured service token, or ``None`` when absent/unreadable/too short.

    The value is never logged or included in exceptions.
    """
    _, path = resolve_token_source(settings)
    if path is None:
        token = settings.service_token.get_secret_value() if settings.service_token else ""
    else:
        try:
            # Bounded read: a token file is tiny; refuse to slurp something unexpected.
            with open(os.fspath(path), "rb") as handle:
                data = handle.read(4097)
        except OSError:
            return None
        if len(data) > 4096:
            return None
        try:
            token = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
    token = token.strip()
    if len(token) < MIN_TOKEN_LENGTH:
        return None
    return token
