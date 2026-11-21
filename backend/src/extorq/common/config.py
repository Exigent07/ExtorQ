"""Runtime configuration (pydantic-settings, prefix ``EXTORQ_``).

Rules:

* Non-secret settings come from ``EXTORQ_*`` environment variables (defaults are
  suitable for running on the developer Mac from the repository root).
* Every secret field (typed :class:`pydantic.SecretStr`) also accepts
  ``<ENV_NAME>_FILE`` pointing to a file whose stripped content is the value, so
  compose secrets (``/run/secrets/...``) never have to be placed in environment
  variables. Setting both ``X`` and ``X_FILE`` is an error.
* ``.env`` files are never read by this module (compose passes AI keys as file
  secrets; see PLAN §4.5).
* Startup checks report the *names* of missing settings, never values.

Other components can subclass :class:`ExtorQBaseSettings` with their own fields
(and prefix) and inherit the ``_FILE`` behaviour.
"""

from __future__ import annotations

import os
import socket
import typing
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import AliasChoices, Field, SecretStr
from pydantic.fields import FieldInfo
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

ENV_PREFIX = "EXTORQ_"

#: ClickHouse service roles (PLAN §5) mapped to their ClickHouse user names (PLAN §4.4).
CLICKHOUSE_USERS: dict[str, str] = {
    "admin": "extorq_admin",
    "ingest": "extorq_ingest",
    "detect": "extorq_detect",
    "rules_ro": "extorq_rules_ro",
    "ai": "extorq_ai",
    "api_ro": "extorq_api_ro",
    "api_writer": "extorq_api_writer",
    "grafana": "extorq_grafana",
}


class ConfigError(ValueError):
    """Invalid configuration. Messages contain setting names only, never values."""


def _is_secret_annotation(annotation: Any) -> bool:
    if annotation is SecretStr:
        return True
    return any(_is_secret_annotation(arg) for arg in typing.get_args(annotation))


def env_names_for(field_name: str, field: FieldInfo, prefix: str) -> list[str]:
    """Environment variable names pydantic-settings consults for ``field_name``."""
    alias = field.validation_alias
    if isinstance(alias, AliasChoices):
        return [choice for choice in alias.choices if isinstance(choice, str)]
    if isinstance(alias, str):
        return [alias]
    return [f"{prefix}{field_name}".upper()]


class SecretFileEnvSource(PydanticBaseSettingsSource):
    """Reads ``<ENV_NAME>_FILE`` for every ``SecretStr`` field of the settings class."""

    def __init__(self, settings_cls: type[BaseSettings]) -> None:
        super().__init__(settings_cls)
        self._values = self._load()

    def _load(self) -> dict[str, str]:
        prefix = str(self.settings_cls.model_config.get("env_prefix", ""))
        environ = {key.upper(): value for key, value in os.environ.items()}
        values: dict[str, str] = {}
        for name, field in self.settings_cls.model_fields.items():
            if not _is_secret_annotation(field.annotation):
                continue
            for env_name in env_names_for(name, field, prefix):
                file_var = f"{env_name}_FILE".upper()
                path = environ.get(file_var)
                if not path:
                    continue
                if environ.get(env_name.upper()):
                    raise ConfigError(f"both {env_name.upper()} and {file_var} are set; use one")
                try:
                    content = Path(path).read_text(encoding="utf-8").strip()
                except OSError as exc:
                    raise ConfigError(
                        f"{file_var} points to an unreadable file ({type(exc).__name__})"
                    ) from None
                if not content:
                    raise ConfigError(f"{file_var} points to an empty file")
                # pydantic-settings matches source keys against a field's validation
                # alias exactly; unaliased fields are keyed by their name.
                values[env_name if field.validation_alias is not None else name] = content
                break
        return values

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        return self._values.get(field_name), field_name, False

    def __call__(self) -> dict[str, Any]:
        return dict(self._values)


class ExtorQBaseSettings(BaseSettings):
    """Base class: ``EXTORQ_`` prefix, no .env reading, ``_FILE`` support for secrets."""

    model_config = SettingsConfigDict(env_prefix=ENV_PREFIX, extra="ignore", case_sensitive=False)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Priority: explicit init kwargs > *_FILE secrets > environment. No dotenv.
        return (init_settings, SecretFileEnvSource(settings_cls), env_settings)


class Settings(ExtorQBaseSettings):
    """Platform settings shared by the gateway, writer, migrations and collectors."""

    environment: str = "lab"
    log_level: str = "INFO"
    #: Instance name reported in PipelineHealth (defaults to the container hostname).
    instance_name: str = Field(default_factory=socket.gethostname)
    #: Base directory for relative paths (defaults to the current working directory).
    home: Path | None = None

    # ── ClickHouse ────────────────────────────────────────────────────
    clickhouse_host: str = "127.0.0.1"
    #: 18123 is the loopback-only debug proxy (compose profile ``debug``); services use 8123.
    clickhouse_port: int = 18123
    clickhouse_database: str = "extorq"
    clickhouse_secure: bool = False
    clickhouse_password_dir: Path = Path("var/secrets/clickhouse")
    clickhouse_connect_timeout: float = 5.0
    clickhouse_send_receive_timeout: float = 60.0
    migrations_dir: Path = Path("infra/clickhouse/migrations")

    # ── Ingest gateway ────────────────────────────────────────────────
    gateway_bind_host: str = "127.0.0.1"
    gateway_port: int = 8443
    gateway_url: str = "https://127.0.0.1:8443"
    gateway_max_concurrency: int = 64
    tls_cert_file: Path = Path("var/tls/gateway.crt")
    tls_key_file: Path = Path("var/tls/gateway.key")
    tls_ca_file: Path = Path("var/tls/ca.crt")
    producers_file: Path = Path("var/secrets/producers.json")
    event_max_future_seconds: int = 86400
    event_max_age_days: int = 400
    #: Maximum authenticated-request audit rows per minute for 401s (anti-flood).
    unauthenticated_audit_per_minute: int = 60

    # ── Spool ─────────────────────────────────────────────────────────
    spool_path: Path = Path("var/spool/spool.db")
    #: Gateway answers 503 + Retry-After when this many records are waiting.
    spool_max_records: int = 200_000
    #: Gateway answers 503 when the spool filesystem has less free space than this.
    spool_min_free_bytes: int = 256 * 1024 * 1024
    #: How long record identities are remembered for gateway-side deduplication.
    dedup_retention_hours: int = 168
    spool_busy_timeout_ms: int = 10_000

    # ── Writer ────────────────────────────────────────────────────────
    writer_batch_size: int = 2000
    writer_max_attempts: int = 8
    writer_poll_interval_seconds: float = 0.5
    writer_backoff_initial_seconds: float = 0.5
    writer_backoff_max_seconds: float = 30.0
    writer_heartbeat_file: Path = Path("var/run/writer.heartbeat")
    health_interval_seconds: float = 30.0

    # ── Collectors ────────────────────────────────────────────────────
    collectors_config_dir: Path = Path("config/collectors")
    collectors_state_dir: Path = Path("var/collectors")
    tokens_dir: Path = Path("var/secrets/tokens")

    # ── Secrets (each also accepts <ENV_NAME>_FILE) ───────────────────
    api_service_token: SecretStr | None = None
    frontend_session_secret: SecretStr | None = None
    analyst_password: SecretStr | None = None
    viewer_password: SecretStr | None = None
    grafana_admin_password: SecretStr | None = None
    jev_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("EXTORQ_JEV_API_KEY", "JEV_API_KEY")
    )
    gemini_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("EXTORQ_GEMINI_API_KEY", "GEMINI_API_KEY")
    )

    def resolve(self, path: Path) -> Path:
        """Resolve a configured path against ``home`` (or the working directory)."""
        if path.is_absolute():
            return path
        base = self.home if self.home is not None else Path.cwd()
        return (base / path).resolve()

    def clickhouse_password_file(self, role: str) -> Path:
        try:
            user = CLICKHOUSE_USERS[role]
        except KeyError:
            raise ConfigError(f"unknown ClickHouse role {role!r}") from None
        return self.resolve(self.clickhouse_password_dir) / f"{user}_password"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings (cached; tests call ``get_settings.cache_clear()``)."""
    return Settings()


def env_name(settings_cls: type[BaseSettings], field_name: str) -> str:
    field = settings_cls.model_fields[field_name]
    prefix = str(settings_cls.model_config.get("env_prefix", ""))
    return env_names_for(field_name, field, prefix)[0].upper()


def missing_settings(settings: BaseSettings, required: Iterable[str]) -> list[str]:
    """Return the environment variable NAMES of required settings that are unset/empty."""
    missing: list[str] = []
    for name in required:
        value = getattr(settings, name, None)
        if isinstance(value, SecretStr):
            value = value.get_secret_value()
        if value is None or (isinstance(value, str) and not value.strip()):
            missing.append(env_name(type(settings), name))
    return missing


def missing_files(settings: Settings, path_fields: Iterable[str]) -> list[str]:
    """Return the NAMES of path settings whose file does not exist or is unreadable."""
    missing: list[str] = []
    for name in path_fields:
        path = getattr(settings, name)
        resolved = settings.resolve(Path(path))
        if not (resolved.is_file() and os.access(resolved, os.R_OK)):
            missing.append(env_name(Settings, name))
    return missing


def check_startup(
    component: str,
    settings: Settings,
    *,
    required: Iterable[str] = (),
    required_files: Iterable[str] = (),
    clickhouse_roles: Iterable[str] = (),
) -> list[str]:
    """Log and return the names of missing configuration for ``component``.

    Values are never logged. Callers decide whether a non-empty result is fatal.
    """
    from extorq.common.logging import get_logger

    problems = missing_settings(settings, required) + missing_files(settings, required_files)
    for role in clickhouse_roles:
        path = settings.clickhouse_password_file(role)
        if not (path.is_file() and os.access(path, os.R_OK)):
            problems.append(f"clickhouse password file for role {role!r} ({path.name})")
    log = get_logger("extorq.config")
    if problems:
        log.error("startup_config_missing", component=component, missing=problems)
    else:
        log.info("startup_config_ok", component=component)
    return problems


def read_secret_file(path: Path) -> str:
    """Read a secret file (stripped). Raises ConfigError naming the file, never the value."""
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigError(f"secret file {path.name} unreadable ({type(exc).__name__})") from None
    if not value:
        raise ConfigError(f"secret file {path.name} is empty")
    return value
