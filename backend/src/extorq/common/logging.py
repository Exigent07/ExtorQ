"""Structured JSON logging with mandatory secret redaction.

``configure_logging(component)`` routes both structlog and the standard library
``logging`` module (uvicorn, httpx, clickhouse-connect) through one JSON
renderer on stdout. Every record carries ``component`` and passes through
:func:`redact_event_dict`, which

* replaces values of sensitive keys (token, password, secret, authorization,
  api_key, cookie, private_key, ...) with ``[REDACTED]``;
* replaces string values that look like credentials (long mixed-case
  base64/url-safe strings that are not plain hex identifiers);
* runs :func:`extorq.common.redaction.redact_text` over all remaining strings,
  including formatted exception tracebacks.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any

import structlog

from extorq.common.redaction import redact_text

REDACTED = "[REDACTED]"

_SENSITIVE_EXACT = frozenset(
    {
        "token",
        "password",
        "passwd",
        "pwd",
        "secret",
        "authorization",
        "proxy_authorization",
        "auth",
        "api_key",
        "apikey",
        "x_api_key",
        "cookie",
        "set_cookie",
        "private_key",
        "access_token",
        "refresh_token",
        "id_token",
        "client_secret",
        "credentials",
        "bearer",
        "session_secret",
    }
)
_SENSITIVE_SUFFIXES = (
    "_token",
    "_password",
    "_passwd",
    "_secret",
    "_api_key",
    "_apikey",
    "_private_key",
    "_credentials",
    "_authorization",
    "_cookie",
)
_TOKENISH = re.compile(r"^[A-Za-z0-9_\-+/=.]{32,}$")
_HEXISH = re.compile(r"^[0-9a-fA-F-]+$")
_MAX_DEPTH = 6


def is_sensitive_key(key: object) -> bool:
    if not isinstance(key, str):
        return False
    normalized = key.strip().lower().replace("-", "_")
    if normalized in _SENSITIVE_EXACT:
        return True
    return normalized.endswith(_SENSITIVE_SUFFIXES)


def looks_like_token(value: str) -> bool:
    """Heuristic for credential-like strings (not hex ids, not words, not paths)."""
    if len(value) < 32 or not _TOKENISH.match(value) or _HEXISH.match(value):
        return False
    has_upper = any(c.isupper() for c in value)
    has_lower = any(c.islower() for c in value)
    has_digit = any(c.isdigit() for c in value)
    return has_upper and has_lower and has_digit


def _redact_value(value: Any, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        return "[TRUNCATED-DEPTH]"
    if isinstance(value, str):
        if looks_like_token(value):
            return REDACTED
        return redact_text(value)[0]
    if isinstance(value, Mapping):
        return {
            k: (REDACTED if is_sensitive_key(k) else _redact_value(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [_redact_value(v, depth + 1) for v in value]
    return value


def redact_event_dict(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """structlog processor: redact sensitive keys and secret-looking values."""
    for key in list(event_dict.keys()):
        if key in ("timestamp", "level", "logger", "component"):
            continue
        value = event_dict[key]
        if is_sensitive_key(key):
            event_dict[key] = REDACTED
        elif key in ("event", "exception", "stack"):
            event_dict[key] = redact_text(value)[0] if isinstance(value, str) else value
        else:
            event_dict[key] = _redact_value(value)
    return event_dict


def _add_component(component: str) -> structlog.types.Processor:
    def processor(
        _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        event_dict.setdefault("component", component)
        return event_dict

    return processor


_NOISY_LOGGERS = {
    "httpx": logging.WARNING,
    "httpcore": logging.WARNING,
    "urllib3": logging.WARNING,
    "clickhouse_connect": logging.WARNING,
    "uvicorn.access": logging.WARNING,
    "asyncio": logging.WARNING,
}


def configure_logging(component: str, level: str | int | None = None) -> None:
    """Configure process-wide JSON logging for ``component`` (idempotent)."""
    if level is None:
        try:
            from extorq.common.config import get_settings

            level = get_settings().log_level
        except Exception:  # noqa: BLE001 - logging must work even with broken config
            level = "INFO"
    numeric_level = logging.getLevelName(level.upper()) if isinstance(level, str) else level
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    shared: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _add_component(component),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        redact_event_dict,
    ]
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *shared,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(ensure_ascii=False, default=str),
        ],
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(numeric_level)
    for name, logger_level in _NOISY_LOGGERS.items():
        logging.getLogger(name).setLevel(max(logger_level, numeric_level))
    # uvicorn installs its own handlers; make it propagate to ours instead.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv_logger = logging.getLogger(name)
        uv_logger.handlers = []
        uv_logger.propagate = True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.stdlib.get_logger(name)  # type: ignore[no-any-return]
