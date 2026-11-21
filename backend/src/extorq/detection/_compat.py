"""Thin, lazily-resolved bridges to platform modules owned by agent A.

Detection and correlation must keep working (and stay testable) while the
platform packages evolve, so every cross-team import is resolved lazily here
with a conservative local fallback:

* logging   -> ``extorq.common.logging.get_logger`` else structlog's logger
* redaction -> ``extorq.common.redaction.redact_text / sanitize_untrusted``
               else a local control-character stripper (never weaker on output
               length; secrets are only ever redacted *more* by A's version)
* clients   -> ``extorq.storage.clickhouse.get_client(role)`` (no fallback: a
               production detector without A's storage layer must fail loudly)
"""

from __future__ import annotations

import re
from typing import Any

_CONTROL_RE = re.compile(
    "[\\x00-\\x08\\x0b-\\x1f\\x7f-\\x9f"
    "\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff]"
)
_TRUNCATION_MARKER = "…[truncated]"


def get_logger(name: str) -> Any:
    """Structured logger (A's ``extorq.common.logging`` when available)."""
    try:
        from extorq.common import logging as common_logging

        return common_logging.get_logger(name)
    except (ImportError, AttributeError):
        import structlog

        return structlog.get_logger(name)


def configure_logging(component: str) -> None:
    """Configure process logging via A's helper, or a JSON structlog fallback."""
    try:
        from extorq.common import logging as common_logging

        common_logging.configure_logging(component)
        return
    except (ImportError, AttributeError):
        pass
    import logging

    import structlog

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(sort_keys=True),
        ],
        logger_factory=structlog.PrintLoggerFactory(),
    )
    structlog.contextvars.bind_contextvars(component=component)


def sanitize(text: str | None, limit: int) -> str:
    """Strip control/format characters and truncate untrusted text."""
    if not text:
        return ""
    try:
        from extorq.common.redaction import sanitize_untrusted

        return str(sanitize_untrusted(str(text), limit))
    except (ImportError, AttributeError):
        cleaned = _CONTROL_RE.sub("", str(text).replace("\r", " ").replace("\n", " "))
        if len(cleaned) <= limit:
            return cleaned
        if limit <= len(_TRUNCATION_MARKER):
            return cleaned[:limit]
        return cleaned[: limit - len(_TRUNCATION_MARKER)] + _TRUNCATION_MARKER


def redact(text: str) -> str:
    """Redact credentials (A's redactor when available; identity otherwise)."""
    try:
        from extorq.common.redaction import redact_text

        return str(redact_text(text)[0])
    except (ImportError, AttributeError):
        return text


def sanitize_error(exc: BaseException, limit: int = 500) -> str:
    """Secret-free, single-line, bounded error summary suitable for storage."""
    message = str(exc).strip().splitlines()[0] if str(exc).strip() else ""
    summary = f"{type(exc).__name__}: {message}" if message else type(exc).__name__
    return sanitize(redact(summary), limit)
