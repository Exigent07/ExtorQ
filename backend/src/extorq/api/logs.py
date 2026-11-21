"""Logging shim: uses the platform logger (``extorq.common.logging``) when present.

Never pass tokens, passwords, Authorization headers, API keys or prompt bodies to a logger.
"""

from __future__ import annotations

from typing import Any


def get_logger(name: str) -> Any:
    try:
        from extorq.common.logging import get_logger as platform_get_logger
    except ImportError:
        import structlog

        return structlog.get_logger(name)
    return platform_get_logger(name)


def configure(component: str = "api") -> None:
    """Configure structured logging through the platform helper when it exists."""
    try:
        from extorq.common.logging import configure_logging
    except ImportError:
        return
    configure_logging(component)
