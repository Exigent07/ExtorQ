"""Late-bound access to interfaces owned by other components.

ExtorQ components are built in parallel. The AI package depends on documented
interfaces (docs/team/PLAN.md §5) owned by other agents:

* ``extorq.common.logging.get_logger`` and ``extorq.common.redaction.redact_text`` (A)
* ``extorq.storage.clickhouse.get_client`` (A)
* ``extorq.correlation.store.load_latest_context`` / ``save_context`` and
  ``extorq.correlation.builder.ContextBuilder`` (C2)

They are imported lazily. When one is unavailable the AI package uses a small,
documented local fallback (or reports the dependency as missing) instead of
failing at import time.
"""

from __future__ import annotations

import importlib
import threading
import time
from typing import Any

_NEGATIVE_TTL_SECONDS = 60.0
_lock = threading.Lock()
_negative_cache: dict[tuple[str, str], float] = {}


def optional_attr(module: str, name: str) -> Any | None:
    """Return ``module.name`` if importable, else ``None`` (negative results cached 60 s)."""
    key = (module, name)
    now = time.monotonic()
    with _lock:
        failed_at = _negative_cache.get(key)
        if failed_at is not None and now - failed_at < _NEGATIVE_TTL_SECONDS:
            return None
    try:
        mod = importlib.import_module(module)
        value = getattr(mod, name, None)
    except Exception:  # noqa: BLE001 - a missing or half-built sibling module is not fatal here
        value = None
    if value is None:
        with _lock:
            _negative_cache[key] = now
    return value


def reset_optional_cache() -> None:
    """Forget cached import failures (tests, or after a dependency was deployed)."""
    with _lock:
        _negative_cache.clear()


def get_logger(name: str) -> Any:
    """Structured logger from ``extorq.common.logging`` with a structlog fallback."""
    factory = optional_attr("extorq.common.logging", "get_logger")
    if factory is not None:
        return factory(name)
    import structlog

    return structlog.get_logger(name)
