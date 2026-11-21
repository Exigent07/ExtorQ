"""Deterministic alert summaries (no AI).

Templates use ``{name}`` placeholders only. Rendering is a regex substitution
over a flat dictionary: there is no attribute access, indexing or format-spec
evaluation (``str.format`` is deliberately not used), so a template can never
reach object internals. Every substituted value is treated as untrusted
(usernames, routes and object names are attacker-controlled): control
characters are stripped and each value is truncated before insertion.

Available names: the built-ins below, the alert's ``entities`` and the scalar or
list values of its ``features``. Unknown values render as ``unknown``.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from extorq.contracts.identity import iso_utc
from extorq.detection._compat import sanitize

MAX_TEMPLATE_CHARS = 1024
MAX_VALUE_CHARS = 128
MAX_SUMMARY_CHARS = 2048
MAX_LIST_ITEMS = 5
BUILTIN_NAMES = frozenset(
    {
        "rule_id",
        "rule_title",
        "asset_id",
        "asset_type",
        "event_count",
        "first_seen",
        "last_seen",
        "confidence",
        "severity",
        "group_key",
    }
)
_PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]{0,63})\}")


class TemplateError(ValueError):
    pass


def validate_template(template: str) -> list[str]:
    """Validate a summary template; return the placeholder names it uses."""
    if not template.strip():
        raise TemplateError("template is empty")
    if len(template) > MAX_TEMPLATE_CHARS:
        raise TemplateError(f"template exceeds {MAX_TEMPLATE_CHARS} characters")
    stripped = _PLACEHOLDER_RE.sub("", template)
    if "{" in stripped or "}" in stripped:
        raise TemplateError("braces may only be used for {lower_snake_case} placeholders")
    return _PLACEHOLDER_RE.findall(template)


def _render_value(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, datetime):
        return iso_utc(value)
    if isinstance(value, list | tuple):
        items = [str(item) for item in value if item is not None]
        if not items:
            return "none"
        shown = ", ".join(items[:MAX_LIST_ITEMS])
        if len(items) > MAX_LIST_ITEMS:
            shown += f" (+{len(items) - MAX_LIST_ITEMS} more)"
        return shown
    return str(value)


def render_summary(template: str, values: dict[str, Any]) -> str:
    """Render ``template`` with sanitised, truncated values."""

    def substitute(match: re.Match[str]) -> str:
        return sanitize(_render_value(values.get(match.group(1))), MAX_VALUE_CHARS) or "unknown"

    return sanitize(_PLACEHOLDER_RE.sub(substitute, template), MAX_SUMMARY_CHARS)
