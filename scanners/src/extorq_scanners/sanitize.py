"""Sanitisation of scanner output before it becomes a stored record.

Everything a scanner prints about the scanned content is untrusted: file paths,
messages and code-derived text can be attacker-controlled (the lab repository
is deliberately weak) and may contain credentials. Every free-text value that
is stored therefore goes through :func:`clean`:

1. :func:`extorq.common.redaction.sanitize_untrusted` strips ANSI/control/
   bidi characters and bounds the length;
2. :func:`extorq.common.redaction.redact_text` removes credential-shaped values.

Identifiers (rule ids, commit SHAs, CVE ids) are never passed through
``redact_text`` as free text: they are validated against strict patterns
instead, because generic ``key: value`` redaction would mangle values such as
``generic-api-key:12``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from extorq.common.redaction import redact_text, sanitize_untrusted

SHORT = 256
MEDIUM = 2048
ATTR_STR = 2048
ATTR_LIST_ITEMS = 64
ATTR_LIST_ITEM = 512

_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")
_HEX_SHA = re.compile(r"^[0-9a-f]{7,64}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class Verbatim(str):
    """A string composed ONLY of components that were each redacted or strictly validated.

    Example: a gitleaks fingerprint ``<commit hex>:<redacted path>:<rule id>:<line>``.
    Running generic ``key: value`` redaction over the composed string produces false
    positives (``extorq-test-secret:9`` looks like ``secret: 9``) that destroy the
    identifier, so :func:`normalize.common.bounded_attributes` stores Verbatim values
    after control-character sanitisation and length bounding only. Never wrap raw
    tool output in Verbatim.
    """

    __slots__ = ()


class RedactionCounter:
    """Counts credential redactions applied while normalising one scan."""

    def __init__(self) -> None:
        self.count = 0

    def add(self, n: int) -> None:
        self.count += n


def clean(value: object, limit: int, counter: RedactionCounter | None = None) -> str | None:
    """Sanitise + redact + bound a free-text value. ``None``/empty stays ``None``."""
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    # Redact before truncating so a secret cut in half cannot slip through.
    text = sanitize_untrusted(text, max(limit * 4, limit))
    text, n = redact_text(text)
    if counter is not None:
        counter.add(n)
    text = sanitize_untrusted(text, limit).strip()
    return text or None


def clean_required(
    value: object, limit: int, fallback: str, counter: RedactionCounter | None
) -> str:
    return clean(value, limit, counter) or fallback


def clean_list(
    values: Iterable[object] | None,
    *,
    max_items: int,
    item_limit: int,
    counter: RedactionCounter | None = None,
) -> list[str]:
    """Sanitised, de-duplicated (order kept) list of at most ``max_items`` strings."""
    out: list[str] = []
    seen: set[str] = set()
    for value in values or ():
        text = clean(value, item_limit, counter)
        if text is None or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= max_items:
            break
    return out


def safe_identifier(value: object, limit: int = SHORT) -> str | None:
    """Return ``value`` if it is a plain identifier (rule/check id), else ``None``."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > limit or not _SLUG.match(value):
        return None
    return value


def safe_commit(value: object) -> str | None:
    if isinstance(value, str) and _HEX_SHA.match(value.strip().lower()):
        return value.strip().lower()
    return None


def is_cve(value: object) -> bool:
    return isinstance(value, str) and bool(_CVE.match(value))


def bounded_int(value: object, *, low: int = 0, high: int = 10_000_000) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < low or value > high:
        return None
    return value


def relative_path(path: object, mount_point: str) -> str | None:
    """Strip the container mount point so stored paths are repository-relative."""
    if not isinstance(path, str) or not path:
        return None
    text = path
    prefix = mount_point.rstrip("/") + "/"
    if text.startswith(prefix):
        text = text[len(prefix) :]
    elif text == mount_point.rstrip("/"):
        text = "."
    return text.lstrip("/") or "."


def obj(container: Any, key: str) -> dict[str, Any]:
    """``container[key]`` when both are JSON objects, else ``{}`` (typed narrowing helper)."""
    value = container.get(key) if isinstance(container, dict) else None
    return value if isinstance(value, dict) else {}


def lst(container: Any, key: str) -> list[Any]:
    """``container[key]`` when it is a JSON array, else ``[]`` (typed narrowing helper)."""
    value = container.get(key) if isinstance(container, dict) else None
    return value if isinstance(value, list) else []
