"""Secret redaction and sanitisation of untrusted text.

Two independent controls:

* :func:`redact_text` removes credentials that commonly leak into logs and
  telemetry (GitHub/AWS/Slack/Google tokens, JWTs, bearer tokens, PEM private
  keys, ``password=...`` style pairs, URL credentials, ExtorQ's own tokens).
  It returns the redacted text plus the number of replacements so producers can
  record ``provenance.redaction_count``.
* :func:`sanitize_untrusted` makes attacker-controlled text safe to store and
  display: it strips ANSI escape sequences, C0/C1 control characters and
  bidirectional/zero-width format characters, NFC-normalises and truncates with
  an explicit marker.

Both are pure functions with no I/O. Patterns are deliberately specific so
ordinary identifiers (SHA-256 digests, event ids, UUIDs) are not destroyed.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable

TRUNCATION_MARKER = "…[truncated]"

# Each rule: (name, compiled pattern, replacement builder). Order matters: the most
# specific patterns run first; later patterns skip values that are already redacted.
_Rule = tuple[str, re.Pattern[str], Callable[[re.Match[str]], str]]


def _whole(label: str) -> Callable[[re.Match[str]], str]:
    marker = f"[REDACTED:{label}]"
    return lambda _match: marker


def _keep_prefix(label: str) -> Callable[[re.Match[str]], str]:
    """Keep group 1 (key/separator/scheme), replace the secret value."""
    marker = f"[REDACTED:{label}]"
    return lambda match: f"{match.group(1)}{marker}"


_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
    r"(?:.*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|.*\Z)",
    re.DOTALL,
)

_RULES: tuple[_Rule, ...] = (
    ("private_key", _PEM_PRIVATE_KEY, _whole("private_key")),
    (
        "github_token",
        re.compile(r"(?<![A-Za-z0-9_])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}(?![A-Za-z0-9_])"),
        _whole("github_token"),
    ),
    (
        "github_token",
        re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{22,255}(?![A-Za-z0-9_])"),
        _whole("github_token"),
    ),
    (
        "extorq_token",
        re.compile(r"(?<![A-Za-z0-9_])xtq_[a-z]_[A-Za-z0-9_-]{20,}"),
        _whole("extorq_token"),
    ),
    (
        "aws_access_key",
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        _whole("aws_access_key"),
    ),
    (
        "aws_secret_key",
        re.compile(
            r"(?i)((?:aws_?secret_?access_?key|aws_?secret_?key|secret_?access_?key)"
            r"[\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
        ),
        _keep_prefix("aws_secret_key"),
    ),
    (
        "slack_token",
        re.compile(r"(?<![A-Za-z0-9])xox[a-z]-[A-Za-z0-9-]{10,250}"),
        _whole("slack_token"),
    ),
    (
        "google_api_key",
        re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
        _whole("google_api_key"),
    ),
    (
        "gitlab_token",
        re.compile(r"(?<![A-Za-z0-9_])glpat-[A-Za-z0-9_-]{20,}"),
        _whole("gitlab_token"),
    ),
    (
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"
        ),
        _whole("jwt"),
    ),
    (
        "url_credentials",
        re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]{1,20}://[^/\s:@\"']{1,256}:)(?!\[REDACTED)[^@\s/\"']{1,256}(?=@)"),
        _keep_prefix("password"),
    ),
    (
        "authorization_basic",
        re.compile(r"(?i)(authorization[\"']?\s*[:=]\s*[\"']?basic\s+)[A-Za-z0-9+/]{8,}={0,2}"),
        _keep_prefix("basic_auth"),
    ),
    (
        "bearer",
        re.compile(r"(?i)(\bbearer\s+)(?!\[REDACTED)[A-Za-z0-9._~+/-]{8,}=*"),
        _keep_prefix("bearer"),
    ),
    (
        "secret_assignment",
        re.compile(
            r"(?i)((?<![A-Za-z0-9])"
            r"(?:password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
            r"client[_-]?secret|auth[_-]?token|private[_-]?key|session[_-]?secret)"
            r"[\"']?\s*[:=]\s*)"
            r"(?!\[REDACTED)(\"[^\"]{1,1024}\"|'[^']{1,1024}'|[^\s&,;\"'<>}{)\]]{1,1024})"
        ),
        lambda match: f"{match.group(1)}{_quote_like(match.group(2))}",
    ),
)


def _quote_like(value: str) -> str:
    marker = "[REDACTED:secret]"
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return f"{value[0]}{marker}{value[0]}"
    return marker


def redact_text(text: str) -> tuple[str, int]:
    """Redact credentials in ``text``; return ``(redacted_text, replacement_count)``."""
    if not text:
        return text, 0
    total = 0
    for _name, pattern, build in _RULES:
        text, count = pattern.subn(build, text)
        total += count
    return text, total


def contains_secret(text: str) -> bool:
    return redact_text(text)[1] > 0


# ── untrusted text sanitisation ───────────────────────────────────────

# CSI (ESC [ ... final), OSC (ESC ] ... BEL | ESC \), other two-byte ESC sequences, 8-bit CSI.
_ANSI = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"
    r"|\x1b[PX^_][^\x1b]*(?:\x1b\\)?"
    r"|\x1b[@-Z\\-_]"
    r"|\x9b[0-?]*[ -/]*[@-~]"
)
_NEWLINES = re.compile(r"\r\n|\r|\n")
# C0 (except TAB/LF handled separately), DEL, C1; bidi embeddings/overrides/isolates,
# zero-width and invisible format characters, BOM.
_CONTROLS = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁠-⁤⁦-⁩﻿]"
)


def sanitize_untrusted(text: str, limit: int, *, keep_newlines: bool = False) -> str:
    """Return ``text`` safe for storage/display, at most ``limit`` characters long.

    Strips ANSI escape sequences and control/format characters, converts line
    breaks to spaces (or ``\\n`` when ``keep_newlines``), NFC-normalises and
    truncates with :data:`TRUNCATION_MARKER` when the result would exceed ``limit``.
    """
    if limit <= 0:
        return ""
    if not text:
        return ""
    cleaned = _ANSI.sub("", text)
    cleaned = _NEWLINES.sub("\n" if keep_newlines else " ", cleaned)
    cleaned = _CONTROLS.sub("", cleaned)
    cleaned = unicodedata.normalize("NFC", cleaned)
    if len(cleaned) <= limit:
        return cleaned
    if limit <= len(TRUNCATION_MARKER):
        return cleaned[:limit]
    return cleaned[: limit - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def truncate_bytes(text: str, max_bytes: int) -> str:
    """Truncate ``text`` so its UTF-8 encoding fits ``max_bytes`` (marker included)."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    marker = TRUNCATION_MARKER.encode("utf-8")
    if max_bytes < len(marker):
        return encoded[: max(0, max_bytes)].decode("utf-8", errors="ignore")
    head = encoded[: max_bytes - len(marker)].decode("utf-8", errors="ignore")
    return head + TRUNCATION_MARKER
