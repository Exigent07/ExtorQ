"""Sanitisation of untrusted text before it reaches Jev.

Every string in Jev's state passes through :func:`clean_untrusted` (telemetry-derived
text) or :func:`clean_trusted` (ExtorQ's own rule metadata and coverage notes):

1. Unicode NFKC normalisation (folds full-width / compatibility look-alikes).
2. Control, format (bidi overrides, zero-width), private-use and surrogate characters
   are removed; line breaks and tabs become spaces (single line).
3. Secret redaction: ``extorq.common.redaction.redact_text`` (agent A) when available,
   then this module's defence-in-depth patterns (private keys, cloud/API tokens, JWTs,
   bearer/basic credentials, ``password=...`` pairs, credentials in URLs, e-mail
   addresses), then exact scrubbing of the configured Jev key.
4. Untrusted text only: stand-alone 32-hex tokens are masked as ``[hex32]`` because
   ExtorQ's own event, alert and context ids have that shape, and telemetry must not be
   able to impersonate them in the state. In all text ``<`` becomes U+2039, so tag-like
   payloads (``</data><instructions>``) cannot imitate markup structure for the model.
5. Whitespace is collapsed and the text is truncated to a per-field limit with an
   explicit ``…[truncated]`` marker.

Jev returns only typed answers (probabilities and option labels), never free text, so
no provider output is ever rendered; :func:`clean_token` bounds the few identifiers that
come back (request ids) and the caller-supplied ``requested_by``.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from extorq.ai._compat import optional_attr

TRUNCATION_MARK = "…[truncated]"
_HARD_INPUT_CAP = 32_768  # contracts bound strings far below this; defence against abuse

# Per-field limits (characters) for untrusted text in the Jev state.
LIMIT_LOG_MESSAGE = 300
LIMIT_SUMMARY = 300
LIMIT_COMMIT_MESSAGE = 200
LIMIT_HTTP_PATH = 160
LIMIT_USER_AGENT = 120
LIMIT_K8S_FIELD = 160
LIMIT_ACTOR = 80
LIMIT_SHORT = 120
LIMIT_EXCERPT = 200

_WS = re.compile(r"\s+")
_LINE_BREAKS = str.maketrans({"\n": " ", "\r": " ", "\t": " ", "\u2028": " ", "\u2029": " "})
_HEX32 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")

# Defence-in-depth secret patterns. Quantifiers are bounded to avoid pathological
# backtracking on attacker-controlled input.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.{0,8192}?"
            r"(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)",
            re.S,
        ),
        "[REDACTED:private_key]",
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws_key]"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b"), "[REDACTED:github_token]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"), "[REDACTED:github_token]"),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}\b"), "[REDACTED:gitlab_token]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "[REDACTED:google_api_key]"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,255}\b"), "[REDACTED:slack_token]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,255}\b"), "[REDACTED:api_key]"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}"),
        "[REDACTED:jwt]",
    ),
    (
        re.compile(r"(?i)\b(bearer|basic)\s+(?!\[REDACTED)[A-Za-z0-9._~+/=-]{8,4096}"),
        r"\1 [REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(authorization|proxy-authorization)\s*[:=]\s*"
            r"(?![A-Za-z]{1,20}\s+\[REDACTED|\[REDACTED)(?:[A-Za-z]{1,20}\s+)?[^\s,;'\"]{1,4096}"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(cookie|set-cookie|x-api-key|api-key)"
            r"\s*[:=]\s*(?!\[REDACTED)[^\s,;]{1,4096}"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)(--(?:password|passwd|pass|token|secret|api-key|apikey|client-secret|auth-token)"
            r"(?:=|\s+))(?!\[REDACTED)[^\s'\"]{1,4096}"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key"
            r"|client[_-]?secret)\s*[:=]\s*(?!(?:read|write|none)\b|[\"']?\[REDACTED)"
            r"(?:\"[^\"]{0,4096}\"|'[^']{0,4096}'|[^\s,;&]{1,4096})"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,15}://)([^\s:/@]{1,256}):([^\s@/]{1,256})@"),
        r"\1\2:[REDACTED]@",
    ),
    (
        re.compile(
            r"(?i)([?&](?:token|key|sig|signature|password|secret|access_token|api_key)=)[^&\s]{1,4096}"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}\b"
        ),
        "[REDACTED:email]",
    ),
)


@dataclass(frozen=True)
class Cleaned:
    """Cleaned text plus what cleaning did (counted into the projection's statistics)."""

    text: str
    redactions: int
    truncated: bool


def _strip_controls(text: str) -> str:
    text = text.translate(_LINE_BREAKS)
    return "".join(ch for ch in text if unicodedata.category(ch) not in {"Cc", "Cf", "Co", "Cs"})


#: GitHub Actions permission levels such as ``id-token: write`` are not secrets, but
#: generic ``token: <value>`` redaction rules match them. They are guarded with an
#: invisible separator while the platform redactor runs and unguarded afterwards.
#: Inputs are normalised first (format characters removed), so the guard character
#: can never originate from telemetry.
_PERMISSION_LEVEL = re.compile(r"(?i)(toke)(n\s*[:=]\s*(?:read|write|none)\b)")
_GUARD = "\u2063"  # INVISIBLE SEPARATOR (escaped: no literal format chars in source)


def _external_redact(text: str) -> tuple[str, int]:
    redact: Callable[[str], tuple[str, int]] | None = optional_attr(
        "extorq.common.redaction", "redact_text"
    )
    if redact is None:
        return text, 0
    guarded = _PERMISSION_LEVEL.sub(lambda m: m.group(1) + _GUARD + m.group(2), text)
    try:
        redacted, count = redact(guarded)
    except Exception:  # noqa: BLE001 - fall back to local patterns; never pass raw text on error
        return text, 0
    if not isinstance(redacted, str):
        return text, 0
    return redacted.replace(_GUARD, ""), int(count)


def redact_secrets(text: str, known_secrets: Iterable[str] = ()) -> tuple[str, int]:
    """Redact secrets with A's redactor (if present), local patterns and exact known values."""
    text, count = _external_redact(text)
    for pattern, replacement in _SECRET_PATTERNS:
        text, n = pattern.subn(replacement, text)
        count += n
    for secret in known_secrets:
        if secret and len(secret) >= 8 and secret in text:
            count += text.count(secret)
            text = text.replace(secret, "[REDACTED:configured_secret]")
    return text, count


def _truncate(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    keep = max(0, limit - len(TRUNCATION_MARK))
    return text[:keep].rstrip() + TRUNCATION_MARK, True


def _normalise(value: object) -> str:
    text = value if isinstance(value, str) else str(value)
    if len(text) > _HARD_INPUT_CAP:
        text = text[:_HARD_INPUT_CAP]
    text = unicodedata.normalize("NFKC", text)
    text = _strip_controls(text)
    return _WS.sub(" ", text).strip()


def neutralise_markup(text: str) -> str:
    """Make HTML/XML tags inert while keeping them readable (``<`` -> U+2039).

    Without ``<`` no tag can open, so ``>`` (as in ``->``) is left untouched.
    """
    return text.replace("<", "\u2039")


def clean_untrusted(value: object, limit: int, *, known_secrets: Iterable[str] = ()) -> Cleaned:
    """Clean attacker-controllable telemetry text for inclusion in Jev's state."""
    text = _normalise(value)
    text, redactions = redact_secrets(text, known_secrets)
    text = _HEX32.sub("[hex32]", text)
    text = neutralise_markup(text)
    text = _WS.sub(" ", text).strip()
    text, truncated = _truncate(text, limit)
    return Cleaned(text, redactions, truncated)


def clean_trusted(value: object, limit: int, *, known_secrets: Iterable[str] = ()) -> Cleaned:
    """Clean ExtorQ-authored text (rule metadata, coverage notes): normalise, redact, bound.

    Rule text may legitimately quote ids, so 32-hex tokens are kept here.
    """
    text = _normalise(value)
    text, redactions = redact_secrets(text, known_secrets)
    text = neutralise_markup(text)
    text, truncated = _truncate(text, limit)
    return Cleaned(text, redactions, truncated)


_SAFE_TOKEN = re.compile(r"[^A-Za-z0-9:._@/+-]")


def clean_token(value: object, limit: int = 128) -> str:
    """Restrict an identifier-like value (requested_by, request ids) to a safe charset."""
    text = _normalise(value)
    return _SAFE_TOKEN.sub("", text)[:limit]
