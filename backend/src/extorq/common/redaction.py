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

Key-based rules (``password=...``, ``"api_key": ...``, ``Authorization: ...``) only
treat strings as secret candidates where the text is structured (B2-IC-2):

* a literal ``true``/``false``/``null``/``None`` is never a credential, whatever the key
  says (``allow_gh_cli_token=true``, ``"automount_sa_token": false``);
* after a quoted key (JSON, Python dict) an unquoted number is data, not a secret
  (``"max_token": 4096``); in free text a number stays a candidate (``password=123456``);
* quoted values are matched escape-aware (``"a\\"b"`` is one value).

Redacting a valid JSON document therefore yields valid JSON whose booleans, numbers
and nulls are unchanged.
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


# Unquoted value delimiters of the key-based rules (a value ends before one of these).
_VALUE_CHARS = r"[^\s&,;\"'<>}{)\]]"
# JSON / Python literals: never a credential, whatever the key says.
_LITERAL_VALUE = rf"(?:true|false|null|none)(?!{_VALUE_CHARS})"
# A JSON number (only exempt after a quoted key, i.e. inside JSON or a Python dict).
_JSON_NUMBER = r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?"
# Quoted string values, escape-aware first (JSON), then plain (free text, e.g. "C:\\x\\").
_QUOTED_VALUE = (
    r"\"(?:[^\"\\\n]|\\.){1,1024}\"|'(?:[^'\\\n]|\\.){1,1024}'"
    r"|\"[^\"]{1,1024}\"|'[^']{1,1024}'"
)

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
        re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
        _whole("jwt"),
    ),
    (
        "url_credentials",
        re.compile(
            r"([a-zA-Z][a-zA-Z0-9+.-]{1,20}://[^/\s:@\"']{1,256}:)(?!\[REDACTED)[^@\s/\"']{1,256}(?=@)"
        ),
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
        # Any other Authorization scheme ("Token x", "ApiKey x", raw value), F-06. Skips
        # values already redacted above; requires a token-like value (digit or symbol) so
        # words such as "authorization=denied" in application logs survive.
        "authorization_header",
        re.compile(
            r"(?i)(\b(?:proxy-)?authorization([\"'])?\s*[:=]\s*([\"'])?"
            r"(?:(?:token|apikey|api-key|key|digest|negotiate|ntlm|aws4-hmac-sha256|hoba|"
            r"mutual|scram-sha-1|scram-sha-256|vapid|dpop|oauth|signature|hawk|sharedkey|"
            r"ssws|googlelogin|bearer|basic)\s+)?)"
            r"(?![^\r\n\"']*\[REDACTED)"
            # quoted key + unquoted value = a JSON number, never a credential (B2-IC-2)
            rf"(?(2)(?(3)|(?!{_JSON_NUMBER}(?![^\s\"',;{{}}\[\]]))))"
            r"(?=[^\s\"',;{}\[\]]*[0-9+/=_.~-])([^\s\"',;{}\[\]]{8,1024})"
        ),
        _keep_prefix("authorization"),
    ),
    (
        # Whitespace-separated CLI secrets: --password x, --token x, -pass x (F-06).
        # "--password-file x" and similar *_file flags are not matched.
        "cli_secret_flag",
        re.compile(
            r"(?i)((?:^|(?<=\s))--?(?:password|passwd|pass|secret|token|api[-_]?key|"
            r"auth[-_]?token|access[-_]?key|client[-_]?secret|private[-_]?key|"
            r"requirepass|masterauth)\s+)"
            r"(?!-)(?!\[REDACTED)(\S{1,1024})"
        ),
        _keep_prefix("secret"),
    ),
    (
        # mysql-family "-p<secret>" (no space) and "sshpass -p <secret>" (F-06). Limited to
        # these programs so "ssh -p2222" or "mkdir -p" are never touched.
        "cli_password_short_flag",
        re.compile(
            r"(?i)(\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mariadb|mariadb-dump)\b"
            r"[^\n]*?\s-p)(?!\[REDACTED)([^\s\-][^\s]{0,1023})"
        ),
        _keep_prefix("password"),
    ),
    (
        "sshpass",
        re.compile(r"(?i)(\bsshpass\s+-p\s*)(?!\[REDACTED)(\S{1,1024})"),
        _keep_prefix("password"),
    ),
    (
        # redis-cli -a <password> (F-06 residual)
        "redis_cli_password",
        re.compile(r"(?i)(\bredis-cli\b[^\n]*?\s-a\s+)(?!\[REDACTED)(\S{1,1024})"),
        _keep_prefix("password"),
    ),
    (
        # curl -u user:pass / --user user:pass: keep the user, redact the password.
        "curl_user_password",
        re.compile(
            r"(?i)(\bcurl\b[^\n]*?\s(?:-u|--user)\s+[^\s:]{1,256}:)(?!\[REDACTED)(\S{1,1024})"
        ),
        _keep_prefix("password"),
    ),
    (
        # Upper-case environment assignments: PGPASSWORD=x, MYSQL_PWD=x, DB_SECRET=x ...
        "env_secret_assignment",
        re.compile(
            r"(\b[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|_PWD)\s*=\s*)"
            r"(?!\[REDACTED)(?!(?i:true|false|null|none)(?![^\s\"'&;]))([^\s\"'&;]{1,1024})"
        ),
        _keep_prefix("secret"),
    ),
    (
        # key=value / "key": value. Only strings are candidates in structured text: JSON
        # literals never, numbers not after a quoted key (B2-IC-2, see module docstring).
        "secret_assignment",
        re.compile(
            r"(?i)((?<![A-Za-z0-9])"
            r"(?:password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
            r"client[_-]?secret|auth[_-]?token|private[_-]?key|session[_-]?secret)"
            r"([\"'])?\s*[:=]\s*)"
            rf"(?!\[REDACTED)(?!{_LITERAL_VALUE})"
            # after a quoted key: no JSON number, no array (objects never match: "{" ends values)
            rf"(?(2)(?!(?:{_JSON_NUMBER})(?!{_VALUE_CHARS})|\[))"
            rf"({_QUOTED_VALUE}|{_VALUE_CHARS}{{1,1024}})"
        ),
        lambda match: f"{match.group(1)}{_quote_like(match.group(3))}",
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
# Line breaks, including the Unicode line/paragraph separators U+2028/U+2029 and NEL.
_NEWLINES = re.compile("\r\n|[\r\n\u0085\u2028\u2029]")
# ASCII fast path: C0 controls except TAB (LF is handled above) and DEL.
_ASCII_CONTROLS = re.compile("[\x00-\x08\x0b-\x1f\x7f]")
#: Unicode general categories removed from untrusted text: controls (Cc, incl. C1),
#: format characters (Cf: bidi embeddings/overrides/isolates, zero-width characters,
#: BOM, soft hyphen, Mongolian vowel separator, TAG characters U+E0000-E007F, ...),
#: surrogates (Cs) and private-use characters (Co). Written as names, never as literal
#: invisible characters in this source file (Trojan Source, F-03).
_STRIPPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co"})


def _strip_invisible(text: str) -> str:
    if text.isascii():
        return _ASCII_CONTROLS.sub("", text)
    return "".join(
        ch
        for ch in text
        if ch == "\t" or ch == "\n" or unicodedata.category(ch) not in _STRIPPED_CATEGORIES
    )


def sanitize_untrusted(text: str, limit: int, *, keep_newlines: bool = False) -> str:
    """Return ``text`` safe for storage/display, at most ``limit`` characters long.

    Strips ANSI escape sequences, control characters (C0, C1), every Unicode format
    character (bidi controls, zero-width characters, TAG characters, soft hyphen, BOM),
    surrogates and private-use characters; converts line breaks (CR, LF, NEL, U+2028,
    U+2029) to spaces (or ``\\n`` when ``keep_newlines``), NFC-normalises and truncates
    with :data:`TRUNCATION_MARKER` when the result would exceed ``limit``.
    """
    if limit <= 0:
        return ""
    if not text:
        return ""
    cleaned = _ANSI.sub("", text)
    cleaned = _NEWLINES.sub("\n" if keep_newlines else " ", cleaned)
    cleaned = _strip_invisible(cleaned)
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
