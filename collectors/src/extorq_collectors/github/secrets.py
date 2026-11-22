"""Detect credential-shaped strings in the lines a commit ADDS (event ``github.secret.exposed``).

Only three things ever leave this module: the pattern *name* (e.g. ``aws_access_key``), the
file/line location, and the line after ``extorq.common.redaction`` has replaced every matched
value. The raw line is never returned, logged or stored, so a leaked credential in a commit does
not become a second leak inside ExtorQ's own storage.

The patterns are ExtorQ's existing redaction rules (one source of truth, already hardened and
tested); a match is therefore "credential-SHAPED": the collector does not (and cannot) tell
whether the credential is valid.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from extorq.common.redaction import redact_text

#: Bounds: a commit cannot make the collector do unbounded work or emit unbounded events.
MAX_PATCH_CHARS = 2_000_000
MAX_LINE_CHARS = 4_000
MAX_FINDINGS_PER_COMMIT = 50
MAX_REDACTED_MATCH_CHARS = 200

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,\d+)? @@")
_LABEL = re.compile(r"\[REDACTED:(?P<label>[a-z0-9_]+)\]")


@dataclass(frozen=True)
class SecretFinding:
    """One credential-shaped match. ``redacted_match`` contains no secret value."""

    path: str
    line: int
    pattern: str
    redacted_match: str


def scan_added_lines(path: str, patch: str) -> list[SecretFinding]:
    """Findings for the lines a unified-diff ``patch`` adds (context and removed lines ignored)."""
    findings: list[SecretFinding] = []
    new_line = 0
    for raw in patch[:MAX_PATCH_CHARS].splitlines():
        hunk = _HUNK.match(raw)
        if hunk:
            new_line = int(hunk["start"])
            continue
        if raw.startswith("+++") or raw.startswith("---") or raw.startswith("\\"):
            continue
        if raw.startswith("+"):
            text = raw[1:MAX_LINE_CHARS]
            redacted, count = redact_text(text)
            if count:
                labels = sorted({m["label"] for m in _LABEL.finditer(redacted)})
                for label in labels or ["secret"]:
                    findings.append(
                        SecretFinding(
                            path=path,
                            line=new_line,
                            pattern=label,
                            redacted_match=redacted.strip()[:MAX_REDACTED_MATCH_CHARS],
                        )
                    )
                    if len(findings) >= MAX_FINDINGS_PER_COMMIT:
                        return findings
            new_line += 1
        elif not raw.startswith("-"):
            new_line += 1  # unchanged context line exists in the new file too
    return findings
