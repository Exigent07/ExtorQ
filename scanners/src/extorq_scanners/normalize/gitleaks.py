"""Gitleaks JSON report -> secret PostureFindings (never the secret itself).

Gitleaks runs with ``--redact`` so secrets never reach this process. From each
leak only the rule id, file, line range, commit (git mode), a fingerprint
rebuilt from those validated parts and the *redacted* match are kept; author,
e-mail, commit message, date, entropy and columns are discarded. Every stored
free-text value additionally passes through ``extorq.common.redaction``.

Gitleaks can fail silently (e.g. git "dubious ownership": exit 0, ``[]``,
``0 commits scanned``), so its stderr log is parsed for ERR/FTL lines and the
scanned commit/byte counts; see ``nothing_scanned`` / ``tool_errors``.
"""

from __future__ import annotations

import re
from typing import Any

from extorq.contracts import FindingCategory, Resource
from extorq_scanners.models import NormalizeContext, NormalizedScan, ReportFormatError
from extorq_scanners.normalize.common import FindingBuilder
from extorq_scanners.sanitize import (
    MEDIUM,
    RedactionCounter,
    Verbatim,
    bounded_int,
    clean,
    clean_list,
    relative_path,
    safe_commit,
    safe_identifier,
)

REDACTION_MARKER = "REDACTED"
_LOG_LEVEL = re.compile(r"^\S+\s+(TRC|DBG|INF|WRN|ERR|FTL|PNC)\s+(.*)$")
_COMMITS = re.compile(r"(\d+) commits scanned")
_BYTES = re.compile(r"scanned ~(\d+) bytes")
_LEAKS = re.compile(r"leaks found: (\d+)")
_REMEDIATION = (
    "Revoke and rotate the credential, remove it from the repository and its history, "
    "and load it from a secret store at runtime."
)


def parse_log(stderr: str) -> dict[str, Any]:
    """Extract error lines and scan counters from gitleaks' console log (stderr)."""
    errors: list[str] = []
    commits = scanned_bytes = leaks = None
    for line in stderr.splitlines():
        match = _LOG_LEVEL.match(line.strip())
        if match and match.group(1) in {"ERR", "FTL", "PNC"}:
            text = clean(match.group(2), 300)
            if text and len(errors) < 20:
                errors.append(text)
        if (m := _COMMITS.search(line)) is not None:
            commits = int(m.group(1))
        if (m := _BYTES.search(line)) is not None:
            scanned_bytes = int(m.group(1))
        if (m := _LEAKS.search(line)) is not None:
            leaks = int(m.group(1))
    return {"errors": errors, "commits": commits, "bytes": scanned_bytes, "leaks": leaks}


def _redacted_match(value: object, counter: RedactionCounter) -> tuple[str, bool]:
    """(evidence, ok). Only matches that gitleaks itself redacted are kept."""
    if isinstance(value, str) and REDACTION_MARKER in value:
        cleaned = clean(value, 512, counter)
        if cleaned and REDACTION_MARKER in cleaned:
            return cleaned, True
    return REDACTION_MARKER, False


def normalize_gitleaks(report: object, stderr: str, ctx: NormalizeContext) -> NormalizedScan:
    """Normalise a parsed gitleaks JSON report plus its stderr log."""
    if not isinstance(report, list):
        raise ReportFormatError("gitleaks report is not a JSON array")
    out = NormalizedScan()
    counter = RedactionCounter()
    builder = FindingBuilder(ctx, out, counter)
    log = parse_log(stderr)
    unredacted = 0

    for leak in report:
        if not isinstance(leak, dict):
            raise ReportFormatError("gitleaks leak entry is not an object")
        rule = safe_identifier(leak.get("RuleID"), 128)
        file_rel = clean(relative_path(leak.get("File"), ctx.mount_point), MEDIUM, counter)
        if rule is None or file_rel is None:
            out.dropped += 1
            continue
        commit = safe_commit(leak.get("Commit"))
        start = bounded_int(leak.get("StartLine"))
        end = bounded_int(leak.get("EndLine"))
        evidence, ok = _redacted_match(leak.get("Match"), counter)
        if not ok or leak.get("Secret") not in (REDACTION_MARKER, None, ""):
            unredacted += 1
        parts = [
            *([commit] if commit else []),
            file_rel,
            rule,
            str(start if start is not None else ""),
        ]
        # Gitleaks' native fingerprint format, rebuilt from validated/redacted parts only.
        fingerprint = Verbatim(":".join(parts))
        severity = ctx.severity_overrides.get(rule, ctx.default_secret_severity)
        builder.add(
            check_id=f"gitleaks:{rule}",
            resource_key=fingerprint,
            category=FindingCategory.SECRET,
            severity=severity,
            title=f"Secret detected ({rule})",
            # Static text from the gitleaks rule definition, not from the scanned content.
            description=clean(leak.get("Description"), MEDIUM, counter),
            resource=Resource(type="file", path=file_rel),
            evidence=f"redacted match: {evidence}",
            remediation=_REMEDIATION,
            attributes={
                "rule_id": Verbatim(rule),
                "line": start,
                "end_line": end,
                "commit": commit,
                "fingerprint": fingerprint,
                "mode": ctx.mode or None,
                "tags": clean_list(leak.get("Tags"), max_items=16, item_limit=64),
            },
        )

    out.tool_errors.extend(log["errors"])
    if log["commits"] is not None:
        out.notes.append(f"{log['commits']} commits scanned")
    if log["bytes"] is not None:
        out.notes.append(f"~{log['bytes']} bytes scanned")
    if unredacted:
        out.notes.append(
            f"{unredacted} leaks were not redacted by gitleaks; their matches were discarded"
        )
    if log["leaks"] is not None and log["leaks"] != len(report):
        out.tool_errors.append(
            f"gitleaks log reports {log['leaks']} leaks but the report contains {len(report)}"
        )
    # Silent failure guard: errors logged and nothing (or zero commits) scanned.
    zero_commits = ctx.mode == "git" and log["commits"] == 0
    zero_bytes = log["bytes"] == 0 and bool(log["errors"])
    out.nothing_scanned = zero_commits or zero_bytes
    out.attributes = {
        k: v
        for k, v in {
            "commits_scanned": log["commits"],
            "bytes_scanned": log["bytes"],
            "mode": ctx.mode or None,
        }.items()
        if v is not None
    }
    out.redactions = counter.count
    return out
