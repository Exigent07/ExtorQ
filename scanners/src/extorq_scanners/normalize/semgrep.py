"""Semgrep JSON report -> code PostureFindings.

Only the location (path, line, column), rule metadata and the rule message are
stored; matched source lines and metavariable values are never read from the
report. Semgrep ``errors`` with level ``error`` (e.g. a file that failed to
parse) reduce coverage and are reported as tool errors (scan is then partial).

Finding identity: (check=rule id, resource=path:start_line:start_col:end_line:end_col).
"""

from __future__ import annotations

import re
from typing import Any

from extorq.contracts import FindingCategory, Resource, SkippedCheck

from extorq_scanners import severity as sev
from extorq_scanners.models import NormalizeContext, NormalizedScan, ReportFormatError
from extorq_scanners.normalize.common import FindingBuilder, references
from extorq_scanners.sanitize import (
    MEDIUM,
    SHORT,
    RedactionCounter,
    bounded_int,
    clean,
    clean_list,
    relative_path,
    safe_identifier,
)

_SENTENCE = re.compile(r"^(.{20,200}?[.!?])(\s|$)")


def _first_sentence(text: str | None) -> str | None:
    if not text:
        return None
    match = _SENTENCE.match(text)
    return match.group(1) if match else text[:200]


def _as_list(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [value]
    return []


def _strip_prefix(rule_id: str, prefixes: tuple[str, ...]) -> str:
    for prefix in prefixes:
        if prefix and rule_id.startswith(prefix):
            return rule_id[len(prefix) :]
    return rule_id


def _position(value: object) -> tuple[int | None, int | None]:
    if not isinstance(value, dict):
        return None, None
    return bounded_int(value.get("line")), bounded_int(value.get("col"))


def _error_text(err: dict[str, Any]) -> str:
    etype = err.get("type")
    if isinstance(etype, list) and etype:
        etype = etype[0]
    where = err.get("path") or err.get("rule_id") or ""
    message = clean(err.get("message"), 200) or ""
    return clean(f"{etype or 'error'} {where}: {message}".strip(), 300) or "semgrep error"


def normalize_semgrep(report: object, ctx: NormalizeContext) -> NormalizedScan:
    """Normalise a parsed Semgrep JSON report. Raises ReportFormatError if unusable."""
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ReportFormatError("semgrep report is not an object with a 'results' list")
    out = NormalizedScan()
    counter = RedactionCounter()
    builder = FindingBuilder(ctx, out, counter)
    out.scanner_version = clean(report.get("version"), 64)

    for result in report["results"]:
        if not isinstance(result, dict):
            raise ReportFormatError("semgrep result entry is not an object")
        raw_rule = result.get("check_id")
        rule = safe_identifier(
            _strip_prefix(raw_rule, ctx.rule_id_prefixes) if isinstance(raw_rule, str) else None
        )
        path = clean(relative_path(result.get("path"), ctx.mount_point), MEDIUM, counter)
        if rule is None or path is None:
            out.dropped += 1
            continue
        line, col = _position(result.get("start"))
        end_line, end_col = _position(result.get("end"))
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        message = clean(extra.get("message"), MEDIUM, counter)
        severity, basis = sev.map_semgrep(extra.get("severity"))
        short_rule = rule.rsplit(".", 1)[-1]
        title = clean(f"{short_rule}: {_first_sentence(message) or rule}", SHORT, counter)
        location = f"{path}:{line or '?'}:{col or '?'}"
        builder.add(
            check_id=rule,
            resource_key=f"{path}:{line}:{col}:{end_line}:{end_col}",
            category=FindingCategory.CODE,
            severity=severity,
            title=title or rule,
            description=message,
            resource=Resource(type="file", path=path),
            evidence=f"match at {location} (source excerpt not stored)",
            refs=references(meta.get("source"), _as_list(meta.get("references")), counter),
            attributes={
                "rule_id": rule,
                "line": line,
                "column": col,
                "end_line": end_line,
                "end_column": end_col,
                "source_severity": extra.get("severity"),
                "severity_basis": basis,
                "confidence": meta.get("confidence"),
                "likelihood": meta.get("likelihood"),
                "impact": meta.get("impact"),
                "rule_category": meta.get("category"),
                "subcategory": clean_list(_as_list(meta.get("subcategory")), max_items=8, item_limit=64),
                "cwe": clean_list(_as_list(meta.get("cwe")), max_items=8, item_limit=256),
                "owasp": clean_list(_as_list(meta.get("owasp")), max_items=8, item_limit=128),
                "vulnerability_class": clean_list(
                    _as_list(meta.get("vulnerability_class")), max_items=8, item_limit=128
                ),
                "ruleset": ctx.ruleset_label,
                "engine_kind": extra.get("engine_kind"),
            },
        )

    errors = report.get("errors") or []
    if not isinstance(errors, list):
        raise ReportFormatError("semgrep report 'errors' is not a list")
    for err in errors:
        if not isinstance(err, dict):
            continue
        text = _error_text(err)
        if str(err.get("level", "error")).lower() in {"warn", "warning", "info"}:
            if len(out.notes) < 20:
                out.notes.append(f"semgrep warning: {text}")
        elif len(out.tool_errors) < 50:
            out.tool_errors.append(text)

    paths = report.get("paths") if isinstance(report.get("paths"), dict) else {}
    scanned = paths.get("scanned") if isinstance(paths.get("scanned"), list) else []
    skipped_paths = paths.get("skipped") if isinstance(paths.get("skipped"), list) else []
    skipped_rules = report.get("skipped_rules") if isinstance(report.get("skipped_rules"), list) else []
    for item in skipped_rules[:100]:
        if isinstance(item, dict):
            rule_id = clean(item.get("rule_id") or item.get("id"), SHORT) or "unknown-rule"
            reason = clean(item.get("details") or item.get("reason") or "skipped by semgrep", MEDIUM)
            out.skipped.append(SkippedCheck(check=rule_id, reason=reason or "skipped by semgrep"))
    out.notes.append(f"{len(scanned)} files scanned")
    if skipped_paths:
        out.notes.append(f"{len(skipped_paths)} paths skipped by semgrep")
    if ctx.rules_total is not None:
        out.checks_total = ctx.rules_total
        out.checks_run = max(0, ctx.rules_total - len(skipped_rules))
    out.nothing_scanned = not scanned and bool(out.tool_errors)
    out.attributes = {"files_scanned": len(scanned), "paths_skipped": len(skipped_paths)}
    if ctx.ruleset_label:
        out.attributes["rulesets"] = ctx.ruleset_label
    out.redactions = counter.count
    return out
