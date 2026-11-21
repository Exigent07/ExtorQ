"""Helpers shared by the Trivy, Gitleaks and Semgrep normalisers."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import ValidationError

from extorq.common.redaction import sanitize_untrusted
from extorq.contracts import (
    AcceptedRisk,
    FindingCategory,
    PackageRef,
    PostureFinding,
    Resource,
    Severity,
)
from extorq.contracts.identity import finding_id
from extorq_scanners.models import NormalizeContext, NormalizedScan
from extorq_scanners.sanitize import (
    ATTR_LIST_ITEM,
    ATTR_LIST_ITEMS,
    ATTR_STR,
    MEDIUM,
    RedactionCounter,
    Verbatim,
    clean,
    clean_list,
)

MAX_REFERENCES = 10
_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_MAX_ATTR_KEYS = 64

AttrValue = str | int | float | bool | list[str]


def bounded_attributes(
    values: Mapping[str, Any], counter: RedactionCounter | None = None
) -> dict[str, AttrValue]:
    """Contract-safe attributes: valid keys, no ``None``, bounded strings and lists.

    String values are treated as untrusted free text (sanitised and redacted).
    """
    out: dict[str, AttrValue] = {}
    for key, value in values.items():
        if len(out) >= _MAX_ATTR_KEYS or not _KEY_RE.match(key) or value is None:
            continue
        if isinstance(value, bool | int | float):
            out[key] = value
        elif isinstance(value, Verbatim):
            verbatim = sanitize_untrusted(str(value), ATTR_STR).strip()
            if verbatim:
                out[key] = verbatim
        elif isinstance(value, str):
            text = clean(value, ATTR_STR, counter)
            if text is not None:
                out[key] = text
        elif isinstance(value, list | tuple):
            items = clean_list(
                [v for v in value if isinstance(v, str | int | float) and not isinstance(v, bool)],
                max_items=ATTR_LIST_ITEMS,
                item_limit=ATTR_LIST_ITEM,
                counter=counter,
            )
            if items:
                out[key] = items
    return out


def references(
    primary: object, extra: Iterable[object] | None, counter: RedactionCounter
) -> list[str]:
    """At most 10 http(s) references, primary URL first, de-duplicated."""
    candidates: list[object] = [primary] if primary else []
    candidates.extend(extra or [])
    urls = [u for u in candidates if isinstance(u, str) and u.startswith(("https://", "http://"))]
    return clean_list(urls, max_items=MAX_REFERENCES, item_limit=MEDIUM, counter=counter)


def _summarize_validation(exc: ValidationError) -> str:
    """Field locations and error types only: never echo input values (may be secrets)."""
    parts = []
    for err in exc.errors()[:5]:
        loc = ".".join(str(p) for p in err.get("loc", ()))
        parts.append(f"{loc}:{err.get('type', 'invalid')}")
    return ", ".join(parts) or "validation error"


class FindingBuilder:
    """Accumulates validated, de-duplicated PostureFindings for one scan."""

    def __init__(self, ctx: NormalizeContext, result: NormalizedScan, counter: RedactionCounter):
        self.ctx = ctx
        self.result = result
        self.counter = counter
        self._ids: set[str] = set()

    def add(
        self,
        *,
        check_id: str,
        resource_key: str,
        category: FindingCategory,
        severity: Severity,
        title: str,
        description: str | None = None,
        resource: Resource | None = None,
        package: PackageRef | None = None,
        cve_ids: list[str] | None = None,
        cvss_score: float | None = None,
        evidence: str | None = None,
        remediation: str | None = None,
        refs: list[str] | None = None,
        accepted_risk: AcceptedRisk | None = None,
        attributes: Mapping[str, Any] | None = None,
        service_id: str | None = None,
    ) -> PostureFinding | None:
        fid = finding_id(
            self.ctx.asset_id,
            self.ctx.scanner,
            check_id,
            resource_key,
            self.ctx.identity_qualifier,
        )
        if fid in self._ids:
            self.result.duplicates += 1
            return None
        try:
            finding = PostureFinding(
                finding_id=fid,
                scan_run_id=self.ctx.scan_run_id,
                asset_id=self.ctx.asset_id,
                scanner=self.ctx.scanner,
                check_id=check_id,
                category=category,
                severity=severity,
                title=title,
                description=description,
                resource=resource,
                service_id=service_id,
                package=package,
                cve_ids=cve_ids or [],
                cvss_score=cvss_score,
                evidence=evidence,
                remediation=remediation,
                references=refs or [],
                observed_at=self.ctx.observed_at,
                accepted_risk=accepted_risk,
                attributes=bounded_attributes(attributes or {}, self.counter),
            )
        except ValidationError as exc:
            self.result.dropped += 1
            if len(self.result.notes) < 20:
                self.result.notes.append(
                    f"dropped finding {check_id[:80]}: {_summarize_validation(exc)}"
                )
            return None
        self._ids.add(fid)
        self.result.findings.append(finding)
        return finding
