"""Deterministic baseline prioritiser (the comparison point for Jev).

score = severity_weight x asset_criticality_weight x evidence_confidence_weight
        + correlation bonus (direct related events, candidate related events)

* ``insufficient_context`` when any telemetry source for the context was stale
  or had a gap during the window AND the alert's evidence confidence is not
  ``high``;
* ``priority_investigation`` when score >= 3.0, ``routine_review`` when
  score >= 1.5, otherwise ``likely_benign_maintenance``.

The baseline intentionally uses only fields every alert has; it knows nothing
about actors, review signals or maintenance context.
"""

from __future__ import annotations

from dataclasses import dataclass

from extorq.contracts.ai import TriageRecommendation
from extorq.contracts.alert import EvidenceConfidence
from extorq.contracts.common import Criticality, Severity
from extorq.contracts.context import InvestigationContext, RelationshipType

SEVERITY_WEIGHT = {
    Severity.INFO: 0.5,
    Severity.LOW: 1.0,
    Severity.MEDIUM: 2.0,
    Severity.HIGH: 3.0,
    Severity.CRITICAL: 4.0,
}
CRITICALITY_WEIGHT = {
    Criticality.LOW: 0.75,
    Criticality.MEDIUM: 1.0,
    Criticality.HIGH: 1.25,
    Criticality.CRITICAL: 1.5,
}
CONFIDENCE_WEIGHT = {
    EvidenceConfidence.LOW: 0.6,
    EvidenceConfidence.MEDIUM: 0.8,
    EvidenceConfidence.HIGH: 1.0,
}
PRIORITY_THRESHOLD = 3.0
ROUTINE_THRESHOLD = 1.5


@dataclass(frozen=True)
class BaselineResult:
    recommendation: TriageRecommendation
    score: float
    reasons: tuple[str, ...]


def baseline_prioritise(ctx: InvestigationContext) -> BaselineResult:
    alert = ctx.alert
    reasons: list[str] = []
    coverage_problem = any(c.stale or c.gap_during_window for c in ctx.coverage)
    if coverage_problem and alert.confidence is not EvidenceConfidence.HIGH:
        return BaselineResult(
            TriageRecommendation.INSUFFICIENT_CONTEXT, 0.0, ("coverage_gap_low_confidence",)
        )

    score = (
        SEVERITY_WEIGHT[alert.severity]
        * CRITICALITY_WEIGHT[ctx.asset.criticality]
        * CONFIDENCE_WEIGHT[alert.confidence]
    )
    reasons.append(f"base={score:.2f}")
    direct = sum(1 for r in ctx.relationships if r.relationship_type is RelationshipType.DIRECT)
    candidate = sum(
        1 for r in ctx.relationships if r.relationship_type is RelationshipType.CANDIDATE
    )
    bonus = min(1.5, 0.5 * direct) + min(0.75, 0.25 * candidate)
    if bonus:
        reasons.append(f"correlation_bonus={bonus:.2f}")
    score += bonus
    if score >= PRIORITY_THRESHOLD:
        rec = TriageRecommendation.PRIORITY_INVESTIGATION
    elif score >= ROUTINE_THRESHOLD:
        rec = TriageRecommendation.ROUTINE_REVIEW
    else:
        rec = TriageRecommendation.LIKELY_BENIGN_MAINTENANCE
    return BaselineResult(rec, round(score, 3), tuple(reasons))
