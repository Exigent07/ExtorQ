"""AIAssessment contracts (schema 1.0).

AI output is advisory, stored separately from alerts, and always traceable to
the InvestigationContext ``input_hash`` it was computed from.

* Jev (TypeSafe System One) answers *typed, bounded* questions (Noul/Choice/
  Score). ExtorQ post-processes the probabilities deterministically into a
  triage recommendation with an explicit INSUFFICIENT_CONTEXT outcome. Jev never
  changes rule severity, suppresses alerts, or counts events.
* Gemini produces an evidence-grounded summary. Every statement carries
  evidence ids; the backend verifies each id against the supplied bundle and
  marks unknown ids as unverified (they are never shown as verified evidence).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from extorq.contracts.common import (
    SCHEMA_VERSION,
    ContractModel,
    HexId,
    MediumStr,
    SchemaVersion,
    Sha256Hex,
    ShortStr,
    UtcDatetime,
)


class AIProvider(StrEnum):
    JEV = "typesafe-jev"
    GEMINI = "google-gemini"


class AITask(StrEnum):
    TRIAGE = "triage"
    SUMMARY = "summary"


class AIStatus(StrEnum):
    OK = "ok"
    INSUFFICIENT_CONTEXT = "insufficient_context"
    INVALID_OUTPUT = "invalid_output"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"
    DISABLED = "disabled"
    BUDGET_EXCEEDED = "budget_exceeded"


# ── Jev triage ───────────────────────────────────────────────────────


class JevAnswer(ContractModel):
    question_id: ShortStr
    type: Literal["noul", "choice", "score"]
    #: Noul probability (0..1), chosen option name, or numeric score.
    value: float | str
    confidence: float | None = Field(default=None, ge=0, le=1)
    probabilities: dict[ShortStr, float] = Field(default_factory=dict)


class TriageRecommendation(StrEnum):
    PRIORITY_INVESTIGATION = "priority_investigation"
    ROUTINE_REVIEW = "routine_review"
    LIKELY_BENIGN_MAINTENANCE = "likely_benign_maintenance"
    INSUFFICIENT_CONTEXT = "insufficient_context"


class JevTriageResult(ContractModel):
    recommendation: TriageRecommendation
    #: True when probabilities fall in the configured uncertainty band or the
    #: Choice answers disagree across option orderings.
    uncertain: bool
    order_consistent: bool
    sufficient_context_probability: float = Field(ge=0, le=1)
    answers: list[JevAnswer] = Field(max_length=32)
    #: Deterministic reason codes describing which answers drove the result.
    rationale_codes: list[ShortStr] = Field(default_factory=list, max_length=16)
    question_set_version: ShortStr


# ── Gemini summary ───────────────────────────────────────────────────


class EvidenceStatement(ContractModel):
    text: MediumStr
    evidence_ids: list[ShortStr] = Field(default_factory=list, max_length=32)
    #: Set by the backend after validation: all cited ids exist in the bundle.
    verified: bool = False
    unverified_ids: list[ShortStr] = Field(default_factory=list, max_length=32)


class SummaryTimelineItem(ContractModel):
    time: ShortStr
    description: MediumStr
    evidence_ids: list[ShortStr] = Field(default_factory=list, max_length=32)
    verified: bool = False
    unverified_ids: list[ShortStr] = Field(default_factory=list, max_length=32)


class InvestigationSummary(ContractModel):
    what_happened: list[EvidenceStatement] = Field(max_length=12)
    timeline: list[SummaryTimelineItem] = Field(max_length=40)
    why_rule_fired: EvidenceStatement
    related_activity: list[EvidenceStatement] = Field(default_factory=list, max_length=12)
    benign_explanations: list[MediumStr] = Field(default_factory=list, max_length=8)
    missing_information: list[MediumStr] = Field(default_factory=list, max_length=12)
    limitations: list[MediumStr] = Field(default_factory=list, max_length=12)
    recommended_next_steps: list[MediumStr] = Field(default_factory=list, max_length=12)
    overall_confidence: Literal["low", "medium", "high"]


class SummaryValidation(ContractModel):
    schema_valid: bool
    evidence_ids_cited: int = Field(ge=0)
    evidence_ids_verified: int = Field(ge=0)
    evidence_ids_rejected: int = Field(ge=0)
    statements_without_evidence: int = Field(ge=0)


# ── Assessment record ────────────────────────────────────────────────


class AIAssessment(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    assessment_id: HexId
    alert_id: HexId
    context_id: HexId
    context_input_hash: Sha256Hex
    provider: AIProvider
    #: Versioned model id actually used (e.g. "jev-1.14.0", "gemini-3.6-flash").
    model: ShortStr
    task: AITask
    #: Question-set or prompt-template version (e.g. "triage-v1", "summary-v1").
    prompt_version: ShortStr
    status: AIStatus
    triage: JevTriageResult | None = None
    summary: InvestigationSummary | None = None
    validation: SummaryValidation | None = None
    latency_ms: int | None = Field(default=None, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    provider_request_id: ShortStr | None = None
    #: Sanitized error class/message. Never contains credentials or prompt content.
    error: MediumStr | None = None
    created_at: UtcDatetime
    #: "system:ai-worker" or "analyst:<username>".
    requested_by: ShortStr
