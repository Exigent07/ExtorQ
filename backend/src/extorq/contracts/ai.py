"""AIAssessment contracts (schema 2.0).

AI output is advisory, stored separately from alerts, and always traceable to
the InvestigationContext ``input_hash`` it was computed from.

Jev (TypeSafe System One) is the only AI provider. It answers *typed, bounded*
questions (Noul/Choice/Score); ExtorQ post-processes the probabilities
deterministically into a triage recommendation with an explicit
INSUFFICIENT_CONTEXT outcome. Jev never changes rule severity, suppresses
alerts, counts events or writes anything except ``ai_assessments``.
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


class AITask(StrEnum):
    TRIAGE = "triage"


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
    #: Question-set version (e.g. "triage-v2").
    prompt_version: ShortStr
    status: AIStatus
    triage: JevTriageResult | None = None
    latency_ms: int | None = Field(default=None, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    provider_request_id: ShortStr | None = None
    #: Sanitized error class/message. Never contains credentials or prompt content.
    error: MediumStr | None = None
    created_at: UtcDatetime
    #: "system:ai-worker" or "analyst:<username>".
    requested_by: ShortStr
