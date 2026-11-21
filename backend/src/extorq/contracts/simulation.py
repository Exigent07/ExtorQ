"""SimulationRun contract (schema 1.0).

Simulations are controlled, reversible actions against authorized lab assets.
A SimulationRun records *that* a scenario was executed; it is never evidence by
itself. Detections must come from the genuine telemetry the action produced.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from extorq.contracts.common import (
    SCHEMA_VERSION,
    AssetId,
    ContractModel,
    MediumStr,
    RuleId,
    SchemaVersion,
    ShortStr,
    SimulationRunId,
    UtcDatetime,
)


class SimulationStatus(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"
    CLEANED_UP = "cleaned_up"


class SimulationRun(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    run_id: SimulationRunId
    #: VM-001 | VM-002 | K8S-001 | K8S-002 | GH-001 | HTTP-001 | CORR-001 ...
    scenario_id: ShortStr
    asset_id: AssetId
    status: SimulationStatus
    started_at: UtcDatetime
    finished_at: UtcDatetime | None = None
    operator: ShortStr
    description: MediumStr
    expected_rule_ids: list[RuleId] = Field(default_factory=list, max_length=8)
    notes: list[MediumStr] = Field(default_factory=list, max_length=16)
