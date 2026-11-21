"""Collector and pipeline health contracts (schema 1.0).

Health is first-class telemetry: dashboards must show *stale* and *missing*
collection explicitly instead of silently rendering old data as current.
A source is considered stale when ``now - last_success_at > 3 * interval_seconds``.
"""

from __future__ import annotations

from pydantic import Field

from extorq.contracts.common import (
    SCHEMA_VERSION,
    AssetId,
    Attributes,
    ContractModel,
    HealthStatus,
    Identifier,
    MediumStr,
    SchemaVersion,
    ShortStr,
    UtcDatetime,
)


class CollectorHealth(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    collector_id: Identifier
    #: macos | linux_ssh | k8s_inventory | k8s_otel | github | scanner
    collector_type: Identifier
    asset_id: AssetId
    source_types: list[ShortStr] = Field(min_length=1, max_length=16)
    status: HealthStatus
    reported_at: UtcDatetime
    last_attempt_at: UtcDatetime | None = None
    last_success_at: UtcDatetime | None = None
    #: Sanitized error summary of the most recent failure.
    last_error: MediumStr | None = None
    events_collected: int = Field(default=0, ge=0)
    #: Records waiting in the collector's local outbox (not yet acknowledged).
    records_buffered: int = Field(default=0, ge=0)
    #: Seconds between now and the newest source timestamp collected.
    lag_seconds: float | None = Field(default=None, ge=0)
    checkpoint_summary: ShortStr | None = None
    collector_version: ShortStr
    interval_seconds: int = Field(ge=1, le=86400)
    details: Attributes = Field(default_factory=dict)


class PipelineHealth(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    #: ingest | writer | detector | ai_worker | api
    component: Identifier
    instance: ShortStr
    reported_at: UtcDatetime
    status: HealthStatus
    queue_depth: int = Field(default=0, ge=0)
    oldest_queued_age_seconds: float | None = Field(default=None, ge=0)
    accepted_total: int = Field(default=0, ge=0)
    duplicate_total: int = Field(default=0, ge=0)
    rejected_total: int = Field(default=0, ge=0)
    quarantined_total: int = Field(default=0, ge=0)
    written_total: int = Field(default=0, ge=0)
    write_errors_total: int = Field(default=0, ge=0)
    dead_letter_total: int = Field(default=0, ge=0)
    last_write_at: UtcDatetime | None = None
    details: Attributes = Field(default_factory=dict)
