"""Detector settings (environment prefix ``EXTORQ_DETECTOR_``; no secrets here).

ClickHouse connection details and credentials belong to A's
``extorq.common.config.Settings`` and are consumed through
``extorq.storage.clickhouse.get_client(role)``.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DetectorSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="EXTORQ_DETECTOR_", extra="ignore")

    #: Rules directory; falls back to EXTORQ_RULES_DIR, ./rules, then the repository copy.
    rules_dir: str | None = None
    #: Window end lag behind "now" so in-flight batches are not evaluated half-written.
    ingest_delay_seconds: int = Field(default=10, ge=0, le=600)
    #: Test/demo profile only: evaluate EVERY rule at this interval instead of its own
    #: ``schedule.interval_seconds``. Rule windows and lookbacks are unchanged, so detection
    #: semantics stay identical; only the evaluation cadence (and ClickHouse load) changes.
    interval_override_seconds: int | None = Field(default=None, ge=5, le=3600)
    max_rows_per_rule: int = Field(default=1000, ge=1, le=100_000)
    #: Longest span a single window_bucket alert may grow to via continuity merging.
    max_episode_seconds: int = Field(default=3600, ge=60, le=7 * 86400)
    #: Upper bound of one idle sleep in the service loop.
    poll_seconds: float = Field(default=5.0, ge=0.5, le=60)
    health_interval_seconds: int = Field(default=30, ge=5, le=3600)
    instance: str | None = Field(default=None, max_length=128)
    correlation_enabled: bool = True
    #: At most this many contexts are (re)built per rule evaluation.
    max_contexts_per_run: int = Field(default=50, ge=0, le=1000)
    startup_attempts: int = Field(default=30, ge=1, le=1000)
    #: Late-data catch-up horizon (0 disables) and overlap with the previous run.
    catchup_max_seconds: int = Field(default=6 * 3600, ge=0, le=7 * 86400)
    catchup_margin_seconds: int = Field(default=300, ge=0, le=3600)
