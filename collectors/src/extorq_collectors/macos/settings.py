"""Validated settings for the macOS collector (``settings:`` in config/collectors/macos.yaml).

Unknown keys are rejected. Configuration can only choose among fixed options
(names of unified-log producers, intervals, limits); it can never supply
predicate text, commands or paths to execute.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from extorq.contracts.common import Criticality, Environment
from extorq_collectors.macos.unified_log import DEFAULT_PRODUCERS, PRODUCERS


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class UnifiedLogSettings(_Strict):
    enabled: bool = True
    interval_seconds: int = Field(default=60, ge=10, le=3600)
    producers: tuple[str, ...] = Field(default=DEFAULT_PRODUCERS, min_length=1)
    #: First run only: how far back to read.
    initial_lookback_seconds: int = Field(default=900, ge=60, le=86400)
    #: Re-read this much before the checkpoint (records are de-duplicated by event id).
    overlap_seconds: int = Field(default=10, ge=0, le=300)
    #: Do not read the most recent seconds (late records still being written).
    settle_seconds: int = Field(default=5, ge=0, le=120)
    max_window_seconds: int = Field(default=900, ge=30, le=86400)
    #: Older history than this is skipped after an outage and reported as a gap.
    max_backfill_seconds: int = Field(default=86400, ge=300, le=7 * 86400)
    max_records_per_cycle: int = Field(default=5000, ge=10, le=50000)
    max_output_bytes: int = Field(default=32 * 1024 * 1024, ge=64 * 1024, le=256 * 1024 * 1024)
    command_timeout_seconds: float = Field(default=120.0, gt=0, le=600)
    #: Map a public GeneratedUID (opendirectoryd logs the name as <private>) to the
    #: account short name with ``dscl . -search /Users GeneratedUID`` (never RealName).
    resolve_generated_uid: bool = True

    @field_validator("producers")
    @classmethod
    def _known(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        unknown = sorted(set(value) - set(PRODUCERS))
        if unknown:
            raise ValueError(f"unknown unified-log producers: {', '.join(unknown)}")
        return tuple(dict.fromkeys(value))

    @model_validator(mode="after")
    def _window_makes_progress(self) -> UnifiedLogSettings:
        # Each window starts overlap_seconds before the checkpoint; it must reach past it.
        if self.overlap_seconds >= self.max_window_seconds:
            raise ValueError("overlap_seconds must be smaller than max_window_seconds")
        return self


class LaunchdSettings(_Strict):
    enabled: bool = True
    interval_seconds: int = Field(default=60, ge=10, le=3600)
    #: Labels (fnmatch patterns) known to be legitimate: events are still emitted
    #: with ``attributes.allowlisted=true``; detection decides what to do with them.
    allowlist: tuple[str, ...] = ()
    full_inventory_seconds: int = Field(default=3600, ge=300, le=86400)


class PostureSettings(_Strict):
    enabled: bool = True
    interval_seconds: int = Field(default=300, ge=60, le=86400)
    max_admin_accounts: int = Field(default=1, ge=0, le=100)
    os_update_medium_after_days: int = Field(default=14, ge=0, le=365)
    command_timeout_seconds: float = Field(default=20.0, gt=0, le=300)


class ListenerSettings(_Strict):
    """Listening sockets (netstat, lsof fallback): their own fast source.

    Listeners open and close quickly and an all-interfaces listener is security relevant
    (MAC-003), so they are diffed every minute instead of with the slower inventory.
    """

    enabled: bool = True
    interval_seconds: int = Field(default=60, ge=10, le=3600)
    include_udp: bool = True
    full_inventory_seconds: int = Field(default=3600, ge=300, le=86400)
    command_timeout_seconds: float = Field(default=30.0, gt=0, le=300)


class InventorySettings(_Strict):
    enabled: bool = True
    interval_seconds: int = Field(default=300, ge=60, le=86400)
    #: Full process arguments are a privacy risk (tokens on command lines); off by default.
    include_process_args: bool = False
    #: Kernel-reported executable paths (proc_pidpath) instead of argv[0] only.
    verify_executable_paths: bool = True
    #: Local account names + UIDs + login shells (never RealName) for account.user.* diffs.
    accounts: bool = True
    full_inventory_seconds: int = Field(default=3600, ge=300, le=86400)
    command_timeout_seconds: float = Field(default=30.0, gt=0, le=300)


class ApplicationsSettings(_Strict):
    """Hourly full application inventory (system_profiler; slow, whole disk)."""

    enabled: bool = True
    interval_seconds: int = Field(default=3600, ge=300, le=86400)
    command_timeout_seconds: float = Field(default=180.0, gt=0, le=600)


class SoftwareSettings(_Strict):
    """Application-folder scan for ``software.installed`` / ``software.removed`` (MAC-005)."""

    enabled: bool = True
    interval_seconds: int = Field(default=60, ge=10, le=3600)
    #: Also scan ~/Applications (scope "user") besides /Applications.
    include_user_applications: bool = True
    #: A new bundle is reported once its entries were quiet this long (half-copied bundles
    #: would otherwise fail signature verification: a false positive).
    settle_seconds: int = Field(default=30, ge=0, le=600)
    #: Upper bound on scans a new bundle can be deferred (settling or retried verification).
    max_defer_scans: int = Field(default=5, ge=0, le=60)
    #: codesign runs only for new bundles: at most this many per scan, within this much
    #: wall-clock time (the rest wait for the next scan), each call bounded by the timeout.
    max_signature_checks: int = Field(default=4, ge=1, le=100)
    check_budget_seconds: float = Field(default=60.0, gt=0, le=600)
    codesign_timeout_seconds: float = Field(default=20.0, gt=0, le=300)


class ServicesSettings(_Strict):
    #: Service discovery runs with every inventory cycle.
    enabled: bool = True
    #: A log-backed adapter is "monitored" while its source was read within this time.
    stale_after_seconds: int = Field(default=600, ge=60, le=86400)


class AssetSettings(_Strict):
    enabled: bool = True
    #: Reported only when explicitly configured (the collector never reads the hostname).
    hostname: str | None = Field(default=None, max_length=255)
    name: str = Field(default="workstation-01", min_length=1, max_length=64)
    environment: Environment = Environment.LAB
    criticality: Criticality = Criticality.MEDIUM
    owner: str | None = Field(default=None, max_length=128)
    interval_seconds: int = Field(default=300, ge=60, le=86400)
    refresh_seconds: int = Field(default=900, ge=60, le=86400)


class MacOSSettings(_Strict):
    unified_log: UnifiedLogSettings = UnifiedLogSettings()
    launchd: LaunchdSettings = LaunchdSettings()
    listeners: ListenerSettings = ListenerSettings()
    inventory: InventorySettings = InventorySettings()
    services: ServicesSettings = ServicesSettings()
    posture: PostureSettings = PostureSettings()
    applications: ApplicationsSettings = ApplicationsSettings()
    software: SoftwareSettings = SoftwareSettings()
    asset: AssetSettings = AssetSettings()

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> MacOSSettings:
        return cls.model_validate(data or {})
