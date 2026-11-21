"""SYNTHETIC event records for correlation unit tests (never real telemetry)."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta
from typing import Any

from extorq.correlation.records import EventRecord

T0 = datetime(2026, 11, 20, 10, 0, 0, tzinfo=UTC)
VM = "linux:lab-vm-01"
K8S = "k8s:extorq-lab"
MAC = "macos:workstation-01"
_ids = itertools.count(1)


def eid() -> str:
    return f"{next(_ids):032x}"


def ev(event_type: str, seconds: float = 0, **fields: Any) -> EventRecord:
    """An EventRecord with sensible synthetic defaults (Linux VM, journald)."""
    base: dict[str, Any] = {
        "event_id": eid(),
        "event_time": T0 + timedelta(seconds=seconds),
        "event_type": event_type,
        "source_type": "linux.journald",
        "asset_id": VM,
        "asset_type": "linux_host",
        "outcome": "failure",
    }
    base.update(fields)
    return EventRecord(**base)
