"""``extorq-collect sim-record``: record one SimulationRun lifecycle step.

Producer: ``simulation-runner``. Simulation scripts call this before and after a scenario::

    extorq-collect sim-record --scenario VM-001 --asset linux:lab-vm-01 \\
        --status started --run-id a1b2c3d4e5 --description "SSH brute force" \\
        --expected-rules VM-001
    ... run the scenario ...
    extorq-collect sim-record --scenario VM-001 --asset linux:lab-vm-01 \\
        --status completed --run-id a1b2c3d4e5

A SimulationRun records *that* a scenario ran; it is never detection evidence.
The record goes through the same durable outbox as collector records
(``var/collectors/simulation-runner/state.db``): it is committed locally first and
then delivered at least once; if the gateway is unreachable it stays buffered and
is delivered by the next ``sim-record`` or ``extorq-collect flush``.

``started_at`` for later statuses comes from the locally remembered ``started``
record of the same run id (or ``--started-at``); it is never invented.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from extorq.common.config import Settings
from extorq.contracts.common import utc_now
from extorq.contracts.identity import iso_utc
from extorq.contracts.simulation import SimulationRun, SimulationStatus
from extorq_collectors.sdk.base import to_record_json
from extorq_collectors.sdk.client import GatewayClient
from extorq_collectors.sdk.runner import default_client, state_path
from extorq_collectors.sdk.sender import Sender, SendReport
from extorq_collectors.sdk.state import StateStore

PRODUCER_ID = "simulation-runner"
STATE_ID = "simulation-runner"
DEFAULT_OPERATOR = "simulation-runner"
DELIVERY_SECONDS = 30.0


class SimulationRecordError(ValueError):
    """Invalid sim-record request (message is safe to print)."""


@dataclass
class SimRecordResult:
    run: SimulationRun
    report: SendReport
    buffered: int


def _kv_key(run_id: str) -> str:
    return f"sim.run.{run_id}"


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise SimulationRecordError(f"invalid timestamp {value!r} (ISO 8601 expected)") from None
    if parsed.tzinfo is None:
        raise SimulationRecordError("timestamps must include a timezone (e.g. ...Z)")
    return parsed


def build_run(
    store: StateStore,
    *,
    scenario: str,
    asset: str,
    status: str,
    run_id: str,
    description: str | None = None,
    expected_rules: Sequence[str] = (),
    operator: str | None = None,
    notes: Sequence[str] = (),
    started_at: str | None = None,
    now: datetime | None = None,
) -> SimulationRun:
    """Assemble and validate the SimulationRun for one lifecycle step."""
    try:
        sim_status = SimulationStatus(status)
    except ValueError:
        allowed = ", ".join(s.value for s in SimulationStatus)
        raise SimulationRecordError(f"invalid status {status!r} (one of {allowed})") from None
    now = now or utc_now()
    remembered: dict[str, Any] = store.kv_get(_kv_key(run_id)) or {}
    if remembered and (remembered.get("scenario") != scenario or remembered.get("asset") != asset):
        raise SimulationRecordError(
            f"run id {run_id} was started for {remembered.get('scenario')} on "
            f"{remembered.get('asset')}; refusing to reuse it for {scenario} on {asset}"
        )
    if started_at is not None:
        start = _parse_time(started_at)
    elif sim_status is SimulationStatus.STARTED:
        start = now
    elif remembered.get("started_at"):
        start = _parse_time(str(remembered["started_at"]))
    else:
        raise SimulationRecordError(
            f"no 'started' record is known locally for run {run_id}; pass --started-at"
        )
    try:
        run = SimulationRun(
            run_id=run_id,
            scenario_id=scenario,
            asset_id=asset,
            status=sim_status,
            started_at=start,
            finished_at=None if sim_status is SimulationStatus.STARTED else now,
            operator=operator or remembered.get("operator") or DEFAULT_OPERATOR,
            description=description
            or remembered.get("description")
            or f"{scenario} simulation on {asset}",
            expected_rule_ids=list(expected_rules or remembered.get("expected_rule_ids") or []),
            notes=list(notes),
        )
    except ValueError as exc:
        raise SimulationRecordError(f"invalid simulation record: {exc}") from None
    return run


def record_simulation(
    settings: Settings,
    *,
    client_factory: Callable[[], GatewayClient] | None = None,
    delivery_seconds: float = DELIVERY_SECONDS,
    **fields: Any,
) -> SimRecordResult:
    """Commit the record to the simulation-runner outbox, then try to deliver it."""
    store = StateStore(state_path(settings, STATE_ID))
    try:
        run = build_run(store, **fields)
        store.commit([to_record_json(run)])
        store.kv_set(
            _kv_key(run.run_id),
            {
                "scenario": run.scenario_id,
                "asset": run.asset_id,
                "started_at": iso_utc(run.started_at),
                "description": run.description,
                "expected_rule_ids": list(run.expected_rule_ids),
                "operator": run.operator,
                "last_status": run.status.value,
            },
        )
        client = client_factory() if client_factory else default_client(settings, PRODUCER_ID)
        try:
            sender = Sender(store, client, PRODUCER_ID)
            deadline = time.monotonic() + delivery_seconds
            report = sender.send_pending(deadline=deadline)
            while not report.drained and time.monotonic() < deadline:
                wait = max(0.0, sender.state.next_attempt_at - sender.clock())
                time.sleep(min(1.0, wait) if wait > 0 else 0.05)
                report = sender.send_pending(deadline=deadline)
        finally:
            client.close()
        return SimRecordResult(run=run, report=report, buffered=store.outbox_depth())
    finally:
        store.close()
