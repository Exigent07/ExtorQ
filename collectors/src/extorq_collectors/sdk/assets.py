"""Asset upsert helper for collectors.

Collectors report the asset they observe (host, cluster, node, repository) as an
:class:`~extorq.contracts.asset.Asset` record. Sending it every cycle would be
noise; never sending it again would let ``last_seen`` go stale. ``asset_upsert``
returns an Asset only when

* its descriptive content changed since the last *committed* upsert, or
* ``refresh_seconds`` elapsed (so ``last_seen`` keeps moving while observed).

The "last sent" state is a snapshot staged with ``ctx.diff_snapshot`` and is
therefore committed in the SAME SQLite transaction as the ``emit`` that carries
the Asset record: a crash in between re-sends it instead of silently skipping it.
``first_seen`` is remembered in the collector's KV state (earliest observation).

Usage::

    asset = asset_upsert(ctx, asset_type="linux_host", name="lab-vm-01",
                         attributes={"os_name": "Ubuntu", "os_version": "24.04"})
    ctx.emit([*events, *([asset] if asset else [])], {"cursor": cursor})

or ``asset_upsert(..., emit=True)`` to emit it on its own.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from extorq.contracts.asset import Asset
from extorq.contracts.common import AssetType, Criticality, Environment
from extorq.contracts.identity import iso_utc
from extorq_collectors.sdk.base import CollectorContext

DEFAULT_REFRESH_SECONDS = 900


def _first_seen(ctx: CollectorContext, asset_id: str, now: datetime) -> datetime:
    key = f"asset.first_seen.{asset_id}"
    stored = ctx.state.get(key)
    if isinstance(stored, str):
        try:
            return datetime.fromisoformat(stored.replace("Z", "+00:00"))
        except ValueError:
            pass
    ctx.state.set(key, iso_utc(now))
    return now


def asset_upsert(
    ctx: CollectorContext,
    *,
    asset_type: AssetType | str,
    name: str,
    asset_id: str | None = None,
    display_name: str | None = None,
    parent_asset_id: str | None = None,
    environment: Environment | str = Environment.LAB,
    criticality: Criticality | str = Criticality.MEDIUM,
    owner: str | None = None,
    labels: Mapping[str, str] | None = None,
    attributes: Mapping[str, Any] | None = None,
    refresh_seconds: int = DEFAULT_REFRESH_SECONDS,
    emit: bool = False,
) -> Asset | None:
    """Return an Asset record when it must be (re)sent, else ``None`` (see module docs)."""
    if refresh_seconds < 60:
        raise ValueError("refresh_seconds must be at least 60")
    target = asset_id or ctx.asset_id
    now = ctx.now()
    candidate = Asset(
        asset_id=target,
        asset_type=AssetType(asset_type),
        name=name,
        display_name=display_name,
        parent_asset_id=parent_asset_id,
        environment=Environment(environment),
        criticality=Criticality(criticality),
        owner=owner,
        labels=dict(labels or {}),
        attributes=dict(attributes or {}),
        first_seen=now,
        last_seen=now,
        observed_by=ctx.collector_id,
    )
    content = candidate.model_dump(mode="json", exclude={"first_seen", "last_seen"})
    content["refresh_bucket"] = int(now.timestamp()) // refresh_seconds
    diff = ctx.diff_snapshot(f"asset:{target}", {target: content})
    if not (diff.added or diff.changed):
        return None
    asset = candidate.model_copy(update={"first_seen": _first_seen(ctx, target, now)})
    if emit:
        ctx.emit([asset])
    return asset
