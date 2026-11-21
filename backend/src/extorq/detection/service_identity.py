"""Service-identity checks for consumers of service attribution (F-IC-6).

Service ids are deterministic hashes of public facts
(``identity.service_id(asset_id, service_kind, service_key)``), so a compromised or
buggy producer could send a ``Service`` record or an event ``ServiceRef`` that reuses
another asset's service id ("shadowing"). Detection and correlation therefore:

* trust a ``services`` row only if its id recomputes from its own
  ``(asset_id, service_kind, service_key)``;
* accept an event's service reference unless the only valid records for that id belong
  to assets unrelated to the event's asset (another host). A reference with no record
  yet (discovery lag) cannot shadow a real service and is kept.

Related assets: identical, or one is the parent of the other (Kubernetes cluster
``k8s:<cluster>`` and its nodes ``k8s:<cluster>/node/<name>``).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from extorq.contracts.identity import service_id as make_service_id

SERVICE_ROWS_SQL = (
    "SELECT service_id, asset_id, service_kind, service_key FROM services "
    "WHERE service_id IN {ids:Array(String)} "
    "GROUP BY service_id, asset_id, service_kind, service_key LIMIT 10000"
)


def assets_related(a: str, b: str) -> bool:
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def valid_service_assets(rows: Iterable[Mapping[str, Any]]) -> dict[str, set[str]]:
    """``{service_id: {asset ids of rows whose id recomputes correctly}}``."""
    valid: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        sid = str(row.get("service_id") or "")
        asset = str(row.get("asset_id") or "")
        kind = str(row.get("service_kind") or "")
        key = str(row.get("service_key") or "")
        if sid and asset and make_service_id(asset, kind, key) == sid:
            valid[sid].add(asset)
    return dict(valid)


def reference_allowed(service_id: str, event_asset: str, valid: Mapping[str, set[str]]) -> bool:
    """False only when valid records exist for the id and none is on a related asset."""
    assets = valid.get(service_id)
    if not assets:
        return True
    return any(assets_related(event_asset, asset) for asset in assets)
