"""Offline migration of historical ClickHouse event receipts into the gateway spool."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from datetime import timedelta
from itertools import batched
from typing import Any

from extorq.common.config import get_settings
from extorq.contracts.common import utc_now
from extorq.ingest.event_identity import EventReceipt, historical_receipt
from extorq.pipeline.spool import Spool
from extorq.storage.clickhouse import get_client

_EVENTS_SQL = """\
SELECT producer_id, event_id, payload
FROM extorq.events FINAL
WHERE event_time >= {since:DateTime64(3, 'UTC')}
ORDER BY asset_id, event_type, event_time, event_id
"""


def seed(
    spool: Spool, rows: Iterable[tuple[Any, ...]], horizon: timedelta, counts: dict[str, int]
) -> None:
    for page in batched(rows, 512):
        receipts: list[EventReceipt] = []
        unmappable = 0
        for producer_id, event_id, payload in page:
            try:
                data = json.loads(payload)
            except (TypeError, ValueError, RecursionError):
                data = None
            receipt = (
                historical_receipt(producer_id, event_id, data, horizon=horizon)
                if isinstance(data, dict)
                else None
            )
            if receipt is None:
                unmappable += 1
            else:
                receipts.append(receipt)
        for name, count in spool.seed_event_identities(receipts).items():
            counts[name] += count
        counts["unmappable"] += unmappable


def main(*, confirm: bool) -> int:
    if not confirm:
        print("Pause ingestion and writing, verify the backup, then pass --yes.", file=sys.stderr)
        return 2
    settings = get_settings()
    if not settings.spool_path.is_file():
        print("Spool database does not exist at the configured path.", file=sys.stderr)
        return 2
    horizon = timedelta(
        days=settings.event_retention_days, seconds=settings.event_max_future_seconds
    )
    counts = dict.fromkeys(("accepted", "duplicate", "conflict", "unmappable", "expired"), 0)
    try:
        spool = Spool(settings.spool_path)
        try:
            client = get_client("api_ro", settings=settings)
            try:
                with client.query_rows_stream(
                    _EVENTS_SQL, parameters={"since": utc_now() - horizon}
                ) as rows:
                    seed(spool, rows, horizon, counts)
            finally:
                client.close()
        finally:
            spool.close()
    except Exception as exc:  # noqa: BLE001 - print the class only; DB errors can carry data
        print(
            f"Identity seed interrupted ({type(exc).__name__}). Retry with services paused.",
            file=sys.stderr,
        )
        print(json.dumps(counts, sort_keys=True))
        return 1
    print(json.dumps(counts, sort_keys=True))
    return 0
