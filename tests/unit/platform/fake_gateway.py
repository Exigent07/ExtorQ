"""In-process fake of the ingest gateway for SDK unit tests (no network, no TLS).

It implements the parts of PLAN §5.1 the SDK relies on: 202 IngestResult with
``replayed`` for a repeated batch_id, scripted failures (503 + Retry-After, 401,
connection errors after processing = "lost 202"), and per-record 403 denial.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from extorq_collectors.sdk.client import GatewayClient


@dataclass
class FakeGateway:
    #: Responses to use for the next requests, consumed in order:
    #: ("status", code, headers) or ("lost",) to process then drop the response.
    script: list[tuple[Any, ...]] = field(default_factory=list)
    #: Return a denial reason for a record to 403 the whole batch.
    deny: Callable[[dict[str, Any]], str | None] | None = None
    batches: list[dict[str, Any]] = field(default_factory=list)
    accepted_records: list[dict[str, Any]] = field(default_factory=list)
    results: dict[str, dict[str, Any]] = field(default_factory=dict)
    seen_keys: set[str] = field(default_factory=set)
    requests: int = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        assert request.headers["authorization"].startswith("Bearer ")
        body = request.content
        if request.headers.get("content-encoding") == "gzip":
            body = gzip.decompress(body)
        batch = json.loads(body)
        step = self.script.pop(0) if self.script else ("ok",)
        if step[0] == "status":
            return httpx.Response(
                step[1],
                headers=step[2] if len(step) > 2 else {},
                json={"detail": f"scripted {step[1]}"},
            )
        if self.deny is not None:
            reasons = [r for r in (self.deny(rec) for rec in batch["records"]) if r]
            if reasons:
                return httpx.Response(
                    403, json={"detail": "records not authorized", "denied": reasons}
                )
        result = self._process(batch)
        if step[0] == "lost":
            raise httpx.ConnectError("connection reset after processing (scripted)")
        return httpx.Response(202, json=result)

    def _process(self, batch: dict[str, Any]) -> dict[str, Any]:
        batch_id = batch["batch_id"]
        if batch_id in self.results:
            return {**self.results[batch_id], "replayed": True}
        self.batches.append(batch)
        accepted = duplicates = 0
        for rec in batch["records"]:
            key = json.dumps(rec, sort_keys=True)
            if key in self.seen_keys:
                duplicates += 1
                continue
            self.seen_keys.add(key)
            self.accepted_records.append(rec)
            accepted += 1
        result = {
            "batch_id": batch_id,
            "accepted": accepted,
            "duplicates": duplicates,
            "rejected": 0,
            "quarantined": [],
            "replayed": False,
        }
        self.results[batch_id] = result
        return result

    def client(self) -> GatewayClient:
        return GatewayClient(
            "https://gateway.test",
            "synthetic-token",
            "/nonexistent-ca.crt",
            transport=httpx.MockTransport(self.handler),
        )

    def kinds(self) -> list[str]:
        return [r["kind"] for r in self.accepted_records]
