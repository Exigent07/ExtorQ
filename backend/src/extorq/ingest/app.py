"""Ingest gateway application (PLAN §5.1).

Endpoints:

* ``POST /v1/ingest``          IngestBatch JSON (gzip ok) -> 202 IngestResult
* ``POST /v1/otlp/v1/logs``    OTLP/HTTP JSON logs -> 200 (partialSuccess when records rejected)
* ``GET  /healthz``            no auth, body only ``{"status":"ok"}``
* ``GET  /v1/status``          bearer auth; spool depth and counters

Status codes: 401 bad/missing token, 403 producer/kind/source/asset not
authorized (written to ``ingest_audit`` through the spool), 409 batch_id
reused with different content, 413 body > 4 MiB (wire or decompressed) or
> 1000 records, 415 content type/encoding, 422 invalid envelope, 503 spool
full / unavailable (``Retry-After``). Per-record problems quarantine the
record and the batch continues. A 202 is sent only after the spool commit
(WAL, synchronous=FULL) returned.

Request bodies are never logged or echoed back; error details never contain
input values.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from extorq.common.config import Settings, get_settings
from extorq.common.logging import get_logger
from extorq.common.redaction import sanitize_untrusted
from extorq.contracts.common import SCHEMA_VERSION, HealthStatus, utc_now
from extorq.contracts.health import PipelineHealth
from extorq.contracts.identity import canonical_json, iso_utc, sha256_hex, stable_id
from extorq.contracts.ingest import (
    MAX_BATCH_RECORDS,
    MAX_BODY_BYTES,
    IngestBatch,
    IngestResult,
    QuarantineNotice,
)
from extorq.ingest.body import (
    BodyError,
    check_content_length,
    check_json_content_type,
    content_encoding,
    gunzip_limited,
    read_limited,
)
from extorq.ingest.processing import (
    Limits,
    PreparedBatch,
    QuarantineEntry,
    clean_reason,
    make_excerpt,
    prepare_batch,
    quarantine_id,
    summarize_validation_error,
)
from extorq.ingest.registry import ProducerEntry, ProducerRegistry
from extorq.pipeline.spool import NewRecord, Spool, SpoolUnavailable

log = get_logger("extorq.ingest")

OTLP_LOGS_PATH = "/v1/otlp/v1/logs"
INGEST_PATH = "/v1/ingest"
BODY_READ_TIMEOUT_SECONDS = 30.0
RETRY_AFTER_FULL = "30"
RETRY_AFTER_UNAVAILABLE = "10"
NORMALIZER_MODULE = "extorq.ingest.otlp_k8s"
MAX_TOKEN_LENGTH = 512
#: Contract versions accepted on the wire (1.1 is additive over 1.0; contracts enforce it).
ACCEPTED_SCHEMA_VERSIONS = ("1.0", "1.1")

Normalizer = Callable[..., tuple[list[Any], list[tuple[int, str]]]]


class Reject(Exception):
    """Control-flow signal carrying an HTTP status (not an error condition)."""

    def __init__(
        self,
        status_code: int,
        detail: str,
        *,
        headers: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.headers = headers or {}
        self.extra = extra or {}


def _json(
    status_code: int, body: dict[str, Any], headers: dict[str, str] | None = None
) -> JSONResponse:
    merged = {"Cache-Control": "no-store"}
    merged.update(headers or {})
    return JSONResponse(body, status_code=status_code, headers=merged)


def default_normalizer_loader() -> Normalizer | None:
    """Lazily import B2's OTLP normaliser; ``None`` while the module does not exist."""
    try:
        module = importlib.import_module(NORMALIZER_MODULE)
    except ModuleNotFoundError as exc:
        if exc.name == NORMALIZER_MODULE:
            return None
        raise
    function = getattr(module, "normalize_otlp_logs", None)
    return function if callable(function) else None


@dataclass
class _AuditLimiter:
    """Fixed-window limiter for audit rows of unauthenticated requests (anti-flood)."""

    per_minute: int
    window_start: float = 0.0
    used: int = 0
    suppressed: int = 0

    def allow(self, now: float) -> bool:
        if now - self.window_start >= 60:
            self.window_start, self.used = now, 0
        if self.used < self.per_minute:
            self.used += 1
            return True
        self.suppressed += 1
        return False


class Gateway:
    """State shared by the gateway endpoints."""

    def __init__(
        self,
        settings: Settings,
        spool: Spool,
        registry: ProducerRegistry,
        normalizer_loader: Callable[[], Normalizer | None] = default_normalizer_loader,
    ) -> None:
        self.settings = settings
        self.spool = spool
        self.registry = registry
        self.normalizer_loader = normalizer_loader
        self.limits = Limits(
            max_future=timedelta(seconds=settings.event_max_future_seconds),
            retention=timedelta(days=settings.event_retention_days),
        )
        self.audit_limiter = _AuditLimiter(settings.unauthenticated_audit_per_minute)
        self._lock = threading.Lock()
        self.started_at = utc_now()

    # ── audit ─────────────────────────────────────────────────────────

    def audit_record(
        self,
        *,
        request: Request,
        decision: str,
        reason: str,
        claimed: str | None,
        authenticated: str | None,
    ) -> NewRecord:
        occurred = utc_now()
        audit_id = uuid.uuid4().hex
        remote = request.client.host if request.client else None
        row = {
            "audit_id": audit_id,
            "occurred_at": iso_utc(occurred),
            "remote_addr": sanitize_untrusted(remote, 64) if remote else None,
            "claimed_producer": sanitize_untrusted(claimed, 128) if claimed else None,
            "authenticated_producer": authenticated,
            "decision": decision,
            "reason": clean_reason(reason, 1024),
            "path": sanitize_untrusted(request.url.path, 256),
        }
        return NewRecord(
            kind="ingest_audit", record_key=audit_id, payload=canonical_json(row), dedup=False
        )

    async def write_audit(self, record: NewRecord, *, status_code: int) -> None:
        try:
            await run_in_threadpool(
                self.spool.append,
                [record],
                producer_id="gateway",
                batch_id="audit",
                ingested_at=iso_utc(utc_now()),
                counters={"rejected_total": 1, f"rejected_{status_code}_total": 1},
            )
        except SpoolUnavailable:
            log.error("audit_write_failed", status_code=status_code)

    async def count_rejection(self, status_code: int) -> None:
        try:
            await run_in_threadpool(
                self.spool.incr, {"rejected_total": 1, f"rejected_{status_code}_total": 1}
            )
        except SpoolUnavailable:
            log.error("counter_write_failed", status_code=status_code)

    # ── request steps ─────────────────────────────────────────────────

    async def authenticate(self, request: Request) -> ProducerEntry:
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        token = token.strip()
        producer = None
        if scheme.lower() == "bearer" and 0 < len(token) <= MAX_TOKEN_LENGTH:
            producer = self.registry.authenticate(token)
        if producer is None:
            reason = "missing_bearer_token" if not header else "invalid_bearer_token"
            if self.audit_limiter.allow(time.monotonic()):
                record = self.audit_record(
                    request=request,
                    decision="unauthenticated",
                    reason=reason,
                    claimed=None,
                    authenticated=None,
                )
                await self.write_audit(record, status_code=401)
            else:
                await self.count_rejection(401)
            log.warning("ingest_unauthenticated", reason=reason, path=request.url.path)
            raise Reject(
                401,
                "authentication required",
                headers={"WWW-Authenticate": 'Bearer realm="extorq-ingest"'},
            )
        return producer

    async def ensure_capacity(self) -> None:
        try:
            depth = await run_in_threadpool(self.spool.depth)
            free = await run_in_threadpool(self.spool.free_bytes)
        except Exception:  # any spool failure means "unavailable" (logged with traceback)
            log.exception("spool_capacity_check_failed")
            raise Reject(
                503, "spool unavailable", headers={"Retry-After": RETRY_AFTER_UNAVAILABLE}
            ) from None
        if depth >= self.settings.spool_max_records:
            log.warning("spool_full", depth=depth, max_records=self.settings.spool_max_records)
            raise Reject(503, "spool full, retry later", headers={"Retry-After": RETRY_AFTER_FULL})
        if free < self.settings.spool_min_free_bytes:
            log.error("spool_disk_low", free_bytes=free)
            raise Reject(
                503, "spool disk space low, retry later", headers={"Retry-After": RETRY_AFTER_FULL}
            )

    async def read_body(self, request: Request) -> bytes:
        check_content_length(request.headers.get("content-length"), MAX_BODY_BYTES)
        encoding = content_encoding(request.headers.get("content-encoding"))
        try:
            raw = await asyncio.wait_for(
                read_limited(request.stream(), MAX_BODY_BYTES), timeout=BODY_READ_TIMEOUT_SECONDS
            )
        except TimeoutError:
            raise Reject(408, "request body not received in time") from None
        if encoding == "gzip":
            return await run_in_threadpool(gunzip_limited, raw, MAX_BODY_BYTES)
        return raw

    async def deny(
        self, request: Request, producer: ProducerEntry, *, claimed: str | None, reasons: list[str]
    ) -> Reject:
        record = self.audit_record(
            request=request,
            decision="forbidden",
            reason="; ".join(reasons),
            claimed=claimed,
            authenticated=producer.producer_id,
        )
        await self.write_audit(record, status_code=403)
        log.warning("ingest_forbidden", producer_id=producer.producer_id, reasons=reasons)
        return Reject(403, "records not authorized for this producer", extra={"denied": reasons})

    # ── spool commit ──────────────────────────────────────────────────

    def _quarantine_records(
        self, producer_id: str, batch_id: str, received: datetime, entries: list[QuarantineEntry]
    ) -> list[NewRecord]:
        records = []
        for entry in entries:
            qid = quarantine_id(producer_id, batch_id, entry.index, entry.payload_sha256)
            row = {
                "quarantine_id": qid,
                "received_at": iso_utc(received),
                "producer_id": producer_id,
                "batch_id": batch_id,
                "record_index": entry.index,
                "record_kind": entry.kind,
                "reason": entry.reason,
                "payload_excerpt": entry.excerpt,
                "payload_sha256": entry.payload_sha256,
            }
            records.append(
                NewRecord(
                    kind="quarantine", record_key=qid, payload=canonical_json(row), dedup=False
                )
            )
        return records

    def commit(
        self,
        *,
        producer: ProducerEntry,
        batch_id: str,
        content_sha256: str,
        received: datetime,
        prepared: PreparedBatch,
    ) -> tuple[dict[str, Any], bool, bool]:
        """Commit a prepared batch; return (result, replayed, conflict)."""
        quarantined = prepared.quarantined
        notices = [QuarantineNotice(index=q.index, reason=q.reason) for q in quarantined]

        def build_result(accepted: int, duplicates: int) -> dict[str, Any]:
            return IngestResult(
                batch_id=batch_id,
                accepted=accepted,
                duplicates=duplicates,
                rejected=len(quarantined),
                quarantined=notices,
                replayed=False,
            ).model_dump(mode="json")

        outcome = self.spool.commit_batch(
            producer_id=producer.producer_id,
            batch_id=batch_id,
            content_sha256=content_sha256,
            ingested_at=iso_utc(received),
            records=[
                NewRecord(kind=c.kind, record_key=c.record_key, payload=c.payload)
                for c in prepared.candidates
            ],
            extra=self._quarantine_records(producer.producer_id, batch_id, received, quarantined),
            build_result=build_result,
            counters={
                "quarantined_total": len(quarantined),
                "redactions_total": prepared.redactions,
                "batches_total": 1,
            },
        )
        return outcome.result, outcome.replayed, outcome.conflict

    # ── health ────────────────────────────────────────────────────────

    def health_record(self) -> NewRecord:
        counters = self.spool.counters()
        depth = self.spool.depth(max_age_seconds=0)
        free = self.spool.free_bytes()
        status = HealthStatus.OK
        if (
            depth >= 0.8 * self.settings.spool_max_records
            or free < 2 * self.settings.spool_min_free_bytes
        ):
            status = HealthStatus.DEGRADED
        if depth >= self.settings.spool_max_records or free < self.settings.spool_min_free_bytes:
            status = HealthStatus.FAILED
        now = utc_now()
        health = PipelineHealth(
            component="ingest",
            instance=self.settings.instance_name[:256],
            reported_at=now,
            status=status,
            queue_depth=depth,
            oldest_queued_age_seconds=self.spool.oldest_age_seconds(),
            accepted_total=counters.get("accepted_total", 0),
            duplicate_total=counters.get("duplicate_total", 0),
            rejected_total=counters.get("rejected_total", 0),
            quarantined_total=counters.get("quarantined_total", 0),
            details={
                "rejected_unit": "requests",
                "rejected_401_total": counters.get("rejected_401_total", 0),
                "rejected_403_total": counters.get("rejected_403_total", 0),
                "redactions_total": counters.get("redactions_total", 0),
                "replayed_batches_total": counters.get("replayed_batches_total", 0),
                "batches_total": counters.get("batches_total", 0),
                "spool_free_bytes": free,
                "spool_max_records": self.settings.spool_max_records,
                "audit_suppressed": self.audit_limiter.suppressed,
            },
        )
        key = stable_id("health.v1", "ingest", health.instance, iso_utc(now))
        return NewRecord(
            kind="pipeline_health", record_key=key, payload=canonical_json(health), dedup=False
        )

    def emit_health(self) -> None:
        record = self.health_record()
        self.spool.append(
            [record], producer_id="gateway", batch_id="health", ingested_at=iso_utc(utc_now())
        )

    def maintenance(self) -> None:
        horizon = time.time() - self.settings.dedup_retention_hours * 3600
        pruned = self.spool.prune(dedup_older_than=horizon, batches_older_than=horizon)
        self.spool.checkpoint()
        if any(pruned):
            log.info("spool_pruned", dedup=pruned[0], batches=pruned[1])


# ── application factory ───────────────────────────────────────────────


def _parse_envelope(body: bytes) -> IngestBatch:
    """Strict JSON (no NaN/Infinity tokens, F-IC-1) then strict envelope validation."""
    try:
        document = _strict_json_loads(body)
    except (ValueError, RecursionError):
        raise Reject(
            400, "body is not valid JSON (NaN/Infinity and malformed input are rejected)"
        ) from None
    try:
        return IngestBatch.model_validate(document)
    except ValidationError as exc:
        for err in exc.errors(include_url=False, include_input=False, include_context=False):
            if tuple(err.get("loc", ())) == ("records",) and err.get("type") == "too_long":
                raise Reject(413, f"batch exceeds {MAX_BATCH_RECORDS} records") from None
        raise Reject(
            422, "invalid batch envelope", extra={"errors": summarize_validation_error(exc)}
        ) from None


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def _strict_json_loads(body: bytes) -> Any:
    """json.loads that refuses NaN/Infinity (not valid JSON; breaks canonical identities)."""
    return json.loads(body, parse_constant=_reject_constant)


def records_digest(records: list[Any]) -> str:
    """Content hash of a batch's records (robust to values canonical_json refuses)."""
    try:
        text = canonical_json(records)
    except (TypeError, ValueError):
        text = json.dumps(records, sort_keys=True, default=str, allow_nan=True)
    return sha256_hex(text.encode("utf-8", "surrogatepass"))


def _event_record(event: Any) -> Any:
    """IngestRecord JSON for one normalised event; anything unexpected is quarantined later."""
    try:
        return {"kind": "event", "data": event.model_dump(mode="json")}
    except Exception as exc:  # noqa: BLE001 - normaliser bug: keep a trace, never a 500
        return {"kind": "event", "normalizer_output_error": type(exc).__name__}


def _otlp_log_records(payload: dict[str, Any]) -> list[Any]:
    """Flatten resourceLogs[].scopeLogs[].logRecords[] (used for quarantine excerpts)."""
    flat: list[Any] = []
    resource_logs = payload.get("resourceLogs")
    if not isinstance(resource_logs, list):
        return flat
    for resource_log in resource_logs:
        scope_logs = resource_log.get("scopeLogs") if isinstance(resource_log, dict) else None
        if not isinstance(scope_logs, list):
            continue
        for scope_log in scope_logs:
            records = scope_log.get("logRecords") if isinstance(scope_log, dict) else None
            if isinstance(records, list):
                flat.extend(records)
    return flat


def create_app(
    settings: Settings | None = None,
    *,
    spool: Spool | None = None,
    registry: ProducerRegistry | None = None,
    normalizer_loader: Callable[[], Normalizer | None] | None = None,
    background_tasks: bool = True,
) -> FastAPI:
    cfg = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
        gw_spool = spool or Spool(
            cfg.resolve(cfg.spool_path), busy_timeout_ms=cfg.spool_busy_timeout_ms
        )
        gw_registry = registry or ProducerRegistry(cfg.resolve(cfg.producers_file))
        gateway = Gateway(
            cfg, gw_spool, gw_registry, normalizer_loader or default_normalizer_loader
        )
        app.state.gateway = gateway
        task = asyncio.create_task(_background(gateway)) if background_tasks else None
        log.info(
            "gateway_started",
            producers=len(gw_registry.producer_ids),
            spool_max_records=cfg.spool_max_records,
        )
        try:
            yield
        finally:
            if task is not None:
                task.cancel()
            if spool is None:
                gw_spool.close()

    app = FastAPI(
        title="ExtorQ ingest gateway",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.exception_handler(Reject)
    async def _reject_handler(_request: Request, exc: Reject) -> JSONResponse:
        return _json(exc.status_code, {"detail": exc.detail, **exc.extra}, exc.headers)

    @app.exception_handler(BodyError)
    async def _body_handler(_request: Request, exc: BodyError) -> JSONResponse:
        return _json(exc.status_code, {"detail": exc.detail})

    @app.exception_handler(Exception)
    async def _unhandled(_request: Request, exc: Exception) -> JSONResponse:
        log.error("gateway_unhandled_error", error_type=type(exc).__name__, exc_info=exc)
        return _json(500, {"detail": "internal error"})

    @app.get("/healthz")
    async def healthz(request: Request) -> JSONResponse:
        gateway: Gateway = request.app.state.gateway
        healthy = await run_in_threadpool(gateway.spool.healthy)
        if not healthy:
            return _json(503, {"status": "unavailable"})
        return _json(200, {"status": "ok"})

    @app.get("/v1/status")
    async def status(request: Request) -> JSONResponse:
        gateway: Gateway = request.app.state.gateway
        producer = await gateway.authenticate(request)
        counters = await run_in_threadpool(gateway.spool.counters)
        depth = await run_in_threadpool(gateway.spool.depth, 0)
        oldest = await run_in_threadpool(gateway.spool.oldest_age_seconds)
        dead = await run_in_threadpool(gateway.spool.dead_letter_count)
        return _json(
            200,
            {
                "producer_id": producer.producer_id,
                "schema_version": SCHEMA_VERSION,
                "accepted_schema_versions": list(ACCEPTED_SCHEMA_VERSIONS),
                "spool": {
                    "depth": depth,
                    "max_records": gateway.settings.spool_max_records,
                    "oldest_age_seconds": oldest,
                    "dead_letter": dead,
                },
                "counters": counters,
                "limits": {
                    "max_body_bytes": MAX_BODY_BYTES,
                    "max_batch_records": MAX_BATCH_RECORDS,
                    "max_future_seconds": int(gateway.limits.max_future.total_seconds()),
                    "event_retention_days": gateway.settings.event_retention_days,
                },
                "otlp_normalizer_available": gateway.normalizer_loader() is not None,
            },
        )

    @app.post(INGEST_PATH)
    async def ingest(request: Request) -> JSONResponse:
        gateway: Gateway = request.app.state.gateway
        started = time.monotonic()
        producer = await gateway.authenticate(request)
        check_json_content_type(request.headers.get("content-type"))
        await gateway.ensure_capacity()
        body = await gateway.read_body(request)
        batch = await run_in_threadpool(_parse_envelope, body)
        if batch.producer_id != producer.producer_id:
            raise await gateway.deny(
                request, producer, claimed=batch.producer_id, reasons=["producer_id_mismatch"]
            )
        content_sha256 = await run_in_threadpool(records_digest, batch.records)
        existing = await run_in_threadpool(
            gateway.spool.lookup_batch, producer.producer_id, batch.batch_id
        )
        if existing is not None:
            return _replay_response(existing, content_sha256, batch.batch_id, producer)
        received = utc_now()
        prepared = await run_in_threadpool(
            prepare_batch,
            batch.records,
            producer,
            batch_id=batch.batch_id,
            now=received,
            limits=gateway.limits,
        )
        if prepared.denied:
            raise await gateway.deny(
                request, producer, claimed=batch.producer_id, reasons=prepared.denials
            )
        try:
            result, replayed, conflict = await run_in_threadpool(
                gateway.commit,
                producer=producer,
                batch_id=batch.batch_id,
                content_sha256=content_sha256,
                received=received,
                prepared=prepared,
            )
        except SpoolUnavailable:
            log.exception("spool_commit_failed", producer_id=producer.producer_id)
            raise Reject(
                503, "spool unavailable", headers={"Retry-After": RETRY_AFTER_UNAVAILABLE}
            ) from None
        if conflict:
            raise Reject(409, "batch_id already used with different content")
        result["replayed"] = replayed
        log.info(
            "ingest_batch",
            producer_id=producer.producer_id,
            batch_id=batch.batch_id,
            records=len(batch.records),
            accepted=result["accepted"],
            duplicates=result["duplicates"],
            quarantined=len(prepared.quarantined),
            redactions=prepared.redactions,
            replayed=replayed,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return _json(202, result)

    @app.post(OTLP_LOGS_PATH)
    async def otlp_logs(request: Request) -> JSONResponse:
        gateway: Gateway = request.app.state.gateway
        started = time.monotonic()
        producer = await gateway.authenticate(request)
        media_type = (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        if media_type == "application/x-protobuf":
            raise Reject(415, "only OTLP/HTTP JSON is supported (set encoding: json)")
        check_json_content_type(request.headers.get("content-type"))
        normalizer = gateway.normalizer_loader()
        if normalizer is None:
            raise Reject(
                503,
                f"OTLP normaliser not available yet ({NORMALIZER_MODULE} missing)",
                headers={"Retry-After": "60"},
            )
        await gateway.ensure_capacity()
        body = await gateway.read_body(request)
        try:
            payload = await run_in_threadpool(_strict_json_loads, body)
        except (ValueError, RecursionError):
            raise Reject(400, "body is not valid JSON") from None
        if not isinstance(payload, dict):
            raise Reject(400, "OTLP payload must be a JSON object")
        body_sha256 = sha256_hex(body)
        batch_id = sha256_hex(f"otlp\x1f{producer.producer_id}\x1f{body_sha256}")[:32]
        existing = await run_in_threadpool(
            gateway.spool.lookup_batch, producer.producer_id, batch_id
        )
        if existing is not None:
            return _otlp_response(existing[1])
        received = utc_now()
        log_records = _otlp_log_records(payload)
        try:
            events, errors = await run_in_threadpool(
                normalizer, payload, producer_id=producer.producer_id, received_at=received
            )
        except Exception as exc:  # noqa: BLE001 - normaliser bug: keep evidence, do not loop
            log.error(
                "otlp_normalizer_failed",
                producer_id=producer.producer_id,
                error_type=type(exc).__name__,
            )
            events = []
            errors = [(0, f"normalizer_error:{type(exc).__name__}")]
            log_records = [payload]
        raw_records = [_event_record(e) for e in events]
        prepared = await run_in_threadpool(
            prepare_batch,
            raw_records,
            producer,
            batch_id=batch_id,
            now=received,
            limits=gateway.limits,
        )
        if prepared.denied:
            raise await gateway.deny(request, producer, claimed=None, reasons=prepared.denials)
        for index, reason in errors:
            source = log_records[index] if 0 <= index < len(log_records) else None
            excerpt, digest = make_excerpt(source)
            prepared.quarantined.append(
                QuarantineEntry(
                    index=index,
                    kind="event",
                    reason=clean_reason(f"otlp_log_record: {reason}"),
                    excerpt=excerpt,
                    payload_sha256=digest,
                )
            )
        try:
            result, _replayed, _conflict = await run_in_threadpool(
                gateway.commit,
                producer=producer,
                batch_id=batch_id,
                content_sha256=body_sha256,
                received=received,
                prepared=prepared,
            )
        except SpoolUnavailable:
            log.exception("spool_commit_failed", producer_id=producer.producer_id)
            raise Reject(
                503, "spool unavailable", headers={"Retry-After": RETRY_AFTER_UNAVAILABLE}
            ) from None
        log.info(
            "otlp_batch",
            producer_id=producer.producer_id,
            batch_id=batch_id,
            log_records=len(log_records),
            events=len(events),
            accepted=result["accepted"],
            duplicates=result["duplicates"],
            quarantined=len(prepared.quarantined),
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return _otlp_response(result)

    return app


def _replay_response(
    existing: tuple[str, dict[str, Any]],
    content_sha256: str,
    batch_id: str,
    producer: ProducerEntry,
) -> JSONResponse:
    stored_sha, stored = existing
    if stored_sha != content_sha256:
        log.warning("batch_id_conflict", producer_id=producer.producer_id, batch_id=batch_id)
        raise Reject(409, "batch_id already used with different content")
    stored["replayed"] = True
    log.info("ingest_batch_replayed", producer_id=producer.producer_id, batch_id=batch_id)
    return _json(202, stored)


def _otlp_response(result: dict[str, Any]) -> JSONResponse:
    rejected = int(result.get("rejected", 0))
    if rejected:
        reasons = "; ".join(q.get("reason", "") for q in result.get("quarantined", [])[:3])
        return _json(
            200,
            {"partialSuccess": {"rejectedLogRecords": rejected, "errorMessage": reasons[:1000]}},
        )
    return _json(200, {})


async def _background(gateway: Gateway) -> None:
    """Emit ingest PipelineHealth every interval and run spool maintenance."""
    last_maintenance = 0.0
    while True:
        try:
            await run_in_threadpool(gateway.emit_health)
            if time.monotonic() - last_maintenance > 600:
                await run_in_threadpool(gateway.maintenance)
                last_maintenance = time.monotonic()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - keep the loop alive; visible in logs
            log.error("gateway_background_failed", error_type=type(exc).__name__)
        await asyncio.sleep(gateway.settings.health_interval_seconds)
