"""Project allow-listed Collector self-observations into node delivery health."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from extorq.contracts.catalog import SourceType
from extorq.contracts.common import AttributeValue, HealthStatus
from extorq.contracts.event import SecurityEvent
from extorq.contracts.health import CollectorHealth
from extorq.contracts.identity import stable_id
from extorq.ingest.otlp_k8s import ASSET_ID, CLUSTER_NAME, node_asset_id

PRODUCER_ID = "k8s-otel-extorq-lab"
COLLECTOR_PREFIX = "k8s-otel-health-"
INTERVAL = 30
FRESHNESS = timedelta(seconds=3 * INTERVAL)
_CLOCK_TOLERANCE = timedelta(seconds=15)
MAX_HEALTH_BYTES = 64 * 1024
_UINT32_MAX = 2**32 - 1
_MAX_CACHED_DELIVERIES = 256
_EXPORTER = "otlp_http/extorq"
_RECEIVERS = {
    SourceType.K8S_AUDIT: "file_log/audit",
    SourceType.K8S_CONTAINER_LOG: "file_log/containers",
}
_METRICS = {
    "exporter_queue_size": "queue_requests",
    "exporter_queue_capacity": "queue_capacity_requests",
    "exporter_sent_log_records": "sent_records",
    "exporter_send_failed_log_records": "send_failed_records",
    "exporter_enqueue_failed_log_records": "enqueue_failed_records",
    "receiver_accepted_log_records": "accepted_records",
    "receiver_refused_log_records": "refused_records",
}


def _as_mapping(raw: Any) -> dict[str, Any]:
    return raw if isinstance(raw, dict) else {}


def _as_list(raw: Any) -> list[Any]:
    return raw if isinstance(raw, list) else []


def _attributes(raw: Any) -> dict[str, Any]:
    attributes: dict[str, Any] = {}
    for item in _as_list(raw):
        pair = _as_mapping(item)
        key, value = pair.get("key"), _as_mapping(pair.get("value"))
        if isinstance(key, str) and len(value) == 1:
            attributes[key] = next(iter(value.values()))
    return attributes


def _resource_asset(envelope: Any) -> str | None:
    resource = _as_mapping(_as_mapping(envelope).get("resource"))
    attrs = _attributes(resource.get("attributes"))
    if attrs.get("k8s.cluster.name") == CLUSTER_NAME:
        return node_asset_id(attrs.get("k8s.node.name"))
    return None


def _counter(value: Any) -> int | None:
    if isinstance(value, str) and len(value) <= 16 and value.isascii() and value.isdecimal():
        value = int(value)
    if type(value) in {float, int} and 0 <= value <= 2**53 - 1 and int(value) == value:
        return int(value)
    return None


def _timestamp(raw: Any, now: datetime) -> datetime | None:
    if isinstance(raw, str) and len(raw) <= 20 and raw.isascii() and raw.isdecimal():
        raw = int(raw)
    if type(raw) is not int or raw <= 0:
        return None
    try:
        timestamp = datetime.fromtimestamp((raw // 1_000_000) / 1000, UTC)
    except (OverflowError, OSError, ValueError):
        return None
    if now - FRESHNESS <= timestamp <= now + _CLOCK_TOLERANCE:
        return timestamp
    return None


@dataclass(frozen=True)
class HealthObservation:
    asset_id: str
    observed_at: datetime
    node_metrics: dict[str, int]
    receiver_metrics: dict[str, dict[str, int]]


def parse_observation(payload: Any, now: datetime) -> HealthObservation | None:
    """Read only scalar metrics from the configured components of one node."""
    resources = _as_list(_as_mapping(payload).get("resourceMetrics"))
    if not resources:
        return None
    assets = {_resource_asset(resource) for resource in resources}
    if len(assets) != 1 or (asset := next(iter(assets))) is None:
        return None
    observed_at = None
    node: dict[str, int] = {}
    receivers: dict[str, dict[str, int]] = {}
    for resource in resources:
        for scope in _as_list(_as_mapping(resource).get("scopeMetrics")):
            for raw in _as_list(_as_mapping(scope).get("metrics")):
                metric = _as_mapping(raw)
                name = metric.get("name")
                if not isinstance(name, str) or not name.startswith("otelcol_"):
                    continue
                key = _METRICS.get(name.removeprefix("otelcol_").removesuffix("_total"))
                if key is None:
                    continue
                series = _as_mapping(metric.get("sum") or metric.get("gauge"))
                for raw_point in _as_list(series.get("dataPoints")):
                    point = _as_mapping(raw_point)
                    value = _counter(point.get("asInt", point.get("asDouble")))
                    at = _timestamp(point.get("timeUnixNano"), now)
                    if value is None or at is None:
                        continue
                    attrs = _attributes(point.get("attributes"))
                    if name.startswith("otelcol_receiver_"):
                        receiver = attrs.get("receiver")
                        if receiver not in _RECEIVERS.values():
                            continue
                        target = receivers.setdefault(str(receiver), {})
                    elif attrs.get("exporter") == _EXPORTER:
                        target = node
                    else:
                        continue
                    observed_at = max(observed_at, at) if observed_at else at
                    if name.startswith("otelcol_exporter_queue_"):
                        target[key] = max(target.get(key, 0), value)
                    else:
                        target[key] = min(target.get(key, 0) + value, 2**53 - 1)
                    permanent = attrs.get("error_permanent", attrs.get("error.permanent"))
                    if key == "send_failed_records" and (permanent is True or permanent == "true"):
                        target["permanently_failed_records"] = min(
                            target.get("permanently_failed_records", 0) + value, 2**53 - 1
                        )
    return HealthObservation(asset, observed_at, node, receivers) if observed_at else None


@dataclass(frozen=True)
class Delivery:
    received_at: datetime
    source_time: datetime


def _status(
    metrics: dict[str, int], delivery: Delivery | None, now: datetime
) -> tuple[HealthStatus, str, str | None]:
    queue = metrics.get("queue_requests", 0)
    capacity = metrics.get("queue_capacity_requests")
    if metrics.get("permanently_failed_records"):
        return (
            HealthStatus.FAILED,
            "dropping_records",
            "The node exporter reported permanent failures",
        )
    if capacity and queue >= capacity:
        return HealthStatus.DEGRADED, "backlogged", "The node exporter queue is saturated"
    if metrics.get("enqueue_failed_records") or metrics.get("refused_records"):
        return (
            HealthStatus.DEGRADED,
            "degraded",
            "The Collector reported enqueue or receive failures",
        )
    if delivery and now - delivery.source_time <= FRESHNESS:
        return HealthStatus.OK, "delivering", None
    if queue or (delivery and delivery.received_at >= now - FRESHNESS):
        return (
            HealthStatus.DEGRADED,
            "backlogged",
            "Fresh native records have not reached the gateway",
        )
    if metrics.get("send_failed_records"):
        return HealthStatus.DEGRADED, "degraded", "The node exporter reported failed send attempts"
    if metrics:
        return HealthStatus.UNKNOWN, "running_not_delivering", None
    return HealthStatus.UNKNOWN, "unknown", None


class DeliveryHealth:
    """Bounded gateway-local evidence for recent committed native deliveries.

    The latest health reports are persisted through the spool. A gateway restart
    clears this corroboration cache until a new native record is durably received.
    """

    def __init__(self) -> None:
        self._deliveries: OrderedDict[tuple[str, SourceType], Delivery] = OrderedDict()

    def record_logs(
        self, payload: dict[str, Any], events: Iterable[Any], received: datetime
    ) -> None:
        assets = {_resource_asset(resource) for resource in _as_list(payload.get("resourceLogs"))}
        if len(assets) != 1 or (asset := next(iter(assets))) is None:
            return
        for event in events:
            if not isinstance(event, SecurityEvent) or event.asset_id != ASSET_ID:
                continue
            source = event.source.source_type
            if source not in _RECEIVERS:
                continue
            key = (asset, source)
            existing = self._deliveries.get(key)
            if event.event_time > received + _CLOCK_TOLERANCE:
                continue
            at = min(received, event.event_time)
            if existing and existing.source_time >= at:
                continue
            self._deliveries[key] = Delivery(received, at)
            self._deliveries.move_to_end(key)
            if len(self._deliveries) > _MAX_CACHED_DELIVERIES:
                self._deliveries.popitem(last=False)

    def reports(self, sample: HealthObservation) -> list[CollectorHealth]:
        reports = []
        for source, receiver in _RECEIVERS.items():
            delivery = self._deliveries.get((sample.asset_id, source))
            source_metrics = sample.receiver_metrics.get(receiver, {})
            # Workers have no apiserver audit file. Only report that source on
            # nodes with a receiver observation or an attributed native receipt.
            if source == SourceType.K8S_AUDIT and not (source_metrics or delivery):
                continue
            metrics = {**sample.node_metrics, **source_metrics}
            status, state, error = _status(metrics, delivery, sample.observed_at)
            details: dict[str, AttributeValue] = dict(metrics)
            details.update(delivery_state=state, exporter_scope="node")
            reports.append(
                CollectorHealth(
                    collector_id=COLLECTOR_PREFIX
                    + stable_id("otel.health.v1", sample.asset_id, source),
                    collector_type="k8s_otel",
                    asset_id=sample.asset_id,
                    source_types=[source.value],
                    status=status,
                    reported_at=sample.observed_at,
                    last_attempt_at=sample.observed_at,
                    last_success_at=delivery.source_time if delivery else None,
                    last_error=error,
                    events_collected=min(source_metrics.get("accepted_records", 0), _UINT32_MAX),
                    lag_seconds=max(
                        0.0, (delivery.received_at - delivery.source_time).total_seconds()
                    )
                    if delivery
                    else None,
                    collector_version="otelcol-contrib/0.165.0",
                    interval_seconds=INTERVAL,
                    details=details,
                )
            )
        return reports
