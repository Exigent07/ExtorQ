"""Kubernetes inventory, service hierarchy, Events and posture collector (owner: B2).

Configured in ``config/collectors/kubernetes.yaml`` with
``module: extorq_collectors.kubernetes.collector:KubernetesInventoryCollector`` and
producer ``k8s-inventory-extorq-lab``. Runs host-native on the Mac against the kind
API server on 127.0.0.1 with the read-only ``extorq-system/extorq-inventory``
identity (TokenRequest token from ``infra/kind/kind.sh token``).

Each cycle (one ``ctx.emit`` = one atomic outbox + snapshot commit):

1. LIST every resource kind (paginated; 410 Gone -> relist). A kind that cannot be
   listed is reported in health and is NOT diffed (a failed list never looks like
   "everything was deleted"); 401 fails the whole cycle (token expired).
2. Snapshot diff per kind -> ``k8s.resource.created|updated|deleted`` events with
   ``attributes.risk_flags`` (shared vocabulary with the audit normaliser) and
   InventoryItems (tombstones for deletions). The first snapshot is a baseline
   (``attributes.baseline = true``) so rules can ignore pre-existing objects.
3. Service hierarchy: Service records (workloads, Kubernetes Services), Pod and
   container ServiceInstances, ``service.discovered|removed|exposure.changed``.
4. core/v1 Events -> ``k8s.event.observed`` (deduplicated by uid + occurrence count).
   Events expire on the API server after about 1 h: a polling gap longer than that
   is reported as ``extorq.collector.gap_detected``.
5. Assets: the cluster and one ``kubernetes_node`` asset per node.
6. Posture scan -> ScanRun + PostureFindings (``extorq-posture-k8s``).

Service, instance and inventory records are re-sent in full every
``refresh_seconds`` so that a lost or quarantined record heals and ``last_seen``
stays meaningful.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from extorq.common.config import get_settings
from extorq.contracts.asset import Asset
from extorq.contracts.common import (
    AssetType,
    CollectionMethod,
    Criticality,
    EventCategory,
    Outcome,
)
from extorq.contracts.event import Provenance, Resource, SecurityEvent, SourceInfo
from extorq.contracts.identity import canonical_json, event_id, sha256_hex
from extorq.contracts.service import Service, ServiceInstance, ServiceRef
from extorq.ingest.otlp_k8s import ASSET_ID, CLUSTER_NAME, node_asset_id, valid_k8s_name
from extorq_collectors.kubernetes.api import (
    KubeApiError,
    KubeClient,
    KubeConfigError,
    KubeConnection,
    KubeUnauthorized,
    token_expiry,
)
from extorq_collectors.kubernetes.hierarchy import Hierarchy, build_hierarchy
from extorq_collectors.kubernetes.model import (
    EVENTS_PATH,
    RESOURCE_KINDS,
    WORKLOAD_KINDS,
    DiffContext,
    OwnerIndex,
    as_dict,
    as_list,
    clean,
    event_count,
    event_time_of,
    gap_event,
    inventory_item,
    k8s_event,
    meta,
    object_key,
    object_state,
    resource_change_event,
    top_level_workloads,
)
from extorq_collectors.kubernetes.posture import DEFAULT_EXCLUDED_NAMESPACES, run_posture_scan
from extorq_collectors.sdk import Collector, CollectorContext, asset_upsert

COLLECTOR_VERSION = "1.0.0"
FIRST_SEEN_KV = "k8s.service_first_seen"
REFRESH_KV = "k8s.last_full_refresh"
EVENTS_OK_KV = "k8s.events_last_success"


class KubernetesSettings(BaseModel):
    """``settings:`` of the collector entry (no secrets: paths only)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kubeconfig: str = "var/kube/extorq-inventory.kubeconfig"
    request_timeout_seconds: float = Field(default=15.0, ge=1, le=120)
    excluded_namespaces: tuple[str, ...] = DEFAULT_EXCLUDED_NAMESPACES
    refresh_seconds: int = Field(default=900, ge=60, le=86400)
    event_ttl_seconds: int = Field(default=3600, ge=300, le=86400)
    max_events_per_cycle: int = Field(default=2000, ge=10, le=20000)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> KubernetesSettings:
        try:
            return cls.model_validate(dict(data))
        except ValidationError as exc:
            fields = ", ".join(".".join(str(p) for p in e["loc"]) for e in exc.errors()[:5])
            raise KubernetesCollectorError(
                f"invalid kubernetes collector settings: {fields}"
            ) from None


class KubernetesCollectorError(RuntimeError):
    """Cycle-level failure; the message is sanitised and secret-free."""


@dataclass
class CycleState:
    lists: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    failed: dict[str, str] = field(default_factory=dict)
    events: list[dict[str, Any]] | None = None
    events_error: str | None = None
    version: dict[str, Any] | None = None
    relists: int = 0
    retries: int = 0


class KubernetesInventoryCollector(Collector):
    collector_type: ClassVar[str] = "k8s_inventory"
    source_types: ClassVar[tuple[str, ...]] = ("k8s.api_inventory", "k8s.events", "k8s.posture")
    collector_version: ClassVar[str] = COLLECTOR_VERSION

    def __init__(
        self, *, transport: httpx.BaseTransport | None = None, kubeconfig_path: Path | None = None
    ) -> None:
        #: Test seams: an httpx.MockTransport and an explicit kubeconfig path.
        self._transport = transport
        self._kubeconfig_path = kubeconfig_path

    # ── lifecycle ─────────────────────────────────────────────────────

    def setup(self, ctx: CollectorContext) -> None:
        KubernetesSettings.from_mapping(ctx.config)  # fail fast on invalid settings

    def _connection(self, cfg: KubernetesSettings) -> KubeConnection:
        path = self._kubeconfig_path or get_settings().resolve(Path(cfg.kubeconfig))
        try:
            return KubeConnection.from_kubeconfig(path)
        except KubeConfigError as exc:
            raise KubernetesCollectorError(str(exc)) from None

    def _fetch(self, cfg: KubernetesSettings, conn: KubeConnection) -> CycleState:
        state = CycleState()
        with KubeClient(
            conn, timeout=cfg.request_timeout_seconds, transport=self._transport
        ) as client:
            try:
                state.version = client.get("/version")
            except KubeUnauthorized as exc:
                raise KubernetesCollectorError(str(exc)) from None
            except (KubeApiError, KubeConfigError) as exc:
                state.failed["version"] = clean(str(exc), 300) or "error"
            for rk in RESOURCE_KINDS:
                try:
                    result = client.list(rk.path)
                except KubeUnauthorized as exc:
                    raise KubernetesCollectorError(str(exc)) from None
                except (KubeApiError, KubeConfigError) as exc:
                    state.failed[rk.kind] = clean(str(exc), 300) or "error"
                    continue
                state.lists[rk.kind] = [{**item, "kind": rk.kind} for item in result.items]
            try:
                events = client.list(EVENTS_PATH)
                state.events = events.items
            except KubeUnauthorized as exc:
                raise KubernetesCollectorError(str(exc)) from None
            except (KubeApiError, KubeConfigError) as exc:
                state.events_error = clean(str(exc), 300) or "error"
            state.relists = client.stats.relists
            state.retries = client.stats.retries
        if not state.lists:
            reasons = "; ".join(f"{k}: {v}" for k, v in list(state.failed.items())[:4])
            raise KubernetesCollectorError(f"no resource kind could be listed ({reasons})")
        return state

    # ── one cycle ─────────────────────────────────────────────────────

    def collect(self, ctx: CollectorContext) -> None:
        cfg = KubernetesSettings.from_mapping(ctx.config)
        conn = self._connection(cfg)
        started = ctx.now()
        fetched = self._fetch(cfg, conn)
        now = ctx.now()
        records: list[BaseModel] = []
        details: dict[str, Any] = {}
        skipped = 0

        owners = OwnerIndex.build(fetched.lists.get("ReplicaSet", []), fetched.lists.get("Job", []))
        hierarchy_ok = all(k in fetched.lists for k in ("Pod", *WORKLOAD_KINDS))
        first_seen_map: dict[str, str] = dict(ctx.state.get(FIRST_SEEN_KV, {}) or {})

        def first_seen(sid: str, created: datetime | None) -> datetime:
            known = first_seen_map.get(sid)
            if known:
                try:
                    return datetime.fromisoformat(known)
                except ValueError:
                    pass
            value = min(created, now) if created else now
            first_seen_map[sid] = value.isoformat()
            return value

        hierarchy = (
            build_hierarchy(
                fetched.lists, owners, now=now, collector_id=ctx.collector_id, first_seen=first_seen
            )
            if hierarchy_ok
            else Hierarchy(notes=["hierarchy skipped: lists failed"])
        )
        refresh_due = self._refresh_due(ctx, cfg, now)
        snapshot_id = f"k8s-{now.strftime('%Y%m%dT%H%M%SZ')}"

        # 1. object diffs -> change events + inventory items
        changes = 0
        for rk in RESOURCE_KINDS:
            if rk.kind not in fetched.lists:
                continue
            snapshot = f"objects:{rk.kind}"
            baseline = not ctx.has_snapshot(snapshot)
            dctx = DiffContext(ctx.collector_id, COLLECTOR_VERSION, now, baseline)
            states: dict[str, dict[str, Any]] = {}
            objects: dict[str, dict[str, Any]] = {}
            for obj in fetched.lists[rk.kind]:
                owner_ref = None
                if rk.kind == "Pod":
                    owner_ref = hierarchy.pod_workloads.get(
                        f"{as_dict(obj.get('metadata')).get('namespace')}/"
                        f"{as_dict(obj.get('metadata')).get('name')}"
                    )
                state = object_state(rk, obj, owner=owner_ref.label if owner_ref else None)
                if state is None:
                    skipped += 1
                    continue
                key = object_key(rk.kind, state["namespace"], state["name"])
                states[key] = state
                objects[key] = obj
            diff = ctx.diff_snapshot(snapshot, states)
            for change, items in (
                ("created", diff.added),
                ("updated", diff.changed),
                ("deleted", diff.removed),
            ):
                for key, state in items.items():
                    current = objects.get(key) if change != "deleted" else None
                    previous = diff.previous.get(key)
                    # Only a change of the object's own content is an update. A change of
                    # derived fields alone (summary/flags after a parser upgrade) refreshes
                    # the inventory item without claiming the object changed.
                    content_changed = change != "updated" or (
                        previous is None or previous.get("sections") != state.get("sections")
                    )
                    try:
                        if content_changed:
                            records.append(
                                self._change_event(
                                    change, rk, state, dctx, current, previous, hierarchy
                                )
                            )
                        item = inventory_item(
                            rk,
                            state,
                            collector_id=ctx.collector_id,
                            snapshot_id=snapshot_id,
                            now=now,
                            present=change != "deleted",
                        )
                    except (ValidationError, ValueError):
                        skipped += 1
                        continue
                    if item is not None:
                        records.append(item)
                    changes += 1 if content_changed else 0
            if refresh_due and rk.item_type is not None:
                emitted = set(diff.added) | set(diff.changed)
                for key, state in states.items():
                    if key in emitted:
                        continue
                    try:
                        item = inventory_item(
                            rk,
                            state,
                            collector_id=ctx.collector_id,
                            snapshot_id=snapshot_id,
                            now=now,
                        )
                    except (ValidationError, ValueError):
                        skipped += 1
                        continue
                    if item is not None:
                        records.append(item)
        details["object_changes"] = changes

        # 2. service hierarchy
        if hierarchy_ok:
            records.extend(self._services(ctx, hierarchy, now, refresh_due, details))
            records.extend(self._instances(ctx, hierarchy, now, refresh_due, details))
            ctx.state.set(
                FIRST_SEEN_KV,
                {sid: first_seen_map[sid] for sid in hierarchy.services if sid in first_seen_map},
            )

        # 3. core/v1 Events (+ TTL gap)
        records.extend(self._events(ctx, cfg, fetched, hierarchy, now, details))

        # 4. assets
        records.extend(self._assets(ctx, fetched))

        # 5. posture
        if "Namespace" in fetched.lists:
            workloads = dict(top_level_workloads(fetched.lists)) if hierarchy_ok else {}
            for pod in fetched.lists.get("Pod", []) if hierarchy_ok else []:
                ref = owners.workload_of(pod)
                if ref is not None and ref.kind == "Pod":
                    workloads.setdefault(ref.key, (ref, pod))
            failed_for_posture = dict(fetched.failed)
            if not hierarchy_ok:
                failed_for_posture.setdefault("Pod", "owner chain unavailable")
            posture = run_posture_scan(
                view=fetched.lists,
                failed_kinds=failed_for_posture,
                workloads=workloads,
                collector_id=ctx.collector_id,
                collector_version=COLLECTOR_VERSION,
                producer_id=ctx.producer_id,
                started_at=started,
                now=ctx.now(),
                excluded_namespaces=cfg.excluded_namespaces,
            )
            records.append(posture.scan_run)
            records.extend(posture.findings)
            skipped += posture.skipped_objects
            details["posture_status"] = posture.scan_run.status.value
            details["posture_findings"] = len(posture.findings)

        ctx.emit(records, {"k8s.last_cycle": now.isoformat()})
        if refresh_due:
            ctx.state.set(REFRESH_KV, now.isoformat())
        expiry = token_expiry(conn.token_file)
        details.update(
            {
                "kinds_listed": len(fetched.lists),
                "kinds_failed": sorted(fetched.failed)[:16],
                "list_errors": [f"{k}: {v}" for k, v in list(fetched.failed.items())[:8]],
                "relists_410": fetched.relists,
                "api_retries": fetched.retries,
                "objects_skipped": skipped,
                "records_emitted": len(records),
                "full_refresh": refresh_due,
                "token_expires_in_seconds": int((expiry - now).total_seconds()) if expiry else None,
                "k8s_version": clean(as_dict(fetched.version).get("gitVersion"), 64),
                "notes": hierarchy.notes[:8],
                # The OTel path reports no CollectorHealth of its own: expose the agent's state.
                "log_agent_ready_nodes": sorted(n for n, ok in hierarchy.agents.items() if ok)
                if hierarchy_ok
                else None,
                "log_agent_not_ready_nodes": sorted(
                    n for n, ok in hierarchy.agents.items() if not ok
                )
                if hierarchy_ok
                else None,
            }
        )
        ctx.health_details = {k: v for k, v in details.items() if v is not None}
        ctx.checkpoint_summary = f"last_cycle={now.isoformat(timespec='seconds')}"
        if expiry is not None and expiry - now < timedelta(hours=2):
            ctx.log.warning(
                "k8s_inventory_token_expiring", seconds_left=int((expiry - now).total_seconds())
            )

    # ── helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _refresh_due(ctx: CollectorContext, cfg: KubernetesSettings, now: datetime) -> bool:
        last = ctx.state.get(REFRESH_KV)
        if not isinstance(last, str):
            return True
        try:
            return (now - datetime.fromisoformat(last)).total_seconds() >= cfg.refresh_seconds
        except ValueError:
            return True

    @staticmethod
    def _change_event(
        change: str,
        rk: Any,
        state: Mapping[str, Any],
        dctx: DiffContext,
        obj: dict[str, Any] | None,
        previous: Mapping[str, Any] | None,
        hierarchy: Hierarchy,
    ) -> SecurityEvent:
        pod_workload = None
        service = None
        namespace = state.get("namespace") or ""
        if rk.kind == "Pod":
            pod_workload = hierarchy.pod_workloads.get(f"{namespace}/{state['name']}")
            if pod_workload is not None:
                service = hierarchy.refs.get(pod_workload.key)
        elif rk.kind in WORKLOAD_KINDS:
            service = hierarchy.refs.get(f"{namespace}/{rk.kind}/{state['name']}")
        return resource_change_event(
            change,
            rk,
            state,
            ctx=dctx,
            obj=obj,
            previous=previous,
            pod_workload=pod_workload,
            service=service,
        )

    @staticmethod
    def _services(
        ctx: CollectorContext,
        hierarchy: Hierarchy,
        now: datetime,
        refresh_due: bool,
        details: dict[str, Any],
    ) -> list[BaseModel]:
        out: list[BaseModel] = []
        items = {
            sid: svc.model_dump(mode="json", exclude={"first_seen", "last_seen"})
            for sid, svc in hierarchy.services.items()
        }
        baseline = not ctx.has_snapshot("services")
        diff = ctx.diff_snapshot("services", items)
        for sid, svc in hierarchy.services.items():
            if sid in diff.added or sid in diff.changed or refresh_due:
                out.append(svc)
            if sid in diff.added:
                out.append(_service_event("service.discovered", svc, now, ctx, baseline))
            elif sid in diff.changed:
                before = diff.previous.get(sid, {})
                if before.get("endpoints") != items[sid].get("endpoints"):
                    out.append(_exposure_event(svc, before, items[sid], now, ctx))
        for _sid, stored in diff.removed.items():
            try:
                tomb = Service.model_validate(
                    {**stored, "first_seen": now, "last_seen": now, "present": False}
                )
            except ValidationError:
                continue
            out.append(tomb)
            out.append(_service_event("service.removed", tomb, now, ctx, False))
        details["services"] = len(hierarchy.services)
        details["services_changed"] = len(diff.added) + len(diff.changed) + len(diff.removed)
        details["services_by_status"] = _count(
            s.monitoring_status.value for s in hierarchy.services.values()
        )
        return out

    @staticmethod
    def _instances(
        ctx: CollectorContext,
        hierarchy: Hierarchy,
        now: datetime,
        refresh_due: bool,
        details: dict[str, Any],
    ) -> list[BaseModel]:
        out: list[BaseModel] = []
        items = {
            iid: inst.model_dump(mode="json", exclude={"observed_at"})
            for iid, inst in hierarchy.instances.items()
        }
        diff = ctx.diff_snapshot("instances", items)
        for iid, inst in hierarchy.instances.items():
            if iid in diff.added or iid in diff.changed or refresh_due:
                out.append(inst)
        for _iid, stored in diff.removed.items():
            try:
                out.append(
                    ServiceInstance.model_validate({**stored, "observed_at": now, "present": False})
                )
            except ValidationError:
                continue
        details["instances"] = len(hierarchy.instances)
        details["instances_changed"] = len(diff.added) + len(diff.changed) + len(diff.removed)
        return out

    @staticmethod
    def _events(
        ctx: CollectorContext,
        cfg: KubernetesSettings,
        fetched: CycleState,
        hierarchy: Hierarchy,
        now: datetime,
        details: dict[str, Any],
    ) -> list[BaseModel]:
        out: list[BaseModel] = []
        if fetched.events is None:
            details["events_error"] = fetched.events_error
            return out
        last_ok = ctx.state.get(EVENTS_OK_KV)
        if isinstance(last_ok, str):
            try:
                gap = (now - datetime.fromisoformat(last_ok)).total_seconds()
            except ValueError:
                gap = 0.0
            if gap > cfg.event_ttl_seconds:
                out.append(
                    gap_event(
                        collector_id=ctx.collector_id,
                        collector_version=COLLECTOR_VERSION,
                        source_type="k8s.events",
                        reason="poll_gap_exceeds_event_ttl",
                        now=now,
                        detail={
                            "gap_seconds": int(gap),
                            "event_ttl_seconds": cfg.event_ttl_seconds,
                            "last_success": last_ok,
                        },
                    )
                )
                details["events_gap_seconds"] = int(gap)
        items: dict[str, dict[str, Any]] = {}
        objects: dict[str, dict[str, Any]] = {}
        newest: datetime | None = None
        for obj in sorted(fetched.events, key=lambda e: str(event_time_of(e) or ""))[
            -cfg.max_events_per_cycle :
        ]:
            uid = meta(obj).get("uid")
            if not isinstance(uid, str) or not uid:
                continue
            items[uid] = {"count": event_count(obj)}
            objects[uid] = obj
            stamp = event_time_of(obj)
            if stamp and (newest is None or stamp > newest):
                newest = stamp
        diff = ctx.diff_snapshot("k8s-events", items)
        for uid in list(diff.added) + list(diff.changed):
            try:
                event = k8s_event(
                    objects[uid],
                    collector_id=ctx.collector_id,
                    collector_version=COLLECTOR_VERSION,
                    now=now,
                    pod_services=hierarchy.pod_services,
                )
            except (ValidationError, ValueError):
                continue
            if event is not None:
                out.append(event)
        ctx.state.set(EVENTS_OK_KV, now.isoformat())
        ctx.report_lag(newest)
        details["events_listed"] = len(items)
        details["events_new"] = len(diff.added) + len(diff.changed)
        return out

    @staticmethod
    def _assets(ctx: CollectorContext, fetched: CycleState) -> list[Asset]:
        out: list[Asset] = []
        version = as_dict(fetched.version)
        nodes = fetched.lists.get("Node")
        cluster_attrs = {
            "k8s_version": clean(version.get("gitVersion"), 64),
            "platform": clean(version.get("platform"), 64),
            "node_count": len(nodes) if nodes is not None else None,
            "namespace_count": len(fetched.lists["Namespace"])
            if "Namespace" in fetched.lists
            else None,
            "distribution": "kind",
        }
        cluster = asset_upsert(
            ctx,
            asset_type=AssetType.KUBERNETES_CLUSTER,
            name=CLUSTER_NAME,
            asset_id=ASSET_ID,
            display_name=f"Kind cluster {CLUSTER_NAME}",
            criticality=Criticality.HIGH,
            attributes={k: v for k, v in cluster_attrs.items() if v is not None},
        )
        if cluster is not None:
            out.append(cluster)
        for node in nodes or []:
            name = valid_k8s_name(meta(node).get("name"))
            asset_id = node_asset_id(name)
            if name is None or asset_id is None:
                continue
            status = as_dict(node.get("status"))
            info = as_dict(status.get("nodeInfo"))
            labels = as_dict(meta(node).get("labels"))
            roles = sorted(
                k.split("/", 1)[1]
                for k in labels
                if isinstance(k, str) and k.startswith("node-role.kubernetes.io/")
            )
            ready = next(
                (
                    as_dict(c).get("status") == "True"
                    for c in as_list(status.get("conditions"))
                    if as_dict(c).get("type") == "Ready"
                ),
                None,
            )
            internal = next(
                (
                    as_dict(a).get("address")
                    for a in as_list(status.get("addresses"))
                    if as_dict(a).get("type") == "InternalIP"
                ),
                None,
            )
            attrs = {
                "kubelet_version": clean(info.get("kubeletVersion"), 64),
                "container_runtime": clean(info.get("containerRuntimeVersion"), 64),
                "os_image": clean(info.get("osImage"), 128),
                "kernel_version": clean(info.get("kernelVersion"), 128),
                "architecture": clean(info.get("architecture"), 32),
                "internal_ip": clean(internal, 64),
                "roles": roles[:8],
                "ready": ready,
                "unschedulable": bool(as_dict(node.get("spec")).get("unschedulable", False)),
                "taints": len(as_list(as_dict(node.get("spec")).get("taints"))),
            }
            asset = asset_upsert(
                ctx,
                asset_type=AssetType.KUBERNETES_NODE,
                name=name,
                asset_id=asset_id,
                display_name=f"{CLUSTER_NAME} node {name}",
                parent_asset_id=ASSET_ID,
                attributes={k: v for k, v in attrs.items() if v is not None and v != []},
            )
            if asset is not None:
                out.append(asset)
        return out


def _count(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


def _service_event(
    event_type: str,
    svc: Service,
    now: datetime,
    ctx: CollectorContext,
    baseline: bool,
    extra: Mapping[str, Any] | None = None,
) -> SecurityEvent:
    """service.discovered / service.removed / service.exposure.changed for one Service."""
    content = sha256_hex(
        canonical_json(svc.model_dump(mode="json", exclude={"first_seen", "last_seen"}))
    )
    attributes: dict[str, Any] = {
        "service_kind": svc.service_kind.value,
        "service_key": svc.service_key,
        "category": svc.category.value,
        "discovered_via": [e.value for e in svc.discovered_via],
        "adapter_support": svc.adapter_support.value,
        "monitoring_status": svc.monitoring_status.value,
        "coverage_note": svc.coverage_note,
        "adapter_id": svc.adapter_id,
        "baseline": True if baseline else None,
        **dict(extra or {}),
    }
    action = event_type.rsplit(".", 1)[1]
    return SecurityEvent(
        event_id=event_id(
            "k8s.api_inventory", ASSET_ID, f"{svc.service_id}:{event_type}:{content}"
        ),
        event_type=event_type,
        category=EventCategory.NETWORK if action == "changed" else EventCategory.CONFIGURATION,
        asset_id=ASSET_ID,
        asset_type=AssetType.KUBERNETES_CLUSTER,
        source=SourceInfo(
            source_type="k8s.api_inventory",
            collector_id=ctx.collector_id,
            collector_version=COLLECTOR_VERSION,
            collection_method=CollectionMethod.API_POLL,
        ),
        event_time=now,
        observed_time=now,
        action=action,
        outcome=Outcome.SUCCESS,
        resource=Resource(type=svc.service_kind.value, name=svc.name),
        service=ServiceRef(service_id=svc.service_id, name=svc.name, adapter_id="k8s-inventory"),
        message=clean(
            f"{svc.service_kind.value} {svc.name} {action} ({svc.monitoring_status.value})", 512
        ),
        attributes={k: v for k, v in attributes.items() if v is not None},
        provenance=Provenance(parser="k8s-inventory", parser_version="1.0.0", raw_sha256=content),
    )


def _endpoint_labels(endpoints: Any) -> set[str]:
    labels = set()
    for ep in as_list(endpoints):
        ep = as_dict(ep)
        labels.add(
            f"{ep.get('protocol')}:{ep.get('address')}:{ep.get('port')}({ep.get('exposure')})"
        )
    return labels


def _exposure_event(
    svc: Service,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    now: datetime,
    ctx: CollectorContext,
) -> SecurityEvent:
    old, new = _endpoint_labels(before.get("endpoints")), _endpoint_labels(after.get("endpoints"))
    return _service_event(
        "service.exposure.changed",
        svc,
        now,
        ctx,
        False,
        extra={
            "endpoints_added": sorted(new - old)[:32],
            "endpoints_removed": sorted(old - new)[:32],
            "attribution": "inferred",
        },
    )


__all__ = ["KubernetesCollectorError", "KubernetesInventoryCollector", "KubernetesSettings"]
