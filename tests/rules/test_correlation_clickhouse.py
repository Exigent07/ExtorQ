"""Correlation on a real (ephemeral) ClickHouse: builder SQL, store, hash stability.

All telemetry here is SYNTHETIC (fixture_builder conventions): the VM-001 burst
fixture plus hand-made related events, attributed to synthetic ssh/nginx services.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fixture_builder import LINUX, MACOS, FixtureWriter

from extorq.contracts.context import RelationshipBasis, RelationshipType
from extorq.contracts.event import SecurityEvent
from extorq.contracts.identity import service_id
from extorq.contracts.ingest import RecordKind
from extorq.contracts.service import Service, ServiceRef
from extorq.correlation.builder import ContextBuilder, context_input_hash
from extorq.correlation.store import load_latest_context, save_context
from extorq.detection import harness
from extorq.detection.engine import DetectionEngine, EngineConfig
from extorq.detection.registry import load_rules_report
from extorq.detection.service import make_context_hook

ROOT = Path(__file__).resolve().parents[2] / "rules"
LOADED = {r.rule_id: r for r in load_rules_report(ROOT)[0]}
META = {k: v.metadata for k, v in LOADED.items()}
BURST = ROOT / "linux" / "tests" / "VM-001" / "positive_burst_external.jsonl"
SSH = service_id("linux:lab-vm-01", "host_service", "ssh.service")
NGINX = service_id("linux:lab-vm-01", "host_service", "nginx.service")


def _service(sid: str, name: str, category: str, at: datetime) -> Service:
    return Service(
        service_id=sid,
        asset_id="linux:lab-vm-01",
        service_kind="host_service",
        service_key=f"{name}.service",
        name=name,
        category=category,
        product="openssh" if name == "ssh" else "nginx",
        discovered_via=["systemd_unit"],
        adapter_id=f"linux-{name}",
        adapter_support="implemented",
        monitoring_status="monitored",
        telemetry_sources=["linux.journald"],
        first_seen=at,
        last_seen=at,
        observed_by="fixture-synthetic",
    )


@pytest.fixture
def clean(clickhouse: harness.EphemeralClickHouse) -> harness.EphemeralClickHouse:
    clickhouse.truncate()
    return clickhouse


def _scenario() -> tuple[list[tuple[RecordKind, object]], datetime, dict[str, str]]:
    records = harness.load_fixture(BURST)
    shift = harness.day_offset(max(m.event_time for _, m in records))
    records = harness.shift_records(records, shift)
    burst = [
        (k, m.model_copy(update={"service": ServiceRef(service_id=SSH, name="ssh")}))
        for k, m in records
    ]
    first = min(m.event_time for _, m in burst)
    last = max(m.event_time for _, m in burst)
    fx = FixtureWriter("corr-related")
    ids: dict[str, str] = {}
    ids["success"] = fx.add(
        "auth.ssh.login_succeeded",
        last + timedelta(seconds=30),
        asset=LINUX,
        outcome="success",
        actor={"type": "user", "name": "ubuntu"},
        network={"src_ip": "203.0.113.45", "src_port": 50999, "protocol": "tcp"},
        service={"service_id": SSH, "name": "ssh"},
        message="Accepted publickey (synthetic)",
    ).event_id
    ids["sudo"] = fx.add(
        "auth.sudo.command",
        last + timedelta(seconds=60),
        asset=LINUX,
        outcome="success",
        actor={"type": "user", "name": "ubuntu"},
        attributes={"run_as": "root"},
    ).event_id
    ids["probe"] = fx.add(
        "http.request",
        first - timedelta(seconds=60),
        asset=LINUX,
        source_type="linux.nginx",
        outcome="failure",
        network={"src_ip": "10.0.2.2"},
        http={"method": "GET", "route": "/.env", "status_code": 404},
        service={"service_id": NGINX, "name": "nginx"},
    ).event_id
    ids["mac"] = fx.add(
        "system.log.notable",
        last + timedelta(seconds=10),
        asset=MACOS,
        source_type="macos.unified_log",
        network={"src_ip": "203.0.113.45"},
        attributes={"subsystem": "com.example.synthetic"},
    ).event_id
    ids["far"] = fx.add(
        "auth.ssh.login_succeeded",
        last + timedelta(hours=3),
        asset=LINUX,
        outcome="success",
        actor={"type": "user", "name": "ubuntu"},
        network={"src_ip": "203.0.113.45"},
    ).event_id
    extra = [(RecordKind.EVENT, e) for e in fx.events]
    services = [
        (RecordKind.SERVICE, _service(SSH, "ssh", "ssh", first)),
        (RecordKind.SERVICE, _service(NGINX, "nginx", "http_server", first)),
    ]
    return [*burst, *extra, *services], last + timedelta(seconds=60), ids


def _engine(ch, hook=None) -> DetectionEngine:
    return DetectionEngine(
        [LOADED["VM-001"]],
        rules_client=ch.client("rules_ro"),
        read_client=ch.client("detect"),
        write_client=ch.client("detect"),
        config=EngineConfig(instance="rules-harness"),
        context_hook=hook,
    )


def test_context_on_clickhouse_classifies_persists_and_reloads(clean, to_row) -> None:
    records, now, ids = _scenario()
    harness.insert_records(clean.client("admin"), records, to_row)
    run = _engine(clean).run_once(now=now, force=True)[0]
    assert run.alerts_created == 1
    [alert] = harness.fetch_alerts(clean.client("admin"), "VM-001")

    builder = ContextBuilder(clean.client("detect"), rules=META)
    build_time = now + timedelta(minutes=1)
    ctx = builder.build(alert["alert_id"], now=build_time)
    rels = {r.event_id: r for r in ctx.relationships}
    assert rels[ids["success"]].relationship_type is RelationshipType.CANDIDATE
    assert RelationshipBasis.SAME_SERVICE in rels[ids["success"]].bases
    # Probe from 10.0.2.2 on nginx shares nothing with the burst from 203.0.113.45 on ssh.
    assert rels[ids["probe"]].relationship_type is RelationshipType.UNESTABLISHED
    assert set(rels[ids["probe"]].bases) == {
        RelationshipBasis.CROSS_SERVICE_SAME_ASSET,
        RelationshipBasis.SAME_ASSET_TIME_WINDOW,
    }
    assert rels[ids["mac"]].relationship_type is RelationshipType.CANDIDATE
    assert RelationshipBasis.CROSS_ASSET in rels[ids["mac"]].bases
    assert ids["far"] not in rels  # outside the context window
    assert rels[ids["sudo"]].relationship_type is RelationshipType.CANDIDATE  # principal
    assert {s.service_id: s.role for s in ctx.services} == {SSH: "evidence", NGINX: "related"}
    assert ctx.services[0].adapter_support == "implemented"
    assert [a.asset_id for a in ctx.related_assets] == ["macos:workstation-01"]
    assert ctx.features["ssh_success_after_failures"] is True
    assert ctx.features["sudo_after_login"] is True
    assert ctx.features["cross_service_activity"] is True
    assert len(ctx.evidence) == 18 and not ctx.truncated["evidence"]
    assert context_input_hash(ctx) == ctx.input_hash

    save_context(clean.client("detect"), ctx)
    assert load_latest_context(clean.client("detect"), alert["alert_id"]) == ctx
    stored = (
        clean.client("admin")
        .select(
            "SELECT count() FROM context_relationships WHERE context_id = {c:String}",
            {"c": ctx.context_id},
        )
        .rows[0][0]
    )
    assert stored == len(ctx.relationships)

    # Same data, same build time -> same hash and context id.
    again = builder.build(alert["alert_id"], now=build_time)
    assert (again.input_hash, again.context_id) == (ctx.input_hash, ctx.context_id)

    # A late related event changes the bundle: new hash, new row, newest served.
    fx = FixtureWriter("corr-late")
    fx.add(
        "auth.ssh.login_succeeded",
        ctx.alert.last_seen + timedelta(minutes=5),
        asset=LINUX,
        outcome="success",
        actor={"type": "user", "name": "deploy"},
        network={"src_ip": "203.0.113.45"},
    )
    harness.insert_records(
        clean.client("admin"), [(RecordKind.EVENT, e) for e in fx.events], to_row
    )
    later = builder.build(alert["alert_id"], now=build_time + timedelta(seconds=1))
    assert later.input_hash != ctx.input_hash
    save_context(clean.client("detect"), later)
    assert (
        load_latest_context(clean.client("detect"), alert["alert_id"]).context_id
        == later.context_id
    )


def test_detector_builds_and_stores_context_for_new_alerts(clean, to_row) -> None:
    records, now, _ = _scenario()
    harness.insert_records(clean.client("admin"), records, to_row)
    detect = clean.client("detect")
    engine = _engine(clean, make_context_hook(detect, detect, list(LOADED.values())))
    run = engine.run_once(now=now, force=True)[0]
    assert run.alerts_created == 1
    assert engine.stats.contexts_built_total == 1 and engine.stats.context_failures_total == 0
    [alert] = harness.fetch_alerts(clean.client("admin"), "VM-001")
    ctx = load_latest_context(detect, alert["alert_id"])
    assert ctx is not None and ctx.alert.alert_id == alert["alert_id"]
    assert ctx.alert.service_ids == [SSH]


def test_correlation_failure_never_fails_detection(clean, to_row) -> None:
    records, now, _ = _scenario()
    harness.insert_records(clean.client("admin"), records, to_row)

    def broken_hook(rule, alert_ids):
        raise RuntimeError("correlation exploded")

    engine = _engine(clean, broken_hook)
    run = engine.run_once(now=now, force=True)[0]
    assert run.status.value == "succeeded" and run.alerts_created == 1
    assert engine.stats.context_failures_total == 1


def test_context_for_unknown_alert_raises(clean) -> None:
    from extorq.correlation.builder import AlertNotFound

    with pytest.raises(AlertNotFound):
        ContextBuilder(clean.client("detect"), rules=META).build("0" * 32, now=datetime.now(UTC))


def test_builder_accepts_events_without_any_service_attribution(clean, to_row) -> None:
    records = harness.shift_records(
        harness.load_fixture(BURST),
        harness.day_offset(max(m.event_time for _, m in harness.load_fixture(BURST))),
    )
    harness.insert_records(clean.client("admin"), records, to_row)
    now = max(m.event_time for _, m in records if isinstance(m, SecurityEvent)) + timedelta(
        seconds=60
    )
    _engine(clean).run_once(now=now, force=True)
    [alert] = harness.fetch_alerts(clean.client("admin"), "VM-001")
    ctx = ContextBuilder(clean.client("detect"), rules=META).build(alert["alert_id"], now=now)
    assert ctx.services == []
    assert any("no service attribution" in x for x in ctx.limitations)
    assert list(alert["service_ids"]) == []
