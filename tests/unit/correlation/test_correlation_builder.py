"""ContextBuilder + store logic with an in-memory fake DbClient. All data is SYNTHETIC.

The fake answers each of the builder's static SQL constants; the SQL itself is
exercised against a real ClickHouse in tests/rules/test_correlation_clickhouse.py.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from correlation_helpers import T0, VM

from extorq.contracts.alert import DetectionAlert
from extorq.contracts.context import InvestigationContext, RelationshipType
from extorq.contracts.identity import canonical_json, context_id, service_id
from extorq.correlation import builder as b
from extorq.correlation.builder import AlertNotFound, ContextBuilder, context_input_hash
from extorq.correlation.store import (
    LATEST_CONTEXT_SQL,
    ContextIntegrityError,
    load_latest_context,
    save_context,
)
from extorq.detection.clients import QueryRows
from extorq.detection.registry import load_rules_report

RULES = {r.rule_id: r.metadata for r in load_rules_report(Path(__file__).parents[3] / "rules")[0]}
ALERT_ID = "f" * 32
SSH_SVC = service_id(VM, "host_service", "ssh.service")
MAC_SSH = service_id("macos:workstation-01", "host_service", "com.openssh.sshd")
EV = [f"{i:032x}" for i in range(1, 7)]
SUCCESS, PROBE, NOTE = "1" * 32, "2" * 32, "3" * 32


def _qr(rows: list[dict[str, Any]]) -> QueryRows:
    columns = sorted({k for r in rows for k in r}) if rows else []
    return QueryRows(
        columns=columns, types=[], rows=[tuple(r.get(c) for c in columns) for r in rows]
    )


def _event(event_id: str, seconds: float, event_type: str, **kw: Any) -> dict[str, Any]:
    row = {
        "event_id": event_id,
        "event_time": T0 + timedelta(seconds=seconds),
        "event_type": event_type,
        "source_type": "linux.journald",
        "asset_id": VM,
        "asset_type": "linux_host",
        "outcome": "failure",
        "attributes": "{}",
        "k8s_source_ips": [],
        "svc_id": None,
        "svc_name": None,
        "svc_instance_id": None,
        "simulation_run_id": None,
    }
    row.update(kw)
    return row


EVIDENCE_ROWS = [
    _event(
        eid,
        i * 10,
        "auth.ssh.login_failed",
        src_ip="203.0.113.45",
        src_port=50100 + i,
        actor_name="admin",
        svc_id=SSH_SVC,
        svc_name="ssh",
    )
    for i, eid in enumerate(EV)
]
RELATED_ROWS = [
    _event(
        SUCCESS,
        120,
        "auth.ssh.login_succeeded",
        src_ip="203.0.113.45",
        actor_name="ubuntu",
        outcome="success",
        svc_id=SSH_SVC,
        svc_name="ssh",
    ),
    _event(
        PROBE,
        -60,
        "http.request",
        source_type="linux.nginx",
        src_ip="10.0.2.2",
        http_status=404,
        http_route="/.env",
    ),
]
TEMPORAL_ROWS = [_event(NOTE, 5, "system.log.notable")]


def _alert() -> DetectionAlert:
    return DetectionAlert.model_validate(
        {
            "alert_id": ALERT_ID,
            "rule_id": "VM-001",
            "rule_version": RULES["VM-001"].version,
            "rule_title": RULES["VM-001"].title,
            "severity": "medium",
            "confidence": "high",
            "asset_id": VM,
            "asset_type": "linux_host",
            "group_key": f"{VM}|203.0.113.45",
            "entities": {"src_ip": "203.0.113.45"},
            "service_ids": [SSH_SVC],
            "summary": "synthetic",
            "first_seen": T0,
            "last_seen": T0 + timedelta(seconds=50),
            "window_start": T0 - timedelta(minutes=20),
            "window_end": T0 + timedelta(minutes=1),
            "event_count": 6,
            "evidence_event_ids": EV,
            "created_at": T0 + timedelta(minutes=2),
            "updated_at": T0 + timedelta(minutes=2),
            "detector_version": "test",
        }
    )


class FakeDb:
    def __init__(self, overrides: dict[str, Callable[[dict[str, Any]], Any]] | None = None):
        self.inserted: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.linked = list(RELATED_ROWS)
        events = {r["event_id"]: r for r in [*EVIDENCE_ROWS, *RELATED_ROWS, *TEMPORAL_ROWS]}
        self.handlers: dict[str, Callable[[dict[str, Any]], Any]] = {
            b.ALERT_SQL: lambda p: QueryRows(["payload"], [], [(_alert().model_dump_json(),)]),
            b.EVIDENCE_IDS_SQL: lambda p: QueryRows(["event_id"], [], [(e,) for e in EV]),
            b.EVENTS_BY_ID_SQL: lambda p: _qr([events[i] for i in p["ids"] if i in events]),
            b.LINKED_SQL: lambda p: _qr(self.linked),
            b.TEMPORAL_SQL: lambda p: _qr(TEMPORAL_ROWS),
            b.ASSETS_SQL: lambda p: _qr([]),
            b.SERVICES_SQL: lambda p: _qr(
                [
                    {
                        "service_id": SSH_SVC,
                        "asset_id": VM,
                        "service_kind": "host_service",
                        "service_key": "ssh.service",
                        "s_name": "ssh",
                        "s_category": "ssh",
                        "s_support": "implemented",
                        "s_status": "monitored",
                    }
                ]
            ),
            b.FINDINGS_SERVICE_SQL: lambda p: RuntimeError("Code: 47. Unknown identifier"),
            b.FINDINGS_CURRENT_SQL: lambda p: RuntimeError("Code: 60. Unknown table"),
            b.FINDINGS_RAW_SQL: lambda p: _qr(
                [
                    {
                        "finding_id": "9" * 32,
                        "scanner": "trivy",
                        "check_id": "CVE-2026-0001",
                        "severity": "high",
                        "title": "openssl",
                        "state": "unverified",
                        "last_observed_at": T0,
                    }
                ]
            ),
            b.COLLECTORS_SQL: lambda p: _qr(
                [
                    {
                        "collector_id": "linux-ssh-lab-vm-01",
                        "asset_id": VM,
                        "source_types": ["linux.journald", "linux.auditd"],
                        "status": "ok",
                        "last_success_at": T0 + timedelta(minutes=9),
                        "lag_seconds": 3.5,
                        "interval_seconds": 30,
                    }
                ]
            ),
            b.COLLECTOR_WINDOW_SQL: lambda p: QueryRows(
                ["collector_id", "bad", "reports"], [], [("linux-ssh-lab-vm-01", 0, 40)]
            ),
            b.GAP_EVENTS_SQL: lambda p: QueryRows(["gap_source"], [], []),
            b.SOURCES_PRESENT_SQL: lambda p: QueryRows(
                ["source_type", "n"], [], [("linux.journald", 9)]
            ),
            b.RULE_RUN_MISSING_SQL: lambda p: QueryRows(["s", "runs"], [], []),
            LATEST_CONTEXT_SQL: lambda p: self._latest(p),
        }
        self.handlers.update(overrides or {})

    def _latest(self, params: dict[str, Any]) -> QueryRows:
        rows = [
            r
            for r in self.inserted["investigation_contexts"]
            if r["alert_id"] == params["alert_id"]
        ]
        rows.sort(key=lambda r: (r["created_at"], r["context_id"]), reverse=True)
        return QueryRows(["body"], [], [(r["body"],) for r in rows[:1]])

    def select(self, sql: str, parameters: dict[str, Any] | None = None) -> QueryRows:
        handler = self.handlers.get(sql)
        if handler is None:
            raise AssertionError(f"unexpected SQL: {sql[:80]}")
        result = handler(parameters or {})
        if isinstance(result, Exception):
            raise result
        return result

    def insert_rows(self, table: str, rows: list[dict[str, Any]]) -> None:
        self.inserted[table].extend(rows)


NOW = T0 + timedelta(minutes=10)


def _build(db: FakeDb, now=NOW) -> InvestigationContext:
    return ContextBuilder(db, rules=RULES).build(ALERT_ID, now=now)


def test_build_classifies_and_describes_the_bundle():
    ctx = _build(FakeDb())
    assert ctx.alert.alert_id == ALERT_ID and ctx.rule.rule_id == "VM-001"
    assert [e.event_id for e in ctx.evidence] == EV
    rels = {r.event_id: r for r in ctx.relationships}
    assert rels[SUCCESS].relationship_type is RelationshipType.CANDIDATE
    assert rels[PROBE].relationship_type is RelationshipType.UNESTABLISHED
    assert rels[NOTE].relationship_type is RelationshipType.UNESTABLISHED
    assert [s.role for s in ctx.services] == ["evidence"] and ctx.services[0].name == "ssh"
    assert ctx.features["ssh_success_after_failures"] is True
    assert ctx.window_start == T0 - timedelta(seconds=900)
    assert ctx.window_end == T0 + timedelta(seconds=50 + 900)
    assert ctx.limitations[0].startswith("Relationships show co-occurrence")
    assert any("Findings lifecycle view unavailable" in x for x in ctx.limitations)
    assert any("No asset inventory record" in x for x in ctx.limitations)
    assert ctx.findings[0].state == "unverified"
    cov = ctx.coverage[0]
    assert cov.source_type == "linux.journald" and cov.stale is False
    assert cov.gap_during_window is False and cov.lag_seconds == 3.5
    timeline_ids = [t.event_id for t in ctx.timeline]
    assert timeline_ids[0] == PROBE  # chronological
    assert sum(t.is_evidence for t in ctx.timeline) == 6


def test_input_hash_is_deterministic_and_excludes_identity_fields():
    first = _build(FakeDb())
    second = _build(FakeDb())
    assert first.input_hash == second.input_hash and first.context_id == second.context_id
    assert first.context_id == context_id(ALERT_ID, first.input_hash)
    assert context_input_hash(first) == first.input_hash
    # created_at is excluded from the hash; content changes are not.
    later = first.model_copy(update={"created_at": first.created_at + timedelta(hours=1)})
    assert context_input_hash(later) == first.input_hash


def test_late_related_event_changes_the_hash():
    db = FakeDb()
    before = _build(db)
    db.linked.append(
        _event("4" * 32, 200, "auth.sudo.command", actor_name="ubuntu", outcome="success")
    )
    after = _build(db)
    assert after.input_hash != before.input_hash
    assert after.features["sudo_after_login"] is True


def test_stale_collector_is_reported():
    ctx = _build(FakeDb(), now=NOW + timedelta(hours=2))
    cov = ctx.coverage[0]
    assert cov.stale is True and "stale" in (cov.note or "")
    assert any("stale or had a gap" in x for x in ctx.limitations)


def test_missing_required_source_is_reported():
    db = FakeDb({b.SOURCES_PRESENT_SQL: lambda p: QueryRows(["source_type", "n"], [], [])})
    ctx = _build(db)
    assert any(
        "No linux.journald events" in m and "required source" in m for m in ctx.missing_telemetry
    )


def test_optional_sections_degrade_to_limitations():
    db = FakeDb(
        {
            b.COLLECTORS_SQL: lambda p: RuntimeError("Code: 497. Not enough privileges"),
            b.SERVICES_SQL: lambda p: RuntimeError("Code: 60. Unknown table"),
            b.FINDINGS_RAW_SQL: lambda p: RuntimeError("boom"),
        }
    )
    ctx = _build(db)
    assert ctx.coverage == []
    assert ctx.services[0].service_kind == "unknown"
    assert any("telemetry coverage is unknown" in x for x in ctx.limitations)
    assert any("Posture findings could not be read" in x for x in ctx.limitations)


def test_unknown_alert_and_bad_id():
    db = FakeDb({b.ALERT_SQL: lambda p: QueryRows(["payload"], [], [])})
    with pytest.raises(AlertNotFound):
        _build(db)
    with pytest.raises(ValueError, match="32 lower-case hex"):
        ContextBuilder(FakeDb()).build("../etc")


def test_rule_metadata_from_detection_rules_table():
    meta = RULES["VM-001"]
    row = {
        "rule_id": meta.rule_id,
        "version": meta.version,
        "title": meta.title,
        "description": meta.description,
        "severity": meta.severity.value,
        "status": meta.status.value,
        "mitre_techniques": meta.mitre_techniques,
        "asset_types": [a.value for a in meta.asset_types],
        "requires": canonical_json([r.model_dump(mode="json") for r in meta.requires]),
        "schedule": canonical_json(meta.schedule.model_dump(mode="json")),
        "dedup": canonical_json(meta.dedup.model_dump(mode="json")),
        "group_by": meta.group_by,
        "params": canonical_json(meta.params),
        "false_positives": meta.false_positives,
        "blind_spots": meta.blind_spots,
        "reference_urls": meta.references,
        "query_sha256": meta.query_sha256,
    }
    db = FakeDb({b.RULE_BY_VERSION_SQL: lambda p: _qr([row])})
    ctx = ContextBuilder(db).build(ALERT_ID, now=NOW)  # no in-process rules given
    assert ctx.rule == meta


def test_save_and_load_roundtrip_and_integrity_check():
    db = FakeDb()
    ctx = _build(db)
    save_context(db, ctx)
    assert len(db.inserted["context_relationships"]) == len(ctx.relationships)
    [row] = db.inserted["investigation_contexts"]
    assert row["candidate_count"] == 1 and row["unestablished_count"] == 2
    loaded = load_latest_context(db, ALERT_ID)
    assert loaded == ctx
    # Tampering with the stored body is detected.
    body = json.loads(row["body"])
    body["features"]["ssh_success_after_failures"] = False
    row["body"] = canonical_json(body)
    with pytest.raises(ContextIntegrityError):
        load_latest_context(db, ALERT_ID)
    assert load_latest_context(db, "e" * 32) is None


def test_save_refuses_a_context_with_a_wrong_hash():
    ctx = _build(FakeDb())
    forged = ctx.model_copy(update={"input_hash": "0" * 64})
    with pytest.raises(ContextIntegrityError):
        save_context(FakeDb(), forged)


def test_service_reference_shadowing_another_asset_is_not_trusted():
    """F-IC-6: a VM event claims the macOS ssh service id; a forged VM row reuses that id."""
    db = FakeDb(
        {
            b.SERVICES_SQL: lambda p: _qr(
                [
                    {
                        "service_id": MAC_SSH,
                        "asset_id": "macos:workstation-01",
                        "service_kind": "host_service",
                        "service_key": "com.openssh.sshd",
                        "s_name": "ssh",
                        "s_category": "ssh",
                        "s_support": "implemented",
                        "s_status": "monitored",
                    },
                    {
                        "service_id": MAC_SSH,
                        "asset_id": VM,
                        "service_kind": "host_service",
                        "service_key": "forged",
                        "s_name": "ssh",
                        "s_category": "ssh",
                        "s_support": "implemented",
                        "s_status": "monitored",
                    },
                ]
            )
        }
    )
    for row in EVIDENCE_ROWS:
        row["svc_id"] = MAC_SSH
    try:
        ctx = _build(db)
    finally:
        for row in EVIDENCE_ROWS:
            row["svc_id"] = SSH_SVC
    [svc] = [s for s in ctx.services if s.service_id == MAC_SSH]
    assert svc.service_kind == "unknown" and svc.asset_id == VM
    assert any("unrelated asset" in x for x in ctx.limitations)


def test_findings_of_evidence_services_are_counted_and_first():
    rows = [
        {
            "finding_id": "8" * 32,
            "scanner": "trivy",
            "check_id": "CVE-2026-0002",
            "severity": "medium",
            "title": "openssh",
            "state": "open",
            "last_observed_at": T0,
            "f_service": SSH_SVC,
        },
        {
            "finding_id": "7" * 32,
            "scanner": "trivy",
            "check_id": "CVE-2026-0003",
            "severity": "critical",
            "title": "kernel",
            "state": "open",
            "last_observed_at": T0,
            "f_service": "",
        },
    ]
    seen = {}

    def service_findings(params):
        seen.update(params)
        return _qr(rows)

    ctx = _build(FakeDb({b.FINDINGS_SERVICE_SQL: service_findings}))
    assert seen["services"] == [SSH_SVC]
    assert [f.check_id for f in ctx.findings] == ["CVE-2026-0002", "CVE-2026-0003"]
    assert ctx.features["findings_on_evidence_services"] == 1
    assert not any("lifecycle view unavailable" in x for x in ctx.limitations)
