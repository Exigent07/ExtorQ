"""Ingest gateway (PLAN §5.1): auth, authorization, limits, validation, quarantine,
time sanity, redaction, dedup, replay, backpressure, OTLP endpoint, schema 1.1.

Runs the real FastAPI app in-process (TestClient) on a temporary SQLite spool with
an in-memory producer registry. All records are SYNTHETIC.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import uuid
import zlib
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from platform_samples import (
    LINUX_ASSET,
    MACOS_ASSET,
    event_data,
    inventory_data,
    record,
    service_data,
    service_instance_data,
)

from extorq.common.config import Settings
from extorq.contracts.common import utc_now
from extorq.contracts.event import SecurityEvent
from extorq.ingest import processing
from extorq.ingest.app import create_app
from extorq.ingest.registry import ProducerEntry, ProducerRegistry
from extorq.pipeline.spool import Spool

TOKENS = {
    "linux-ssh-lab-vm-01": "synthetic-linux-token-0123456789abcdef",
    "k8s-otel-extorq-lab": "synthetic-otel-token-0123456789abcdef",
}
KINDS = [
    "event",
    "asset",
    "inventory_item",
    "finding",
    "scan_run",
    "collector_health",
    "service",
    "service_instance",
]


def entries() -> list[ProducerEntry]:
    return [
        ProducerEntry(
            producer_id="linux-ssh-lab-vm-01",
            token_sha256=hashlib.sha256(TOKENS["linux-ssh-lab-vm-01"].encode()).hexdigest(),
            allowed_kinds=KINDS,
            allowed_source_types=["linux.*"],
            allowed_asset_patterns=[LINUX_ASSET],
        ),
        ProducerEntry(
            producer_id="k8s-otel-extorq-lab",
            token_sha256=hashlib.sha256(TOKENS["k8s-otel-extorq-lab"].encode()).hexdigest(),
            allowed_kinds=["event"],
            allowed_source_types=["k8s.audit", "k8s.container_log"],
            allowed_asset_patterns=["k8s:extorq-lab*"],
        ),
    ]


class Harness:
    def __init__(self, tmp_path: Path, normalizer: Any = None, **settings: Any) -> None:
        self.settings = Settings(home=tmp_path, **settings)
        self.spool = Spool(tmp_path / "spool.db")
        self.app = create_app(
            self.settings,
            spool=self.spool,
            registry=ProducerRegistry.from_entries(entries()),
            normalizer_loader=lambda: normalizer,
            background_tasks=False,
        )
        self.client = TestClient(self.app)

    def post(
        self,
        body: bytes | dict[str, Any],
        *,
        producer: str = "linux-ssh-lab-vm-01",
        token: str | None = None,
        path: str = "/v1/ingest",
        headers: dict[str, str] | None = None,
    ) -> Any:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        hdrs = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token or TOKENS[producer]}",
        }
        hdrs.update(headers or {})
        return self.client.post(path, content=data, headers=hdrs)

    def rows(self, kind: str) -> list[dict[str, Any]]:
        with self.spool._lock:
            payloads = self.spool._conn.execute(
                "SELECT payload FROM records WHERE kind = ? ORDER BY seq", (kind,)
            ).fetchall()
        return [json.loads(p[0]) for p in payloads]


@pytest.fixture
def gw(tmp_path: Path) -> Iterator[Harness]:
    harness = Harness(tmp_path)
    with harness.client:
        yield harness
    harness.spool.close()


def batch(
    records: list[dict[str, Any]],
    producer: str = "linux-ssh-lab-vm-01",
    batch_id: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "1.1",
        "batch_id": batch_id or uuid.uuid4().hex,
        "producer_id": producer,
        "sent_at": utc_now().isoformat(),
        "records": records,
    }


def fresh_event(marker: str, **kw: Any) -> dict[str, Any]:
    return record("event", event_data(marker, event_time=utc_now() - timedelta(minutes=1), **kw))


# ── health / status / authentication ─────────────────────────────────


def test_healthz_needs_no_auth_and_reveals_nothing(gw: Harness) -> None:
    response = gw.client.get("/healthz")
    assert response.status_code == 200 and response.json() == {"status": "ok"}


def test_status_requires_auth_and_reports_schema_1_1(gw: Harness) -> None:
    assert gw.client.get("/v1/status").status_code == 401
    response = gw.client.get(
        "/v1/status", headers={"Authorization": f"Bearer {TOKENS['linux-ssh-lab-vm-01']}"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == "1.1" and body["accepted_schema_versions"] == ["1.0", "1.1"]
    audits = gw.rows("ingest_audit")
    assert audits and audits[0]["decision"] == "unauthenticated"
    assert audits[0]["reason"] == "missing_bearer_token"


@pytest.mark.parametrize(
    "auth", ["", "Bearer", "Bearer wrong-token-value", "Basic abc", "Bearer " + "x" * 600]
)
def test_bad_or_missing_tokens_are_401_and_audited(gw: Harness, auth: str) -> None:
    response = gw.client.post(
        "/v1/ingest",
        content=b"{}",
        headers={"Content-Type": "application/json", **({"Authorization": auth} if auth else {})},
    )
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")
    audit = gw.rows("ingest_audit")[-1]
    assert audit["decision"] == "unauthenticated" and audit["authenticated_producer"] is None
    assert "wrong-token-value" not in json.dumps(audit)


# ── body limits / envelope ────────────────────────────────────────────


def test_content_type_must_be_json(gw: Harness) -> None:
    response = gw.post(b"{}", headers={"Content-Type": "text/plain"})
    assert response.status_code == 415


def test_declared_body_over_4_mib_is_rejected_before_reading(gw: Harness) -> None:
    response = gw.post(b"{}", headers={"Content-Length": str(4 * 1024 * 1024 + 1)})
    assert response.status_code == 413


def test_streamed_body_over_4_mib_is_rejected(gw: Harness) -> None:
    def chunks() -> Iterator[bytes]:
        for _ in range(5):
            yield b" " * (1024 * 1024)

    response = gw.client.post(
        "/v1/ingest",
        content=chunks(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TOKENS['linux-ssh-lab-vm-01']}",
        },
    )
    assert response.status_code == 413


def test_gzip_bomb_and_broken_gzip(gw: Harness) -> None:
    bomb = gzip.compress(b"[" + b" " * (8 * 1024 * 1024) + b"]")
    assert len(bomb) < 4 * 1024 * 1024
    assert gw.post(bomb, headers={"Content-Encoding": "gzip"}).status_code == 413
    assert gw.post(b"not gzip", headers={"Content-Encoding": "gzip"}).status_code == 400
    assert gw.post(b"{}", headers={"Content-Encoding": "br"}).status_code == 415
    raw = zlib.compress(b"{}")
    assert gw.post(raw, headers={"Content-Encoding": "gzip"}).status_code == 400


def test_gzip_batch_is_accepted(gw: Harness) -> None:
    body = gzip.compress(json.dumps(batch([fresh_event("gz")])).encode())
    response = gw.post(body, headers={"Content-Encoding": "gzip"})
    assert response.status_code == 202 and response.json()["accepted"] == 1


def test_envelope_errors(gw: Harness) -> None:
    assert gw.post(b"{not json").status_code == 400
    assert gw.post({"batch_id": "x"}).status_code == 422
    too_many = batch([fresh_event(str(i)) for i in range(1001)])
    assert gw.post(too_many).status_code == 413
    v2 = batch([fresh_event("v")])
    v2["schema_version"] = "2.0"
    assert gw.post(v2).status_code == 422


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_non_json_float_tokens_are_rejected(gw: Harness, token: str) -> None:
    body = json.dumps(batch([fresh_event("nan")])).replace(
        '"synthetic": true', f'"synthetic": {token}'
    )
    assert token in body
    response = gw.post(body.encode())
    assert response.status_code == 400
    assert gw.rows("event") == []


def test_schema_1_0_batches_are_still_accepted(gw: Harness) -> None:
    rec = fresh_event("old")
    rec["data"]["schema_version"] = "1.0"
    body = batch([rec])
    body["schema_version"] = "1.0"
    assert gw.post(body).json()["accepted"] == 1


# ── authorization ─────────────────────────────────────────────────────


def test_unauthorized_record_rejects_whole_batch_and_is_audited(gw: Harness) -> None:
    foreign = fresh_event(
        "mac",
        asset_id=MACOS_ASSET,
        asset_type="macos_host",
        source_type="macos.unified_log",
        event_type="system.log.notable",
        category="other",
    )
    response = gw.post(batch([fresh_event("ok"), foreign]))
    assert response.status_code == 403
    assert "asset_not_allowed" in response.json()["denied"][0]
    assert gw.rows("event") == []
    audit = gw.rows("ingest_audit")[-1]
    assert audit["decision"] == "forbidden"
    assert audit["authenticated_producer"] == "linux-ssh-lab-vm-01"


def test_claimed_producer_must_match_token(gw: Harness) -> None:
    response = gw.post(batch([fresh_event("x")], producer="github-collector"))
    assert response.status_code == 403
    audit = gw.rows("ingest_audit")[-1]
    assert audit["claimed_producer"] == "github-collector"
    assert audit["reason"] == "producer_id_mismatch"


def test_source_type_and_kind_authorization(gw: Harness) -> None:
    sim = record(
        "simulation_run",
        {
            "run_id": "synth0001",
            "scenario_id": "VM-001",
            "asset_id": LINUX_ASSET,
            "status": "started",
            "started_at": utc_now().isoformat(),
            "operator": "synthetic",
            "description": "SYNTHETIC",
        },
    )
    response = gw.post(batch([sim]))
    assert response.status_code == 403 and "kind_not_allowed" in response.json()["denied"][0]
    otel = fresh_event("k8s", asset_id="k8s:extorq-lab", asset_type="kubernetes_cluster")
    response = gw.post(
        batch([otel], producer="k8s-otel-extorq-lab"), producer="k8s-otel-extorq-lab"
    )
    assert response.status_code == 403
    assert "source_type_not_allowed" in response.json()["denied"][0]


# ── per-record processing ────────────────────────────────────────────


def test_invalid_record_is_quarantined_and_batch_continues(gw: Harness) -> None:
    bad = fresh_event("bad")
    bad["data"]["event_id"] = "not-hex"
    bad["data"]["message"] = "x" * 3000 + " password=hunter2-synthetic"
    response = gw.post(batch([fresh_event("good"), bad]))
    assert response.status_code == 202
    body = response.json()
    assert body["accepted"] == 1 and body["rejected"] == 1
    assert body["quarantined"][0]["index"] == 1
    assert "event_id" in body["quarantined"][0]["reason"]
    (q,) = gw.rows("quarantine")
    assert len(q["payload_excerpt"].encode()) <= 4096
    assert "hunter2-synthetic" not in q["payload_excerpt"]
    assert len(q["payload_sha256"]) == 64


def test_time_sanity_quarantines_future_and_ancient_events(gw: Harness) -> None:
    future = record("event", event_data("f", event_time=utc_now() + timedelta(days=2)))
    ancient = record("event", event_data("a", event_time=utc_now() - timedelta(days=401)))
    body = gw.post(batch([future, ancient, fresh_event("now")])).json()
    reasons = sorted(q["reason"] for q in body["quarantined"])
    assert reasons[1] == "time: event_time_in_future"
    assert reasons[0].startswith("older_than_retention: ")
    assert body["accepted"] == 1


def test_events_older_than_the_events_retention_are_quarantined(gw: Harness) -> None:
    """PLAN §11: 90-400 days old used to be accepted (202) and then expired by the TTL."""
    inside = record("event", event_data("in", event_time=utc_now() - timedelta(days=89)))
    beyond = record("event", event_data("out", event_time=utc_now() - timedelta(days=91)))
    body = gw.post(batch([inside, beyond])).json()
    assert body["accepted"] == 1 and body["rejected"] == 1
    (notice,) = body["quarantined"]
    assert notice["index"] == 1
    assert notice["reason"].startswith("older_than_retention: ")
    assert "90 days" in notice["reason"]
    (q,) = gw.rows("quarantine")
    assert q["reason"] == notice["reason"] and q["record_kind"] == "event"
    (stored,) = gw.rows("event")
    assert stored["data"]["event_id"] == inside["data"]["event_id"]


def test_retention_is_configurable_and_reported_in_status(tmp_path: Path) -> None:
    harness = Harness(tmp_path, event_retention_days=30)
    with harness.client:
        body = harness.post(
            batch([record("event", event_data("x", event_time=utc_now() - timedelta(days=31)))])
        ).json()
        status = harness.client.get(
            "/v1/status", headers={"Authorization": f"Bearer {TOKENS['linux-ssh-lab-vm-01']}"}
        ).json()
    harness.spool.close()
    assert body["quarantined"][0]["reason"].startswith("older_than_retention: ")
    assert "30 days" in body["quarantined"][0]["reason"]
    assert status["limits"]["event_retention_days"] == 30
    assert status["limits"]["max_future_seconds"] == 86400


def test_retention_only_applies_to_event_time(gw: Harness) -> None:
    """Other kinds keep their own TTL columns; only future timestamps are refused there."""
    old = utc_now() - timedelta(days=200)
    inventory = record(
        "inventory_item", {**inventory_data(), "observed_at": old.isoformat(), "item_key": "old"}
    )
    late_observed = record(
        "event",
        event_data(
            "late",
            event_time=utc_now() - timedelta(days=1),
            observed_time=(utc_now() - timedelta(minutes=1)).isoformat(),
        ),
    )
    body = gw.post(batch([inventory, late_observed])).json()
    assert body["accepted"] == 2 and body["rejected"] == 0


def test_default_retention_matches_the_events_ttl() -> None:
    """The gateway window and ``extorq.events`` TTL must never drift apart."""
    ddl = (
        Path(__file__).resolve().parents[3]
        / "infra"
        / "clickhouse"
        / "migrations"
        / "0001_core_tables.sql"
    ).read_text(encoding="utf-8")
    match = re.search(
        r"CREATE TABLE IF NOT EXISTS extorq\.events\b.*?"
        r"TTL toDateTime\(event_time\) \+ INTERVAL (\d+) DAY",
        ddl,
        re.DOTALL,
    )
    assert match is not None, "events TTL not found in 0001_core_tables.sql"
    ttl_days = int(match.group(1))
    assert Settings().event_retention_days == ttl_days
    expected = timedelta(days=ttl_days)
    assert expected == processing.EVENTS_RETENTION == processing.Limits().retention


def test_json_attributes_keep_booleans_numbers_and_nulls(gw: Harness) -> None:
    """B2-IC-2: ``"automount_sa_token":false`` used to become ``[REDACTED:secret]`` and
    turned ``attributes.request_summary`` into invalid JSON on every pod create."""
    summary = json.dumps(
        {
            "kind": "Pod",
            "automount_sa_token": False,
            "host_network": False,
            "secret_volumes": 0,
            "token_ttl": None,
            "password": "-".join(["pw", "synthetic", "123"]),  # built at runtime
        },
        separators=(",", ":"),
    )
    rec = fresh_event("summary")
    rec["data"]["attributes"] = {"request_summary": summary, "automount_sa_token": False}
    body = gw.post(batch([rec])).json()
    assert body["accepted"] == 1 and body["rejected"] == 0
    (stored,) = gw.rows("event")
    attributes = stored["data"]["attributes"]
    parsed = json.loads(attributes["request_summary"])  # still valid JSON
    assert parsed["automount_sa_token"] is False and parsed["secret_volumes"] == 0
    assert parsed["token_ttl"] is None and parsed["password"] == "[REDACTED:secret]"
    assert attributes["automount_sa_token"] is False
    assert stored["data"]["provenance"]["redaction_count"] == 1


def test_secrets_are_redacted_and_counted_before_persistence(gw: Harness) -> None:
    rec = fresh_event("secret")
    token = "ghp_" + "A1b2C3d4" * 5
    rec["data"]["message"] = f"login with {token}"
    rec["data"]["attributes"] = {"cmd": "mysql -u root -pSynthPass1 lab"}
    assert gw.post(batch([rec])).json()["accepted"] == 1
    (stored,) = gw.rows("event")
    text = json.dumps(stored)
    assert token not in text and "SynthPass1" not in text
    assert stored["data"]["provenance"]["redaction_count"] == 2


def test_duplicate_events_and_batch_replay(gw: Harness) -> None:
    first = batch([fresh_event("dup")])
    r1 = gw.post(first).json()
    assert r1["accepted"] == 1 and not r1["replayed"]
    replay = gw.post(first).json()
    assert replay == {**r1, "replayed": True}
    again = gw.post(batch([fresh_event("dup")])).json()
    assert again["accepted"] == 0 and again["duplicates"] == 1
    assert len(gw.rows("event")) == 1
    conflict = dict(first)
    conflict["records"] = [fresh_event("different")]
    assert gw.post(conflict).status_code == 409


def test_unexpected_per_record_exception_quarantines_only_that_record(
    gw: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = processing.record_identity

    def flaky(rec: Any) -> str:
        if isinstance(rec.data, SecurityEvent) and rec.data.message == "boom":
            raise ValueError("synthetic identity failure")
        return real(rec)

    monkeypatch.setattr(processing, "record_identity", flaky)
    boom = fresh_event("boom")
    boom["data"]["message"] = "boom"
    body = gw.post(batch([fresh_event("fine"), boom])).json()
    assert body["accepted"] == 1
    assert body["quarantined"][0]["reason"] == "record_not_serialisable:ValueError"


def test_service_records_are_accepted_and_unattributable_instances_quarantined(gw: Harness) -> None:
    svc = service_data()
    inst = service_instance_data()
    now = utc_now().isoformat()
    svc["first_seen"] = svc["last_seen"] = svc["last_telemetry_at"] = now
    inst["observed_at"] = inst["started_at"] = now
    orphan = dict(inst, asset_id=None)
    body = gw.post(
        batch(
            [
                record("service", svc),
                record("service_instance", inst),
                record("service_instance", orphan),
            ]
        )
    ).json()
    assert body["accepted"] == 2
    assert body["quarantined"][0]["reason"].startswith("asset_unattributable")
    assert gw.rows("service")[0]["data"]["service_id"] == svc["service_id"]


def test_spool_backpressure_returns_503_with_retry_after(tmp_path: Path) -> None:
    harness = Harness(tmp_path, spool_max_records=1)
    with harness.client:
        assert harness.post(batch([fresh_event("1")])).status_code == 202
        response = harness.post(batch([fresh_event("2")]))
    harness.spool.close()
    assert response.status_code == 503
    assert response.headers["retry-after"] == "30"


# ── OTLP ──────────────────────────────────────────────────────────────

OTLP = {
    "resourceLogs": [
        {
            "scopeLogs": [
                {"logRecords": [{"body": {"stringValue": "x"}}, {"body": {"stringValue": "y"}}]}
            ]
        }
    ]
}


def test_otlp_returns_503_until_normaliser_exists(gw: Harness) -> None:
    response = gw.post(OTLP, producer="k8s-otel-extorq-lab", path="/v1/otlp/v1/logs")
    assert response.status_code == 503 and "otlp_k8s" in response.json()["detail"]


def test_otlp_with_fake_normaliser(tmp_path: Path) -> None:
    def normalizer(
        payload: dict[str, Any], *, producer_id: str, received_at: Any
    ) -> tuple[list[SecurityEvent], list[tuple[int, str]]]:
        event = SecurityEvent.model_validate(
            event_data(
                "otlp",
                asset_id="k8s:extorq-lab",
                asset_type="kubernetes_cluster",
                source_type="k8s.container_log",
                event_type="k8s.container.log",
                category="kubernetes_workload",
                event_time=utc_now(),
            )
        )
        return [event], [(1, "unparseable synthetic line")]

    harness = Harness(tmp_path, normalizer=normalizer)
    with harness.client:
        ok = harness.post(OTLP, producer="k8s-otel-extorq-lab", path="/v1/otlp/v1/logs")
        replay = harness.post(OTLP, producer="k8s-otel-extorq-lab", path="/v1/otlp/v1/logs")
        proto = harness.post(
            b"\x00",
            producer="k8s-otel-extorq-lab",
            path="/v1/otlp/v1/logs",
            headers={"Content-Type": "application/x-protobuf"},
        )
        nan = harness.post(
            b'{"resourceLogs": NaN}', producer="k8s-otel-extorq-lab", path="/v1/otlp/v1/logs"
        )
        wrong = harness.post(OTLP, producer="linux-ssh-lab-vm-01", path="/v1/otlp/v1/logs")
        events = harness.rows("event")
    harness.spool.close()
    assert ok.status_code == 200
    assert ok.json()["partialSuccess"]["rejectedLogRecords"] == 1
    assert replay.status_code == 200
    assert len(events) == 1
    assert proto.status_code == 415 and nan.status_code == 400
    assert wrong.status_code == 403  # producer not allowed k8s source types / assets


def test_service_identity_must_derive_from_its_own_fields(gw: Harness) -> None:
    """F-19: a producer cannot publish rows under another asset's service id."""
    from extorq.contracts.identity import instance_id, service_id

    now = utc_now().isoformat()
    svc = service_data()
    svc["first_seen"] = svc["last_seen"] = svc["last_telemetry_at"] = now
    svc["service_id"] = service_id(MACOS_ASSET, "host_service", "com.openssh.sshd")
    inst = service_instance_data()
    inst["observed_at"] = inst["started_at"] = now
    inst["instance_id"] = instance_id(inst["service_id"], "process", "9999:1")
    body = gw.post(batch([record("service", svc), record("service_instance", inst)])).json()
    assert body["accepted"] == 0
    assert [q["reason"].split(":")[0] for q in body["quarantined"]] == [
        "identity_mismatch",
        "identity_mismatch",
    ]
