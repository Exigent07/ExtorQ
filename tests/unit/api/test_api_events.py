"""Event search and single-event retrieval."""

from __future__ import annotations

from datetime import timedelta

import pytest
from api_fakes import NOW, FakeRepository, event_row, hexid
from fastapi.testclient import TestClient

from extorq.contracts import SecurityEvent
from extorq.contracts.identity import canonical_json


def _payload(event_id: str) -> str:
    event = SecurityEvent(
        event_id=event_id,
        event_type="auth.ssh.login_failed",
        category="authentication",
        asset_id="linux:lab-vm-01",
        asset_type="linux_host",
        source={
            "source_type": "linux.journald",
            "collector_id": "synthetic-collector",
            "collector_version": "0.0.0",
            "collection_method": "ssh_pull",
        },
        event_time=NOW - timedelta(hours=1),
        outcome="failure",
        message="synthetic <script>alert(1)</script>",
        provenance={"parser": "synthetic-parser", "parser_version": "0"},
    )
    return canonical_json(event.model_dump(mode="json"))


def test_event_search_default_window_and_has_more(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    for i in range(3):
        row = event_row(f"e{i}", event_time=NOW - timedelta(minutes=i + 1))
        repo.events[row["event_id"]] = row
    old = event_row("old", event_time=NOW - timedelta(days=2))
    repo.events[old["event_id"]] = old
    response = client.get("/api/v1/events", headers=analyst, params={"limit": 2})
    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) == 2
    assert body["page"]["has_more"] is True
    assert body["page"]["total"] is None
    assert body["range"]["since"].startswith("2026-11-20T12:00:00")
    assert body["range"]["until"].startswith("2026-11-22T12:00:00")
    assert "attributes" not in body["items"][0]
    filters = repo.last_call("list_events")
    assert filters.since == NOW - timedelta(hours=24)


def test_event_search_normalises_ip_and_maps_filters(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    response = client.get(
        "/api/v1/events",
        headers=analyst,
        params={
            "src_ip": " 2001:DB8::0001 ",
            "actor": "root",
            "event_type_prefix": "auth.ssh.",
            "source_type": "linux.journald",
            "outcome": "failure",
        },
    )
    assert response.status_code == 200
    filters = repo.last_call("list_events")
    assert filters.src_ip == "2001:db8::1"
    assert filters.actor == "root"
    assert filters.event_type_prefix == "auth.ssh."
    assert filters.source_type == "linux.journald"
    assert filters.outcome == "failure"


@pytest.mark.parametrize(
    ("params", "status"),
    [
        ({"src_ip": "10.0.0.300"}, 400),
        ({"since": "2026-10-01T00:00:00Z", "until": "2026-11-21T00:00:00Z"}, 400),
        ({"limit": 501}, 422),
        ({"source_type": "linux.unknown"}, 422),
        ({"event_type": "Auth.SSH"}, 422),
        ({"actor": "x" * 257}, 422),
    ],
)
def test_event_search_rejects_bad_input(
    client: TestClient, analyst: dict[str, str], params: dict[str, object], status: int
) -> None:
    assert client.get("/api/v1/events", headers=analyst, params=params).status_code == status


def test_event_detail_returns_contract_event(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    event_id = hexid("event:detail")
    repo.payloads[event_id] = {
        "event_id": event_id,
        "payload": _payload(event_id),
        "ingested_time": NOW,
        "producer_id": "synthetic-producer",
        "batch_id": "b" * 32,
    }
    repo.evidence[hexid("alert:x")] = [{"event_id": event_id, "role": "trigger", "added_at": NOW}]
    response = client.get(f"/api/v1/events/{event_id}", headers=analyst)
    assert response.status_code == 200
    body = response.json()
    assert body["event"]["event_id"] == event_id
    assert body["event"]["message"] == "synthetic <script>alert(1)</script>"
    assert body["ingest"]["producer_id"] == "synthetic-producer"
    assert body["alert_ids"] == [hexid("alert:x")]
    assert response.headers["content-type"].startswith("application/json")


def test_event_detail_invalid_stored_payload_is_reported(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    event_id = hexid("event:broken")
    repo.payloads[event_id] = {
        "event_id": event_id,
        "payload": '{"event_id": "not valid"}',
        "ingested_time": NOW,
        "producer_id": "p",
        "batch_id": "b",
    }
    response = client.get(f"/api/v1/events/{event_id}", headers=analyst)
    assert response.status_code == 500
    assert response.json()["detail"] == "stored event failed contract validation"


def test_event_detail_404_and_422(client: TestClient, analyst: dict[str, str]) -> None:
    assert client.get("/api/v1/events/" + "e" * 32, headers=analyst).status_code == 404
    assert client.get("/api/v1/events/xyz", headers=analyst).status_code == 422
