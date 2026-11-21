"""Alert endpoints: list, detail/evidence, context, assessments, summary, state."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
from api_fakes import (
    NOW,
    FakeIntegrations,
    FakeRepository,
    alert_row,
    assessment,
    asset_row,
    event_row,
    hexid,
    make_context,
    rule_row,
)
from fastapi.testclient import TestClient

from extorq.api.errors import ServiceUnavailable
from extorq.contracts import AIStatus


def _seed_alert(repo: FakeRepository, label: str = "a1", **kw: Any) -> str:
    row = alert_row(label, **kw)
    repo.alerts.append(row)
    return str(row["alert_id"])


# ── list ──────────────────────────────────────────────────────────────────────────


def test_list_alerts_maps_rows_and_paginates(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    for i in range(3):
        _seed_alert(repo, f"a{i}", last_seen=NOW - timedelta(minutes=10 + i))
    response = client.get("/api/v1/alerts", headers=analyst, params={"limit": 2})
    assert response.status_code == 200
    body = response.json()
    assert [item["analyst_status"] for item in body["items"]] == ["new", "new"]
    assert body["items"][0]["analyst_state_recorded"] is False
    assert body["page"] == {
        "limit": 2,
        "offset": 0,
        "returned": 2,
        "has_more": True,
        "next_offset": 2,
        "total": 3,
    }
    second = client.get("/api/v1/alerts", headers=analyst, params={"limit": 2, "offset": 2})
    assert second.json()["page"]["has_more"] is False
    assert second.json()["page"]["next_offset"] is None


def test_list_alerts_default_range_and_filters_reach_repository(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    response = client.get(
        "/api/v1/alerts",
        headers=analyst,
        params=[
            ("severity", "high"),
            ("severity", "critical"),
            ("status", "new"),
            ("rule_id", "VM-001"),
            ("asset_id", "github:owner/extorq-lab"),
            ("open_only", "true"),
            ("sort", "severity"),
        ],
    )
    assert response.status_code == 200
    filters = repo.last_call("list_alerts")
    assert filters.severities == ("high", "critical")
    assert filters.statuses == ("new",)
    assert filters.rule_id == "VM-001"
    assert filters.asset_id == "github:owner/extorq-lab"
    assert filters.open_only is True
    assert filters.sort == "severity"
    assert filters.since == NOW - timedelta(days=30)
    assert filters.until == NOW + timedelta(days=1)


@pytest.mark.parametrize(
    "params",
    [
        {"since": "2026-11-20T10:00:00"},  # naive
        {"since": "2026-11-21T10:00:00Z", "until": "2026-11-21T09:00:00Z"},
        {"since": "2024-01-01T00:00:00Z", "until": "2026-11-21T00:00:00Z"},  # > 400 days
    ],
)
def test_list_alerts_rejects_bad_ranges(
    client: TestClient, analyst: dict[str, str], params: dict[str, str]
) -> None:
    assert client.get("/api/v1/alerts", headers=analyst, params=params).status_code == 400


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 201},
        {"offset": 10_001},
        {"rule_id": "vm-001"},
        {"asset_id": "UPPER:case"},
        {"sort": "alert_id"},
        {"severity": "urgent"},
    ],
)
def test_list_alerts_rejects_invalid_parameters(
    client: TestClient, analyst: dict[str, str], params: dict[str, Any]
) -> None:
    assert client.get("/api/v1/alerts", headers=analyst, params=params).status_code == 422


# ── detail / evidence ─────────────────────────────────────────────────────────────


def test_alert_detail_resolves_evidence_and_reports_unresolved(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    trigger = event_row("trigger")
    supporting = event_row("supporting", event_time=NOW - timedelta(minutes=59))
    missing_id = hexid("event:missing")
    array_only_missing = hexid("event:array-only")
    alert_id = _seed_alert(
        repo,
        evidence_event_ids=[trigger["event_id"], array_only_missing],
        evidence_truncated=1,
    )
    repo.events[trigger["event_id"]] = trigger
    repo.events[supporting["event_id"]] = supporting
    repo.evidence[alert_id] = [
        {"event_id": supporting["event_id"], "role": "supporting", "added_at": NOW},
        {"event_id": missing_id, "role": "supporting", "added_at": NOW},
        {"event_id": trigger["event_id"], "role": "trigger", "added_at": NOW},
    ]
    repo.rules.append(rule_row())
    repo.assets.append(asset_row())

    response = client.get(f"/api/v1/alerts/{alert_id}", headers=analyst)
    assert response.status_code == 200
    body = response.json()
    assert [e["event_id"] for e in body["evidence"]] == [
        trigger["event_id"],
        supporting["event_id"],
    ]
    assert body["evidence"][0]["role"] == "trigger"
    assert body["evidence"][0]["attributes"] == {"auth_method": "password"}
    # Untrusted text is returned verbatim as JSON data (rendered as text by clients).
    assert body["evidence"][0]["message"] == "<b>synthetic</b> message"
    assert body["unresolved_evidence_ids"] == [missing_id, array_only_missing]
    assert body["evidence_total"] == 4
    assert body["evidence_capped"] is False
    assert body["alert"]["evidence_truncated"] is True
    assert body["alert"]["features"] == {"distinct_connections": 6}
    assert body["analyst_state"] == {
        "status": "new",
        "assignee": None,
        "note": None,
        "updated_by": None,
        "updated_at": None,
        "recorded": False,
    }
    assert body["rule"]["false_positives"] == ["synthetic fp"]
    assert body["asset"]["asset_id"] == "linux:lab-vm-01"


def test_alert_detail_404_and_422(client: TestClient, analyst: dict[str, str]) -> None:
    assert client.get("/api/v1/alerts/" + "a" * 32, headers=analyst).status_code == 404
    assert client.get("/api/v1/alerts/not-hex", headers=analyst).status_code == 422
    assert client.get("/api/v1/alerts/" + "A" * 32, headers=analyst).status_code == 422


# ── state mutation ────────────────────────────────────────────────────────────────


def test_state_change_writes_audit_row_before_state(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    alert_id = _seed_alert(repo)
    response = client.post(
        f"/api/v1/alerts/{alert_id}/state",
        headers=analyst,
        json={"status": "investigating", "assignee": "alice", "note": "looking\ninto it"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"]["status"] == "investigating"
    assert body["state"]["updated_by"] == "alice"
    assert body["state"]["recorded"] is True
    assert [table for table, _ in repo.writes] == ["analyst_actions", "analyst_state"]
    action = repo.writes[0][1]
    assert action["action_id"] == body["action_id"]
    assert action["actor"] == "alice"
    assert action["role"] == "analyst"
    assert action["action"] == "alert_state_changed"
    assert action["alert_id"] == alert_id
    details = json.loads(action["details"])
    assert details["previous_status"] is None
    assert details["status"] == "investigating"
    assert details["note"] == "looking\ninto it"
    state = repo.writes[1][1]
    assert state["updated_at"] == NOW
    assert state["status"] == "investigating"


def test_state_change_records_previous_state(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    alert_id = _seed_alert(repo)
    repo.states[alert_id] = {
        "alert_id": alert_id,
        "status": "acknowledged",
        "assignee": "bob",
        "note": None,
        "updated_by": "bob",
        "updated_at": NOW - timedelta(hours=1),
    }
    response = client.post(
        f"/api/v1/alerts/{alert_id}/state",
        headers=analyst,
        json={"status": "closed_benign"},
    )
    assert response.status_code == 200
    details = json.loads(repo.writes[0][1]["details"])
    assert details["previous_status"] == "acknowledged"
    assert details["previous_assignee"] == "bob"


def test_state_change_unknown_alert_writes_nothing(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    response = client.post(
        "/api/v1/alerts/" + "b" * 32 + "/state", headers=analyst, json={"status": "acknowledged"}
    )
    assert response.status_code == 404
    assert repo.writes == []


def test_state_change_optimistic_concurrency_conflict(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    alert_id = _seed_alert(repo)
    repo.states[alert_id] = {
        "alert_id": alert_id,
        "status": "acknowledged",
        "assignee": None,
        "note": None,
        "updated_by": "bob",
        "updated_at": NOW - timedelta(minutes=1),
    }
    stale = (NOW - timedelta(minutes=5)).isoformat()
    conflict = client.post(
        f"/api/v1/alerts/{alert_id}/state",
        headers=analyst,
        json={"status": "investigating", "expected_updated_at": stale},
    )
    assert conflict.status_code == 409
    assert repo.writes == []
    fresh = (NOW - timedelta(minutes=1)).isoformat()
    ok = client.post(
        f"/api/v1/alerts/{alert_id}/state",
        headers=analyst,
        json={"status": "investigating", "expected_updated_at": fresh},
    )
    assert ok.status_code == 200


def test_state_change_fails_closed_when_audit_unwritable(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    alert_id = _seed_alert(repo)
    repo.fail_action_insert = True
    response = client.post(
        f"/api/v1/alerts/{alert_id}/state", headers=analyst, json={"status": "acknowledged"}
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "audit log is unavailable; no change was made"
    assert repo.writes == []
    assert alert_id not in repo.states


def test_state_write_failure_is_audited(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    alert_id = _seed_alert(repo)
    repo.fail_state_insert = True
    response = client.post(
        f"/api/v1/alerts/{alert_id}/state", headers=analyst, json={"status": "acknowledged"}
    )
    assert response.status_code == 503
    actions = [row["action"] for table, row in repo.writes if table == "analyst_actions"]
    assert actions == ["alert_state_changed", "alert_state_change_failed"]


@pytest.mark.parametrize(
    "body",
    [
        {"status": "deleted"},
        {"status": "acknowledged", "note": "bell\x07"},
        {"status": "acknowledged", "assignee": "bad name"},
        {"status": "acknowledged", "note": "x" * 2049},
        {"status": "acknowledged", "severity": "info"},  # extra field: AI/analysts can't edit
        {},
    ],
)
def test_state_change_validates_body(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository, body: dict[str, Any]
) -> None:
    alert_id = _seed_alert(repo)
    response = client.post(f"/api/v1/alerts/{alert_id}/state", headers=analyst, json=body)
    assert response.status_code == 422
    assert repo.writes == []


# ── context ───────────────────────────────────────────────────────────────────────


def test_context_returns_stored_context(
    client: TestClient,
    analyst: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    alert_id = _seed_alert(repo)
    integrations.stored[alert_id] = make_context(alert_id)
    body = client.get(f"/api/v1/alerts/{alert_id}/context", headers=analyst).json()
    assert body["source"] == "stored"
    assert body["persisted"] is True
    assert body["context"]["alert_id"] == alert_id
    assert repo.writes == []


def test_context_built_on_demand_is_persisted_for_analysts_with_audit(
    client: TestClient,
    analyst: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    alert_id = _seed_alert(repo)
    integrations.buildable[alert_id] = make_context(alert_id)
    body = client.get(f"/api/v1/alerts/{alert_id}/context", headers=analyst).json()
    assert body["source"] == "built_on_demand"
    assert body["persisted"] is True
    assert len(integrations.saved) == 1
    assert [row["action"] for _, row in repo.writes] == ["context_built"]


def test_context_built_for_viewer_is_ephemeral(
    client: TestClient,
    viewer: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    alert_id = _seed_alert(repo)
    integrations.buildable[alert_id] = make_context(alert_id)
    body = client.get(f"/api/v1/alerts/{alert_id}/context", headers=viewer).json()
    assert body["source"] == "built_on_demand"
    assert body["persisted"] is False
    assert integrations.saved == []
    assert repo.writes == []


def test_context_unavailable_module_is_503(
    client: TestClient,
    analyst: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    alert_id = _seed_alert(repo)
    integrations.load_error = ServiceUnavailable(
        "correlation store (extorq.correlation.store) is not installed"
    )
    response = client.get(f"/api/v1/alerts/{alert_id}/context", headers=analyst)
    assert response.status_code == 503
    assert "extorq.correlation.store" in response.json()["detail"]


def test_context_builder_crash_is_reported_without_details(
    client: TestClient,
    analyst: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    alert_id = _seed_alert(repo)
    integrations.build_error = KeyError("internal")
    response = client.get(f"/api/v1/alerts/{alert_id}/context", headers=analyst)
    assert response.status_code == 500
    assert response.json()["detail"] == "investigation context could not be built"


def test_context_404_for_unknown_alert(client: TestClient, analyst: dict[str, str]) -> None:
    assert client.get("/api/v1/alerts/" + "c" * 32 + "/context", headers=analyst).status_code == 404


# ── assessments ───────────────────────────────────────────────────────────────────


def test_assessments_via_ai_store_newest_first(
    client: TestClient,
    analyst: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    alert_id = _seed_alert(repo)
    older = assessment(alert_id, created_at=NOW - timedelta(hours=1), status=AIStatus.TIMEOUT)
    newer = assessment(alert_id, created_at=NOW)
    assert integrations.assessments is not None
    integrations.assessments[alert_id] = [older, newer]
    body = client.get(f"/api/v1/alerts/{alert_id}/assessments", headers=analyst).json()
    assert body["source"] == "ai.store"
    assert [a["status"] for a in body["items"]] == ["ok", "timeout"]


def test_assessments_direct_fallback_parses_e_row_format(
    client: TestClient,
    analyst: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    alert_id = _seed_alert(repo)
    integrations.assessments = None  # E's store module absent
    base = assessment(alert_id).model_dump(mode="python")
    good = {k: base[k] for k in base if k not in ("triage", "summary", "validation")}
    good.update(
        {
            "provider": "google-gemini",
            "task": "summary",
            "status": "ok",
            "recommendation": None,
            "uncertain": None,
            "output": json.dumps(
                {"requested_model": "m", "triage": None, "summary": None, "validation": None}
            ),
        }
    )
    broken = dict(good, assessment_id=hexid("broken"), status="not-a-status")
    repo.direct_assessments = [good, broken]
    body = client.get(f"/api/v1/alerts/{alert_id}/assessments", headers=analyst).json()
    assert body["source"] == "direct"
    assert len(body["items"]) == 1
    assert body["invalid_records"] == 1


# ── summary ───────────────────────────────────────────────────────────────────────


def test_summary_success_is_audited_and_attributed(
    client: TestClient,
    analyst: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    alert_id = _seed_alert(repo)
    integrations.summary_result = assessment(alert_id)
    response = client.post(f"/api/v1/alerts/{alert_id}/summary", headers=analyst)
    assert response.status_code == 200, response.text
    assert response.json()["assessment"]["status"] == "ok"
    assert integrations.summary_calls == [(alert_id, "analyst:alice")]
    assert [row["action"] for _, row in repo.writes] == ["ai_summary_requested"]


def test_summary_disabled_is_graceful_503(
    client: TestClient,
    analyst: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    alert_id = _seed_alert(repo)
    integrations.summary_result = assessment(
        alert_id, status=AIStatus.DISABLED, error="EXTORQ_GEMINI_ENABLED is false"
    )
    response = client.post(f"/api/v1/alerts/{alert_id}/summary", headers=analyst)
    assert response.status_code == 503
    assert response.json()["detail"] == (
        "AI summaries are unavailable: EXTORQ_GEMINI_ENABLED is false"
    )


def test_summary_budget_refusal_is_returned_not_hidden(
    client: TestClient,
    analyst: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    alert_id = _seed_alert(repo)
    integrations.summary_result = assessment(
        alert_id, status=AIStatus.BUDGET_EXCEEDED, error="cooldown_active"
    )
    response = client.post(f"/api/v1/alerts/{alert_id}/summary", headers=analyst)
    assert response.status_code == 200
    assert response.json()["assessment"]["status"] == "budget_exceeded"


def test_summary_module_absent_is_503(
    client: TestClient,
    analyst: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    alert_id = _seed_alert(repo)
    integrations.summary_error = ServiceUnavailable("AI summary service is not installed")
    response = client.post(f"/api/v1/alerts/{alert_id}/summary", headers=analyst)
    assert response.status_code == 503


def test_summary_unexpected_failure_is_503(
    client: TestClient,
    analyst: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    alert_id = _seed_alert(repo)
    integrations.summary_error = RuntimeError("provider exploded with detail")
    response = client.post(f"/api/v1/alerts/{alert_id}/summary", headers=analyst)
    assert response.status_code == 503
    assert "exploded" not in response.text


def test_summary_unknown_alert_does_not_call_ai(
    client: TestClient, analyst: dict[str, str], integrations: FakeIntegrations
) -> None:
    response = client.post("/api/v1/alerts/" + "d" * 32 + "/summary", headers=analyst)
    assert response.status_code == 404
    assert integrations.summary_calls == []


def test_summary_rate_limit_per_user(
    client: TestClient,
    analyst: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    alert_id = _seed_alert(repo)
    integrations.summary_result = assessment(alert_id)
    statuses = [
        client.post(f"/api/v1/alerts/{alert_id}/summary", headers=analyst).status_code
        for _ in range(7)
    ]
    assert statuses[:6] == [200] * 6
    assert statuses[6] == 429


def test_summary_in_flight_conflict(
    client: TestClient,
    analyst: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    alert_id = _seed_alert(repo)
    integrations.summary_result = assessment(alert_id)
    gate = client.app.state.summary_gate  # type: ignore[attr-defined]
    gate.acquire("someone-else", alert_id)
    response = client.post(f"/api/v1/alerts/{alert_id}/summary", headers=analyst)
    assert response.status_code == 409
    gate.release(alert_id)
    assert client.post(f"/api/v1/alerts/{alert_id}/summary", headers=analyst).status_code == 200
