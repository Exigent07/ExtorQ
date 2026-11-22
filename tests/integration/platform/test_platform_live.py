"""Platform integration tests against the running stack (``-m integration``).

Requires ``make up`` + ``make up-debug``. Sends a handful of SYNTHETIC events
(see platform_live.py); never stops or restarts anything.
"""

from __future__ import annotations

import gzip
import json
import uuid

import pytest
from clickhouse_connect.driver.exceptions import DatabaseError, Error
from platform_live import (
    ASSET,
    batch,
    client,
    event_counts,
    post,
    require_stack,
    synthetic_event,
    token,
    wait_for,
)

pytestmark = [pytest.mark.integration, pytest.mark.timeout(240)]


@pytest.fixture(scope="module", autouse=True)
def _stack() -> None:
    require_stack()


def _error_code(exc: BaseException) -> int | None:
    code = getattr(exc, "code", None)
    if code is not None:
        return int(code)
    text = str(exc)
    marker = "Code: "
    if marker in text:
        digits = text.split(marker, 1)[1].split(".", 1)[0].strip()
        return int(digits) if digits.isdigit() else None
    return None


# ── round trip / dedup / replay ───────────────────────────────────────


def test_https_ingest_round_trip_into_clickhouse() -> None:
    marker = uuid.uuid4().hex
    event = synthetic_event(marker)
    body = gzip.compress(json.dumps(batch([{"kind": "event", "data": event}])).encode())
    import httpx
    from platform_live import GATEWAY, tls

    response = httpx.post(
        f"{GATEWAY}/v1/ingest",
        content=body,
        verify=tls(),
        timeout=15,
        headers={
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "Authorization": f"Bearer {token()}",
        },
    )
    assert response.status_code == 202, response.text
    assert response.json()["accepted"] == 1
    rows = wait_for(
        lambda: (
            client("api_ro")
            .query(
                "SELECT producer_id, asset_id, labels['synthetic'], schema_version "
                "FROM extorq.events WHERE event_id = {id:String}",
                parameters={"id": event["event_id"]},
            )
            .result_rows
        ),
        lambda r: bool(r),
    )
    assert rows == [("macos-workstation-01", ASSET, "true", "1.1")]


def test_duplicate_batches_and_events_do_not_inflate_counts() -> None:
    marker = uuid.uuid4().hex
    events = [synthetic_event(marker, i) for i in range(3)]
    first = batch([{"kind": "event", "data": e} for e in events])
    r1 = post(first, bearer=token())
    assert r1.status_code == 202 and r1.json()["accepted"] == 3
    replay = post(first, bearer=token())
    assert replay.status_code == 202 and replay.json()["replayed"] is True
    again = post(batch([{"kind": "event", "data": e} for e in events]), bearer=token())
    assert again.json()["duplicates"] == 3 and again.json()["accepted"] == 0
    ids = [e["event_id"] for e in events]
    counts = wait_for(lambda: event_counts(ids), lambda c: c[0] == 3)
    assert counts == (3, 3)  # gateway dedup: no duplicate rows at all, not only uniqExact


# ── authentication / authorization audit ──────────────────────────────


def _audit_rows(reason_like: str, since_marker: str) -> list[tuple[object, ...]]:
    return (
        client("api_ro")
        .query(
            "SELECT decision, reason, claimed_producer, authenticated_producer, path "
            "FROM extorq.ingest_audit WHERE occurred_at > now64(3) - INTERVAL 5 MINUTE "
            "AND reason LIKE {r:String} AND positionCaseInsensitive(reason, {m:String}) > 0",
            parameters={"r": reason_like, "m": since_marker},
        )
        .result_rows
    )


def test_forged_token_is_rejected_and_audited() -> None:
    response = post(
        batch([{"kind": "event", "data": synthetic_event("forged")}]),
        bearer="xtq_p_forged-" + uuid.uuid4().hex,
    )
    assert response.status_code == 401
    rows = wait_for(
        lambda: (
            client("api_ro")
            .query(
                "SELECT count() FROM extorq.ingest_audit WHERE decision = 'unauthenticated' "
                "AND reason = 'invalid_bearer_token' AND occurred_at > now64(3) - INTERVAL 2 MINUTE"
            )
            .result_rows
        ),
        lambda r: r[0][0] > 0,
    )
    assert rows[0][0] > 0


def test_valid_token_sending_another_assets_records_is_403_and_audited() -> None:
    marker = uuid.uuid4().hex
    event = synthetic_event(marker)
    event["asset_id"] = "linux:lab-vm-01"
    event["asset_type"] = "linux_host"
    response = post(batch([{"kind": "event", "data": event}]), bearer=token())
    assert response.status_code == 403
    assert "asset_not_allowed" in response.json()["denied"][0]
    rows = wait_for(
        lambda: (
            client("api_ro")
            .query(
                "SELECT decision, authenticated_producer FROM extorq.ingest_audit "
                "WHERE decision = 'forbidden' AND occurred_at > now64(3) - INTERVAL 2 MINUTE "
                "AND reason LIKE '%asset_not_allowed:linux:lab-vm-01%'"
            )
            .result_rows
        ),
        lambda r: bool(r),
    )
    assert ("forbidden", "macos-workstation-01") in rows
    assert event_counts([event["event_id"]]) == (0, 0)  # nothing from the batch stored


def test_selftest_producer_cannot_send_events() -> None:
    response = post(
        batch([{"kind": "event", "data": synthetic_event("selftest")}], producer="extorq-selftest"),
        bearer=token("extorq-selftest"),
    )
    assert response.status_code == 403
    assert "kind_not_allowed" in response.json()["denied"][0]


# ── ClickHouse RBAC matrix (PLAN §4.4) ────────────────────────────────

DENIED = (497, 164)  # ACCESS_DENIED / READONLY


def _denied(role: str, sql: str) -> int | None:
    try:
        client(role).command(sql)
    except (DatabaseError, Error) as exc:
        return _error_code(exc)
    return None


@pytest.mark.parametrize(
    ("role", "sql"),
    [
        ("ingest", "SELECT count() FROM extorq.alerts"),
        ("ingest", "SELECT count() FROM extorq.events"),
        ("ai", "INSERT INTO extorq.alerts (alert_id) VALUES ('synthetic-denied')"),
        ("api_writer", "INSERT INTO extorq.alerts (alert_id) VALUES ('synthetic-denied')"),
        ("api_ro", "INSERT INTO extorq.analyst_state (alert_id) VALUES ('synthetic-denied')"),
        ("rules_ro", "INSERT INTO extorq.events (event_id) VALUES ('synthetic-denied')"),
        ("rules_ro", "SELECT count() FROM extorq.alerts"),
        ("grafana", "SELECT raw FROM extorq.events LIMIT 1"),
        ("grafana", "SELECT payload FROM extorq.events LIMIT 1"),
        ("grafana", "SELECT payload_excerpt FROM extorq.ingest_quarantine LIMIT 1"),
        ("detect", "INSERT INTO extorq.ai_assessments (assessment_id) VALUES ('synthetic-denied')"),
        ("api_ro", "DROP TABLE extorq.events"),
    ],
)
def test_rbac_denials(role: str, sql: str) -> None:
    code = _denied(role, sql)
    assert code in DENIED, f"{role} was not denied ({code})"


@pytest.mark.parametrize(
    ("role", "sql"),
    [
        ("grafana", "SELECT count(event_id), count(service_id) FROM extorq.events"),
        ("api_ro", "SELECT count() FROM extorq.v_services"),
        ("rules_ro", "SELECT count() FROM extorq.events"),
        ("detect", "SELECT count() FROM extorq.alerts"),
        ("ai", "SELECT count() FROM extorq.ai_assessments"),
    ],
)
def test_rbac_allowed_reads(role: str, sql: str) -> None:
    assert client(role).query(sql).result_rows


def test_default_user_cannot_connect_over_the_network() -> None:
    import clickhouse_connect

    with pytest.raises((DatabaseError, Error)) as err:
        clickhouse_connect.get_client(
            host="127.0.0.1", port=18123, username="default", password="", connect_timeout=5
        ).command("SELECT 1")
    # The user is removed (users.d/10-extorq-users.xml). ClickHouse answers any failed
    # authentication without revealing whether the user exists: UNKNOWN_USER (192),
    # REQUIRED_PASSWORD (194) or AUTHENTICATION_FAILED (516).
    assert _error_code(err.value) in (192, 194, 516)


def test_service_users_have_readonly_profiles_and_quotas() -> None:
    rows = client("api_ro").query("SELECT getSetting('readonly')").result_rows
    assert int(rows[0][0]) == 2
    rows = client("rules_ro").query("SELECT getSetting('readonly')").result_rows
    assert int(rows[0][0]) == 1
    rows = client("grafana").query("SELECT getSetting('max_execution_time')").result_rows
    assert float(rows[0][0]) > 0


def test_gateway_status_reports_schema_1_1_and_no_secrets() -> None:
    import httpx
    from platform_live import GATEWAY, tls

    response = httpx.get(
        f"{GATEWAY}/v1/status",
        verify=tls(),
        timeout=10,
        headers={"Authorization": f"Bearer {token('extorq-selftest')}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == "1.1"
    assert body["producer_id"] == "extorq-selftest"
    assert token("extorq-selftest") not in response.text


def test_live_gateway_quarantines_forged_service_identity() -> None:
    """F-19 on the deployed gateway: a service row must carry its own derived id."""
    from extorq.contracts.common import utc_now
    from extorq.contracts.identity import service_id

    now = utc_now().isoformat()
    forged = {
        "service_id": service_id("linux:lab-vm-01", "host_service", "ssh.service"),
        "asset_id": ASSET,
        "service_kind": "host_service",
        "service_key": "extorq-platform-test.service",
        "name": "extorq-platform-test",
        "category": "other",
        "discovered_via": ["systemd_unit"],
        "adapter_support": "none",
        "monitoring_status": "unmonitored",
        "coverage_note": "SYNTHETIC forged identity probe (agent A)",
        "first_seen": now,
        "last_seen": now,
        "observed_by": "extorq-platform-test",
    }
    response = post(batch([{"kind": "service", "data": forged}]), bearer=token())
    assert response.status_code == 202
    body = response.json()
    assert body["accepted"] == 0
    assert body["quarantined"][0]["reason"].startswith("identity_mismatch")


# ── session 3: retention-aligned quarantine, JSON-safe redaction ─────


def test_live_gateway_quarantines_events_older_than_the_events_retention() -> None:
    """PLAN §11: an event ClickHouse would expire at once is refused, not acknowledged."""
    from datetime import timedelta

    from extorq.contracts.common import utc_now

    marker = uuid.uuid4().hex
    old = synthetic_event(marker, 0)
    old["event_time"] = old["observed_time"] = (utc_now() - timedelta(days=91)).isoformat()
    recent = synthetic_event(marker, 1)
    recent["event_time"] = (utc_now() - timedelta(days=89)).isoformat()
    response = post(
        batch([{"kind": "event", "data": old}, {"kind": "event", "data": recent}]),
        bearer=token(),
    )
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["accepted"] == 1 and body["rejected"] == 1
    assert body["quarantined"][0]["index"] == 0
    assert body["quarantined"][0]["reason"].startswith("older_than_retention: ")
    rows = wait_for(
        lambda: (
            client("api_ro")
            .query(
                "SELECT reason, record_kind FROM extorq.ingest_quarantine "
                "WHERE received_at > now64(3) - INTERVAL 10 MINUTE "
                "AND batch_id = {b:String}",
                parameters={"b": body["batch_id"]},
            )
            .result_rows
        ),
        lambda r: bool(r),
    )
    assert len(rows) == 1 and rows[0][1] == "event"
    assert rows[0][0].startswith("older_than_retention")
    counts = wait_for(lambda: event_counts([recent["event_id"]]), lambda c: c[0] == 1)
    assert counts == (1, 1)
    assert event_counts([old["event_id"]]) == (0, 0)


def test_live_redaction_keeps_json_booleans_in_attributes() -> None:
    """B2-IC-2 on the deployed gateway: JSON in attributes stays valid JSON."""
    marker = uuid.uuid4().hex
    event = synthetic_event(marker)
    summary = json.dumps({"automount_sa_token": False, "secret_volumes": 0, "token_ttl": None})
    event["attributes"] = {"synthetic": True, "test_marker": marker, "request_summary": summary}
    response = post(batch([{"kind": "event", "data": event}]), bearer=token())
    assert response.status_code == 202 and response.json()["accepted"] == 1
    rows = wait_for(
        lambda: (
            client("api_ro")
            .query(
                "SELECT JSONExtractString(attributes, 'request_summary') FROM extorq.events "
                "WHERE event_id = {id:String}",
                parameters={"id": event["event_id"]},
            )
            .result_rows
        ),
        lambda r: bool(r),
    )
    assert json.loads(rows[0][0]) == {
        "automount_sa_token": False,
        "secret_volumes": 0,
        "token_ttl": None,
    }


def test_live_gateway_status_reports_the_acceptance_window() -> None:
    import httpx
    from platform_live import GATEWAY, tls

    response = httpx.get(
        f"{GATEWAY}/v1/status",
        verify=tls(),
        timeout=10,
        headers={"Authorization": f"Bearer {token('extorq-selftest')}"},
    )
    limits = response.json()["limits"]
    assert limits["event_retention_days"] == 90 and limits["max_future_seconds"] == 86400
