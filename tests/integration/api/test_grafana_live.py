"""The running Grafana (compose service ``grafana``, 127.0.0.1:3001) against the live stack.

Runs with ``-m integration`` and skips when Grafana is not reachable. Read-only: every
query is a SELECT executed by Grafana's ClickHouse plugin as ``extorq_grafana``; the only
write attempts are privilege probes that cannot change data even if they were allowed
(``INSERT ... SELECT ... WHERE 0``).

The admin password is read from its file (``EXTORQ_GRAFANA_ADMIN_PASSWORD_FILE``, default
``var/secrets/grafana_admin_password``) and only used for HTTP basic auth; it is never
printed, logged or included in assertion messages.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[3]
DASHBOARD_DIR = REPO_ROOT / "infra" / "grafana" / "dashboards"
GRAFANA_URL = os.environ.get("EXTORQ_GRAFANA_URL", "http://127.0.0.1:3001")
PASSWORD_FILE = Path(
    os.environ.get(
        "EXTORQ_GRAFANA_ADMIN_PASSWORD_FILE",
        str(REPO_ROOT / "var" / "secrets" / "grafana_admin_password"),
    )
)
DATASOURCE_UID = "extorq-clickhouse"
EXPECTED_UIDS = {
    "extorq-security-overview",
    "extorq-collector-health",
    "extorq-linux",
    "extorq-kubernetes",
    "extorq-github",
}


@pytest.fixture(scope="module")
def grafana() -> httpx.Client:
    try:
        health = httpx.get(f"{GRAFANA_URL}/api/health", timeout=5)
    except httpx.HTTPError:
        pytest.skip(f"Grafana not reachable at {GRAFANA_URL}")
    if health.status_code != 200:
        pytest.skip(f"Grafana unhealthy: HTTP {health.status_code}")
    if not PASSWORD_FILE.is_file():
        pytest.skip("Grafana admin password file not present")
    password = PASSWORD_FILE.read_text(encoding="utf-8").strip()
    return httpx.Client(base_url=GRAFANA_URL, auth=("admin", password), timeout=60)


def _query(client: httpx.Client, target: dict[str, Any], time_from: str = "now-7d") -> Any:
    body = {
        "queries": [{**target, "intervalMs": 60_000, "maxDataPoints": 500}],
        "from": time_from,
        "to": "now",
    }
    return client.post("/api/ds/query", json=body)


def _targets() -> list[tuple[str, str, dict[str, Any]]]:
    out = []
    for path in sorted(DASHBOARD_DIR.glob("*.json")):
        dashboard = json.loads(path.read_text(encoding="utf-8"))
        for panel in dashboard["panels"]:
            for target in panel.get("targets", []):
                out.append((dashboard["uid"], panel["title"], target))
    return out


def test_unauthenticated_access_is_refused() -> None:
    try:
        response = httpx.get(f"{GRAFANA_URL}/api/search", timeout=5)
    except httpx.HTTPError:
        pytest.skip("Grafana not reachable")
    assert response.status_code == 401
    login_page = httpx.get(f"{GRAFANA_URL}/login", timeout=5)
    headers = {k.lower(): v for k, v in login_page.headers.items()}
    assert headers.get("x-frame-options", "").lower() == "deny"  # allow_embedding=false
    assert "content-security-policy" in headers
    assert headers.get("x-content-type-options") == "nosniff"


def test_datasource_plugin_and_provisioning(grafana: httpx.Client) -> None:
    datasource = grafana.get(f"/api/datasources/uid/{DATASOURCE_UID}").json()
    assert datasource["type"] == "grafana-clickhouse-datasource"
    assert datasource["readOnly"] is True  # provisioned, not editable
    assert datasource["jsonData"]["username"] == "extorq_grafana"
    assert datasource["jsonData"]["host"] == "clickhouse"
    assert datasource["jsonData"]["protocol"] == "http"
    assert datasource["secureJsonFields"].get("password") is True  # set, value never returned
    health = grafana.get(f"/api/datasources/uid/{DATASOURCE_UID}/health")
    assert health.status_code == 200, health.text[:300]
    assert health.json()["status"] == "OK"
    plugin = grafana.get("/api/plugins/grafana-clickhouse-datasource/settings").json()
    assert plugin["info"]["version"] == "4.23.5"
    assert plugin["signature"] == "valid"


def test_dashboards_are_provisioned_in_the_extorq_folder(grafana: httpx.Client) -> None:
    found = grafana.get("/api/search", params={"tag": "extorq", "type": "dash-db"}).json()
    assert {d["uid"] for d in found} == EXPECTED_UIDS
    assert {d.get("folderTitle") for d in found} == {"ExtorQ"}
    for uid in EXPECTED_UIDS:
        meta = grafana.get(f"/api/dashboards/uid/{uid}").json()["meta"]
        assert meta["provisioned"] is True
        assert meta["canSave"] is False or meta.get("provisionedExternalId")


@pytest.mark.parametrize(
    ("uid", "title", "target"), _targets(), ids=lambda v: v if isinstance(v, str) else None
)
def test_every_panel_query_executes_as_extorq_grafana(
    grafana: httpx.Client, uid: str, title: str, target: dict[str, Any]
) -> None:
    response = _query(grafana, target)
    assert response.status_code == 200, (uid, title, response.text[:500])
    result = response.json()["results"]["A"]
    assert "error" not in result, (uid, title, result.get("error", "")[:500])
    assert result.get("status", 200) == 200


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT raw FROM extorq.events LIMIT 1",
        "SELECT payload FROM extorq.events LIMIT 1",
        "SELECT * FROM extorq.events LIMIT 1",
        "SELECT payload_excerpt FROM extorq.ingest_quarantine LIMIT 1",
        "SELECT details FROM extorq.analyst_actions LIMIT 1",
        "SELECT body FROM extorq.investigation_contexts LIMIT 1",
        # Cannot change data even if it were allowed (zero rows).
        "INSERT INTO extorq.analyst_state SELECT alert_id, status, assignee, note, updated_by, "
        "updated_at FROM extorq.analyst_state WHERE 0",
    ],
)
def test_grafana_identity_is_least_privilege(grafana: httpx.Client, sql: str) -> None:
    target = {
        "refId": "A",
        "datasource": {"type": "grafana-clickhouse-datasource", "uid": DATASOURCE_UID},
        "editorType": "sql",
        "format": 1,
        "queryType": "table",
        "rawSql": sql,
    }
    response = _query(grafana, target)
    result = response.json()["results"]["A"]
    error = str(result.get("error", ""))
    assert error, f"query unexpectedly allowed: {sql}"
    assert any(
        marker in error
        for marker in ("ACCESS_DENIED", "Not enough privileges", "READONLY", "readonly")
    ), error[:300]


def test_hardening_settings_are_effective(grafana: httpx.Client) -> None:
    settings = grafana.get("/api/frontend/settings").json()
    assert settings["anonymousEnabled"] is False
    # (frontend "allowOrgCreate" is always true for a server admin; the setting is below)
    assert settings.get("publicDashboardsEnabled", False) is False
    assert settings.get("snapshotEnabled", settings.get("snapshotsEnabled", False)) is False
    assert settings.get("externalSnapshotPublish", settings.get("externalSnapshotURL")) in (
        False,
        None,
        "",
    )
    admin = grafana.get("/api/admin/settings").json()
    assert admin["security"]["cookie_samesite"] == "strict"
    assert admin["security"]["allow_embedding"] == "false"
    assert admin["security"]["disable_gravatar"] == "true"
    assert admin["users"]["allow_sign_up"] == "false"
    assert admin["users"]["allow_org_create"] == "false"
    assert admin["users"]["viewers_can_edit"] == "false"
    assert admin["log"]["mode"] == "console"
    assert admin["unified_alerting"]["enabled"] == "false"
    assert admin["news"]["news_feed_enabled"] == "false"
    assert admin["security"]["content_security_policy"] == "true"
    assert admin["auth.anonymous"]["enabled"] == "false"
    assert admin["analytics"]["reporting_enabled"] == "false"
    assert admin["analytics"]["check_for_updates"] == "false"
    assert admin["plugins"]["preinstall_disabled"] == "true"
    assert admin["plugins"]["plugin_admin_enabled"] == "false"
    assert admin["snapshots"]["external_enabled"] == "false"
    assert admin["public_dashboards"]["enabled"] == "false"
