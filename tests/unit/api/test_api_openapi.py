"""The published OpenAPI document (docs/api/openapi.json) matches the code."""

from __future__ import annotations

import json
from pathlib import Path

from extorq.api.openapi_export import build_openapi

REPO_ROOT = Path(__file__).resolve().parents[3]
PUBLISHED = REPO_ROOT / "docs" / "api" / "openapi.json"

EXPECTED_OPERATIONS = {
    ("get", "/api/v1/overview"),
    ("get", "/api/v1/assets"),
    ("get", "/api/v1/assets/{asset_id}"),
    ("get", "/api/v1/findings"),
    ("get", "/api/v1/rules"),
    ("get", "/api/v1/rules/{rule_id}"),
    ("get", "/api/v1/alerts"),
    ("get", "/api/v1/alerts/{alert_id}"),
    ("get", "/api/v1/alerts/{alert_id}/context"),
    ("get", "/api/v1/alerts/{alert_id}/assessments"),
    ("post", "/api/v1/alerts/{alert_id}/summary"),
    ("post", "/api/v1/alerts/{alert_id}/state"),
    ("get", "/api/v1/events"),
    ("get", "/api/v1/events/{event_id}"),
    ("get", "/api/v1/health"),
    ("get", "/api/v1/timeseries/alerts"),
    ("get", "/api/v1/timeseries/events"),
    # Service-aware monitoring (PLAN section 10, schema 1.1)
    ("get", "/api/v1/assets/{asset_id}/services"),
    ("get", "/api/v1/services"),
    ("get", "/api/v1/services/{service_id}"),
}


def test_published_document_is_up_to_date() -> None:
    published = json.loads(PUBLISHED.read_text(encoding="utf-8"))
    assert published == build_openapi(), (
        "docs/api/openapi.json is stale: run "
        "`uv run python -m extorq.api.openapi_export docs/api/openapi.json`"
    )


def test_every_plan_endpoint_is_present_and_authenticated() -> None:
    spec = build_openapi()
    operations = {(method, path) for path, methods in spec["paths"].items() for method in methods}
    assert operations == EXPECTED_OPERATIONS
    for path, methods in spec["paths"].items():
        for method, operation in methods.items():
            assert operation["security"] == [{"ServiceToken": []}], (method, path)
            headers = {p["name"] for p in operation["parameters"] if p["in"] == "header"}
            assert {"X-ExtorQ-User", "X-ExtorQ-Role"} <= headers, (method, path)
            assert "401" in operation["responses"] and "403" in operation["responses"]
    assert spec["components"]["securitySchemes"]["ServiceToken"]["scheme"] == "bearer"
