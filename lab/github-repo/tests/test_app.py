"""Unit tests for the lab inventory service."""

from __future__ import annotations

import pytest
from flask.testing import FlaskClient

from app.inventory import InventoryStore, ValidationError, validate_item
from app.main import create_app


@pytest.fixture()
def client() -> FlaskClient:
    app = create_app(InventoryStore())
    app.config["TESTING"] = True
    return app.test_client()


def test_healthz(client: FlaskClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_item_lifecycle(client: FlaskClient) -> None:
    assert client.get("/api/items").get_json() == {"items": []}
    created = client.put("/api/items/WIDGET-1", json={"name": "Widget", "quantity": 3})
    assert created.status_code == 201
    updated = client.put("/api/items/WIDGET-1", json={"name": "Widget", "quantity": 5})
    assert updated.status_code == 200
    assert client.get("/api/items/WIDGET-1").get_json()["quantity"] == 5
    assert client.delete("/api/items/WIDGET-1").status_code == 204
    assert client.get("/api/items/WIDGET-1").status_code == 404


def test_rejects_invalid_items(client: FlaskClient) -> None:
    assert client.put("/api/items/bad sku", json={"name": "x"}).status_code == 400
    assert client.put("/api/items/GOOD-1", json={"name": "", "quantity": 1}).status_code == 400


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {"sku": "AB", "name": "x"},
        {"sku": "ABC", "name": "x", "quantity": -1},
        {"sku": "ABC", "name": "x", "quantity": True},
    ],
)
def test_validate_item_rejects(payload: object) -> None:
    with pytest.raises(ValidationError):
        validate_item(payload)


def test_upstream_disabled_by_default(client: FlaskClient) -> None:
    assert client.get("/api/upstream/status").get_json() == {"configured": False}
