"""Flask application factory for the lab inventory service."""

from __future__ import annotations

import os

from flask import Flask, jsonify, request
from flask.typing import ResponseReturnValue

from app import __version__
from app.inventory import InventoryStore, ValidationError, validate_item
from app.upstream import UpstreamClient


def create_app(store: InventoryStore | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    inventory = store or InventoryStore()
    upstream = UpstreamClient(os.environ.get("INVENTORY_UPSTREAM_URL"))

    @app.get("/healthz")
    def healthz() -> ResponseReturnValue:
        return jsonify(status="ok", version=__version__)

    @app.get("/api/items")
    def list_items() -> ResponseReturnValue:
        return jsonify(items=[item.to_dict() for item in inventory.list()])

    @app.get("/api/items/<sku>")
    def get_item(sku: str) -> ResponseReturnValue:
        item = inventory.get(sku)
        if item is None:
            return jsonify(error="not found"), 404
        return jsonify(item.to_dict())

    @app.put("/api/items/<sku>")
    def put_item(sku: str) -> ResponseReturnValue:
        payload = request.get_json(silent=True)
        if isinstance(payload, dict):
            payload = {**payload, "sku": sku}
        try:
            item = validate_item(payload)
        except ValidationError as exc:
            return jsonify(error=str(exc)), 400
        created = inventory.upsert(item)
        return jsonify(item.to_dict()), 201 if created else 200

    @app.delete("/api/items/<sku>")
    def delete_item(sku: str) -> ResponseReturnValue:
        if not inventory.delete(sku):
            return jsonify(error="not found"), 404
        return "", 204

    @app.get("/api/upstream/status")
    def upstream_status() -> ResponseReturnValue:
        return jsonify(upstream.status())

    return app


app = create_app()
