"""In-memory inventory store with input validation."""

from __future__ import annotations

import re
import threading
from dataclasses import asdict, dataclass

_SKU_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{2,31}$")
MAX_NAME = 120
MAX_QUANTITY = 1_000_000


class ValidationError(ValueError):
    """Client supplied an invalid item."""


@dataclass(frozen=True)
class Item:
    sku: str
    name: str
    quantity: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def validate_item(payload: object) -> Item:
    if not isinstance(payload, dict):
        raise ValidationError("body must be a JSON object")
    sku = payload.get("sku")
    name = payload.get("name")
    quantity = payload.get("quantity", 0)
    if not isinstance(sku, str) or not _SKU_RE.match(sku):
        raise ValidationError("sku must be 3-32 characters of A-Z, 0-9 or '-'")
    if not isinstance(name, str) or not name.strip() or len(name) > MAX_NAME:
        raise ValidationError(f"name must be 1-{MAX_NAME} characters")
    if (
        not isinstance(quantity, int)
        or isinstance(quantity, bool)
        or not 0 <= quantity <= MAX_QUANTITY
    ):
        raise ValidationError(f"quantity must be an integer between 0 and {MAX_QUANTITY}")
    return Item(sku=sku, name=name.strip(), quantity=quantity)


class InventoryStore:
    """Thread-safe in-memory store (the lab service keeps no persistent state)."""

    def __init__(self) -> None:
        self._items: dict[str, Item] = {}
        self._lock = threading.Lock()

    def list(self) -> list[Item]:
        with self._lock:
            return sorted(self._items.values(), key=lambda item: item.sku)

    def get(self, sku: str) -> Item | None:
        with self._lock:
            return self._items.get(sku)

    def upsert(self, item: Item) -> bool:
        """Insert or replace an item; returns True when the item is new."""
        with self._lock:
            created = item.sku not in self._items
            self._items[item.sku] = item
            return created

    def delete(self, sku: str) -> bool:
        with self._lock:
            return self._items.pop(sku, None) is not None
