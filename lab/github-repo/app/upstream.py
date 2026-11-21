"""Optional upstream inventory feed (disabled unless INVENTORY_UPSTREAM_URL is set)."""

from __future__ import annotations

from urllib.parse import urlsplit

import requests


class UpstreamClient:
    def __init__(self, base_url: str | None, timeout: float = 3.0) -> None:
        self._base_url = base_url.rstrip("/") if base_url else None
        self._timeout = timeout
        if self._base_url and urlsplit(self._base_url).scheme != "https":
            raise ValueError("INVENTORY_UPSTREAM_URL must use https")

    def status(self) -> dict[str, object]:
        if not self._base_url:
            return {"configured": False}
        try:
            response = requests.get(f"{self._base_url}/health", timeout=self._timeout)
        except requests.RequestException as exc:
            return {"configured": True, "reachable": False, "error": type(exc).__name__}
        return {"configured": True, "reachable": True, "status_code": response.status_code}
