"""HTTP helpers for the web-application tests (nginx/lab-portal on the VM, lab-portal in kind).

Requests go only to loopback URLs the suite controls (127.0.0.1:8088 for the VM, the
NodePort 127.0.0.1:8089 for the cluster). Redirects are never followed: a probe that is
answered with a redirect must be counted as what it is, not as the status of the page it
points to. Wrong passwords are random (144 bits from the OS CSPRNG), never the real
credential and never printed. Requests carry the default ``Python-urllib`` user agent: no
custom header identifies them as tests.
"""

from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Any

from detection_tests.model import ActionFailed

DEMO_USER = "lab-admin"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _require_loopback(url: str) -> None:
    host = urllib.parse.urlsplit(url).hostname
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(f"refusing a non-loopback test URL: {url!r}")


def request(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = 10.0,
) -> int:
    """Send one request and return the HTTP status (4xx/5xx included, 3xx not followed)."""
    _require_loopback(url)
    req = urllib.request.Request(  # noqa: S310 - loopback http URL checked above
        url, data=body, method=method, headers=dict(headers or {})
    )
    try:
        with _OPENER.open(req, timeout=timeout) as response:
            response.read(64 * 1024)
            return int(response.status)
    except urllib.error.HTTPError as exc:
        code = int(exc.code)
        exc.close()
        return code
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        reason = getattr(exc, "reason", exc)
        raise ActionFailed(f"{method} {url} failed: {type(reason).__name__}") from None


def random_password() -> str:
    """A throwaway wrong password: 24 URL-safe characters, never the real credential."""
    return secrets.token_urlsafe(18)


def login(base_url: str, username: str, password: str) -> int:
    """POST /login as JSON (the lab portal answers JSON and does not redirect)."""
    body = json.dumps({"username": username, "password": password}).encode("utf-8")
    return request(
        f"{base_url}/login",
        method="POST",
        body=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )


def failed_logins(base_url: str, count: int, username: str = DEMO_USER) -> list[int]:
    """``count`` logins with random wrong passwords; returns the HTTP statuses."""
    return [login(base_url, username, random_password()) for _ in range(count)]


def get_all(base_url: str, paths: Sequence[str]) -> list[tuple[str, int]]:
    """GET every path; returns ``(path, status)`` pairs."""
    return [(path, request(f"{base_url}{path}")) for path in paths]
