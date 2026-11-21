"""Minimal, read-only Kubernetes API client for the inventory collector (owner: B2).

* Loads the kubeconfig written by ``infra/kind/kind.sh token``: an HTTPS API server on
  the Mac loopback, the cluster CA inline, and a ``tokenFile`` holding a short-lived
  TokenRequest token of ``extorq-system/extorq-inventory``. Client certificates
  (the cluster-admin kubeconfig), inline tokens, exec plugins and
  ``insecure-skip-tls-verify`` are refused: this collector must never run with
  more than its read-only identity.
* GET only. TLS verification is pinned to the cluster CA (system trust store not
  loaded), hostname verification on, TLS >= 1.2. Every request has connect/read
  timeouts and bounded retries with jittered exponential backoff (5xx, 429,
  transport errors; ``Retry-After`` honoured up to a cap).
* Paginated LIST (``limit`` + ``continue``). An expired continue token (HTTP 410
  Gone) restarts the list from the beginning (bounded attempts); the number of
  restarts is reported so the collector can expose it in health.
* The bearer token is re-read from ``tokenFile`` for every list, so a re-minted
  token is picked up without a restart. It never appears in reprs, logs or errors.
"""

from __future__ import annotations

import base64
import binascii
import json
import random
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml

USER_AGENT = "extorq-k8s-inventory/1.0"
MAX_TOKEN_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_RETRY_AFTER_SECONDS = 30.0
ALLOWED_API_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class KubeConfigError(ValueError):
    """The kubeconfig is missing, malformed or would grant more than read-only access."""


class KubeApiError(RuntimeError):
    """An API request failed. Messages never contain the token or response bodies."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class KubeUnauthorized(KubeApiError):
    """401: token missing, expired or revoked (re-mint with ``kind.sh token``)."""


class KubeForbidden(KubeApiError):
    """403: the read-only identity is not allowed to read this resource."""


class KubeGone(KubeApiError):
    """410: continue token expired and the bounded relist attempts were exhausted."""


class KubeUnavailable(KubeApiError):
    """Transport errors / 5xx / 429 after all retries."""


@dataclass(frozen=True)
class KubeConnection:
    server: str
    ca_pem: str
    token_file: Path
    context: str

    def __repr__(self) -> str:
        return f"KubeConnection(server={self.server!r}, context={self.context!r})"

    @classmethod
    def from_kubeconfig(
        cls, path: Path, *, allowed_hosts: frozenset[str] = ALLOWED_API_HOSTS
    ) -> KubeConnection:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise KubeConfigError(
                f"kubeconfig not found: {path} (run: infra/kind/kind.sh token)"
            ) from None
        except (OSError, yaml.YAMLError) as exc:
            raise KubeConfigError(f"kubeconfig unreadable ({type(exc).__name__})") from None
        if not isinstance(document, dict):
            raise KubeConfigError("kubeconfig is not a mapping")
        context_name = document.get("current-context")
        contexts = {c.get("name"): c.get("context") or {} for c in _named(document, "contexts")}
        if context_name not in contexts:
            raise KubeConfigError("kubeconfig current-context is missing or unknown")
        ctx = contexts[context_name]
        clusters = {c.get("name"): c.get("cluster") or {} for c in _named(document, "clusters")}
        users = {u.get("name"): u.get("user") or {} for u in _named(document, "users")}
        cluster = clusters.get(ctx.get("cluster"))
        user = users.get(ctx.get("user"))
        if not isinstance(cluster, dict) or not isinstance(user, dict):
            raise KubeConfigError("kubeconfig context references an unknown cluster or user")
        server = cluster.get("server")
        if not isinstance(server, str):
            raise KubeConfigError("kubeconfig cluster has no server")
        parts = urlsplit(server)
        if parts.scheme != "https" or parts.hostname not in allowed_hosts:
            raise KubeConfigError(
                "API server must be https on the loopback interface (got a different URL)"
            )
        if cluster.get("insecure-skip-tls-verify"):
            raise KubeConfigError("insecure-skip-tls-verify is not allowed")
        ca_data = cluster.get("certificate-authority-data")
        if not isinstance(ca_data, str):
            raise KubeConfigError("kubeconfig cluster needs certificate-authority-data")
        try:
            ca_pem = base64.b64decode(ca_data, validate=True).decode("ascii")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            raise KubeConfigError("certificate-authority-data is not base64 PEM") from None
        if "-----BEGIN CERTIFICATE-----" not in ca_pem:
            raise KubeConfigError("certificate-authority-data is not a PEM certificate")
        forbidden = {
            "client-certificate",
            "client-certificate-data",
            "client-key",
            "client-key-data",
            "token",
            "exec",
            "auth-provider",
            "username",
            "password",
        }
        present = sorted(forbidden & set(user))
        if present:
            # Never accept the cluster-admin kubeconfig (client certificate) or inline secrets.
            raise KubeConfigError(
                "kubeconfig user must authenticate with tokenFile only "
                f"(refusing fields: {', '.join(present)})"
            )
        token_file = user.get("tokenFile")
        if not isinstance(token_file, str) or not token_file:
            raise KubeConfigError("kubeconfig user has no tokenFile")
        token_path = Path(token_file)
        if not token_path.is_absolute():
            token_path = (path.parent / token_path).resolve()
        return cls(
            server=server.rstrip("/"),
            ca_pem=ca_pem,
            token_file=token_path,
            context=str(context_name),
        )


def _named(document: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = document.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def read_token(path: Path) -> str:
    """Read the bearer token (never logged). Raises KubeConfigError when unusable."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise KubeConfigError(
            f"token file not found: {path} (run: infra/kind/kind.sh token)"
        ) from None
    except OSError as exc:
        raise KubeConfigError(f"token file unreadable ({type(exc).__name__})") from None
    if len(raw) > MAX_TOKEN_BYTES:
        raise KubeConfigError("token file is too large")
    try:
        token = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        raise KubeConfigError("token file is not ASCII") from None
    if not token or any(ch.isspace() for ch in token):
        raise KubeConfigError("token file is empty or malformed")
    return token


def token_expiry(path: Path) -> datetime | None:
    """``exp`` claim of the (JWT) service-account token, for health only. No verification."""
    try:
        token = read_token(path)
        payload = token.split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
        exp = claims.get("exp") if isinstance(claims, dict) else None
        if isinstance(exp, int) and not isinstance(exp, bool) and exp > 0:
            return datetime.fromtimestamp(exp, UTC)
    except (KubeConfigError, IndexError, ValueError, binascii.Error, OverflowError, OSError):
        return None
    return None


@dataclass
class ListResult:
    items: list[dict[str, Any]]
    resource_version: str | None
    pages: int = 0
    relists: int = 0


@dataclass
class ClientStats:
    requests: int = 0
    retries: int = 0
    relists: int = 0
    errors: dict[str, int] = field(default_factory=dict)


class KubeClient:
    """GET-only client bound to one :class:`KubeConnection`."""

    def __init__(
        self,
        connection: KubeConnection,
        *,
        timeout: float = 15.0,
        max_attempts: int = 3,
        max_relists: int = 3,
        page_size: int = 500,
        max_items: int = 20_000,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: Callable[[], float] = random.random,
    ) -> None:
        if not 1 <= max_attempts <= 6:
            raise ValueError("max_attempts must be within 1..6")
        self.connection = connection
        self.max_attempts = max_attempts
        self.max_relists = max_relists
        self.page_size = max(1, min(page_size, 500))
        self.max_items = max_items
        self._sleep = sleep
        self._rng = rng
        self.stats = ClientStats()
        verify: ssl.SSLContext | bool = True
        if transport is None:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=connection.ca_pem)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            verify = context
        self._client = httpx.Client(
            base_url=connection.server,
            verify=verify,
            timeout=httpx.Timeout(timeout, connect=min(5.0, timeout)),
            transport=transport,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            follow_redirects=False,
        )

    def __repr__(self) -> str:
        return f"KubeClient(server={self.connection.server!r})"

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> KubeClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ── requests ──────────────────────────────────────────────────────

    def get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        """GET ``path`` (relative to the API server) and return the decoded JSON object."""
        if not path.startswith("/") or ".." in path:
            raise ValueError("path must be an absolute API path")
        token = read_token(self.connection.token_file)
        last_error = "no attempt"
        for attempt in range(1, self.max_attempts + 1):
            self.stats.requests += 1
            retry_after: float | None = None
            try:
                response = self._client.get(
                    path, params=params, headers={"Authorization": f"Bearer {token}"}
                )
            except httpx.TimeoutException as exc:
                last_error = f"timeout ({type(exc).__name__})"
            except httpx.TransportError as exc:
                last_error = f"transport error ({type(exc).__name__})"
            else:
                status = response.status_code
                if status == 200:
                    if len(response.content) > MAX_RESPONSE_BYTES:
                        raise KubeApiError(f"response too large for {path}", status_code=status)
                    try:
                        data = response.json()
                    except ValueError:
                        raise KubeApiError(
                            f"invalid JSON from {path}", status_code=status
                        ) from None
                    if not isinstance(data, dict):
                        raise KubeApiError(f"unexpected JSON from {path}", status_code=status)
                    return data
                reason = _status_reason(response)
                if status == 401:
                    raise KubeUnauthorized(
                        f"401 Unauthorized for {path} (token expired or revoked: "
                        "run infra/kind/kind.sh token)",
                        status_code=status,
                    )
                if status == 403:
                    raise KubeForbidden(f"403 Forbidden for {path} ({reason})", status_code=status)
                if status == 410:
                    raise KubeGone(f"410 Gone for {path} ({reason})", status_code=status)
                if status != 429 and status < 500:
                    raise KubeApiError(f"HTTP {status} for {path} ({reason})", status_code=status)
                last_error = f"HTTP {status} ({reason})"
                retry_after = _retry_after(response.headers.get("retry-after"))
            self._count_error(last_error)
            if attempt < self.max_attempts:
                self.stats.retries += 1
                backoff = min(8.0, 0.5 * 2 ** (attempt - 1)) * (0.5 + self._rng())
                self._sleep(max(backoff, retry_after or 0.0))
        raise KubeUnavailable(f"{path}: {last_error} after {self.max_attempts} attempts")

    def list(self, path: str) -> ListResult:
        """Paginated LIST; restarts from scratch on 410 Gone (expired continue token)."""
        relists = 0
        while True:
            try:
                return self._list_once(path, relists)
            except KubeGone:
                relists += 1
                self.stats.relists += 1
                if relists > self.max_relists:
                    raise
                self._sleep(0.2 * relists)

    def _list_once(self, path: str, relists: int) -> ListResult:
        items: list[dict[str, Any]] = []
        token: str | None = None
        pages = 0
        resource_version: str | None = None
        while True:
            params = {"limit": str(self.page_size)}
            if token:
                params["continue"] = token
            page = self.get(path, params)
            pages += 1
            page_items = page.get("items")
            if not isinstance(page_items, list):
                raise KubeApiError(f"LIST {path} returned no items array")
            items.extend(item for item in page_items if isinstance(item, dict))
            if len(items) > self.max_items:
                raise KubeApiError(f"LIST {path} exceeded {self.max_items} items")
            raw_metadata = page.get("metadata")
            metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
            resource_version = metadata.get("resourceVersion") or resource_version
            token = metadata.get("continue") or None
            if not token:
                return ListResult(
                    items=items, resource_version=resource_version, pages=pages, relists=relists
                )
            if pages > 1000:
                raise KubeApiError(f"LIST {path} did not terminate")

    def _count_error(self, reason: str) -> None:
        key = reason.split(" (", 1)[0][:64]
        self.stats.errors[key] = self.stats.errors.get(key, 0) + 1


def _status_reason(response: httpx.Response) -> str:
    """The API Status ``reason`` (e.g. Forbidden, Expired); never the message body."""
    try:
        data = response.json()
    except ValueError:
        return response.reason_phrase[:64]
    if isinstance(data, dict) and isinstance(data.get("reason"), str):
        return data["reason"][:64]
    return response.reason_phrase[:64]


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    if seconds < 0:
        return None
    return min(seconds, MAX_RETRY_AFTER_SECONDS)
