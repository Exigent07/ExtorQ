"""HTTPS client for the ExtorQ ingest gateway.

* TLS trust is pinned to ``var/tls/ca.crt`` (the system trust store is NOT
  loaded), hostname verification on, TLS 1.2 minimum.
* Bodies are gzip-compressed JSON; every request has connect/read/write timeouts.
* Errors are typed so the sender can decide: :class:`RetryableError` (5xx, 429,
  503 with ``Retry-After``, timeouts, connection failures), :class:`AuthError`
  (401: keep buffering, operator must fix the token), :class:`RejectedError`
  (4xx: this batch will never be accepted as is).
"""

from __future__ import annotations

import gzip
import ssl
from pathlib import Path
from typing import Any

import httpx

from extorq.contracts.ingest import IngestBatch, IngestResult
from extorq_collectors import __version__

USER_AGENT = f"extorq-collector/{__version__}"
MAX_RETRY_AFTER_SECONDS = 300.0


class GatewayError(Exception):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class RetryableError(GatewayError):
    def __init__(
        self, message: str, *, status_code: int | None = None, retry_after: float | None = None
    ) -> None:
        super().__init__(message, status_code=status_code)
        self.retry_after = retry_after


class AuthError(GatewayError):
    """401: token missing/invalid. Records stay buffered."""


class RejectedError(GatewayError):
    """4xx other than 401/408/429: the batch as sent will not be accepted."""

    def __init__(self, message: str, *, status_code: int, detail: Any = None) -> None:
        super().__init__(message, status_code=status_code)
        self.detail = detail


def parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None  # HTTP-date form is not used by the ExtorQ gateway
    if seconds < 0:
        return None
    return min(seconds, MAX_RETRY_AFTER_SECONDS)


def pinned_ssl_context(ca_file: str | Path) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class GatewayClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        ca_file: str | Path,
        *,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not token:
            raise ValueError("gateway token is empty")
        self.base_url = base_url.rstrip("/")
        self._token = token
        verify: ssl.SSLContext | bool = pinned_ssl_context(ca_file) if transport is None else True
        self._client = httpx.Client(
            base_url=self.base_url,
            verify=verify,
            timeout=httpx.Timeout(timeout, connect=min(10.0, timeout)),
            transport=transport,
            headers={"User-Agent": USER_AGENT},
            follow_redirects=False,
        )

    def __repr__(self) -> str:  # never show the token
        return f"GatewayClient(base_url={self.base_url!r})"

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> GatewayClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def send(self, batch: IngestBatch) -> IngestResult:
        body = gzip.compress(batch.model_dump_json().encode("utf-8"), compresslevel=6)
        try:
            response = self._client.post(
                "/v1/ingest",
                content=body,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                    "Content-Encoding": "gzip",
                },
            )
        except httpx.TimeoutException as exc:
            raise RetryableError(f"gateway timeout ({type(exc).__name__})") from None
        except httpx.TransportError as exc:
            raise RetryableError(f"gateway unreachable ({type(exc).__name__})") from None
        status = response.status_code
        if status == 202:
            try:
                return IngestResult.model_validate(response.json())
            except ValueError as exc:
                raise RetryableError(
                    f"unparseable 202 response ({type(exc).__name__})", status_code=status
                ) from None
        detail = _detail(response)
        if status == 401:
            raise AuthError("gateway rejected the producer token (401)", status_code=status)
        if status in (408, 429) or status >= 500:
            raise RetryableError(
                f"gateway HTTP {status}: {detail}",
                status_code=status,
                retry_after=parse_retry_after(response.headers.get("retry-after")),
            )
        raise RejectedError(
            f"gateway HTTP {status}: {detail}", status_code=status, detail=_json_or_none(response)
        )

    def status(self) -> dict[str, Any]:
        response = self._client.get(
            "/v1/status", headers={"Authorization": f"Bearer {self._token}"}
        )
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else {}


def _json_or_none(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def _detail(response: httpx.Response) -> str:
    data = _json_or_none(response)
    if isinstance(data, dict) and "detail" in data:
        return str(data["detail"])[:300]
    return response.reason_phrase[:100]
