"""Pure-ASGI middleware: request ids, security headers and request-body limits."""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from starlette.exceptions import HTTPException

from extorq.api.errors import classify_unhandled

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")

SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"cache-control", b"no-store"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"cross-origin-resource-policy", b"same-origin"),
)


class BodyTooLarge(HTTPException):
    """Raised while streaming a request body past the limit.

    An ``HTTPException`` so FastAPI's body reader re-raises it (it converts other
    exceptions into 400) and the regular handler renders a 413 with the request id.
    """

    def __init__(self) -> None:
        super().__init__(status_code=413, detail="request body too large")


class SecurityMiddleware:
    """Adds a request id + security headers and enforces a maximum request body size.

    The body limit is enforced both on ``Content-Length`` (fast reject) and while
    streaming (chunked bodies cannot bypass it).
    """

    def __init__(self, app: ASGIApp, *, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = None
        content_length: int | None = None
        for name, value in scope.get("headers", []):
            if name == b"x-request-id":
                candidate = value.decode("latin-1")
                if _REQUEST_ID_RE.fullmatch(candidate):
                    request_id = candidate
            elif name == b"content-length":
                try:
                    content_length = int(value)
                except ValueError:
                    content_length = -1
        if request_id is None:
            request_id = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id

        response_started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                for name, value in SECURITY_HEADERS:
                    if name not in present:
                        headers.append((name, value))
                headers.append((b"x-request-id", request_id.encode("latin-1")))
                message["headers"] = headers
            await send(message)

        if content_length is not None and (
            content_length < 0 or content_length > self.max_body_bytes
        ):
            await self._reject(send_wrapper, request_id, 413, "request body too large")
            return

        received = 0

        async def receive_wrapper() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise BodyTooLarge
            return message

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except BodyTooLarge:
            if not response_started:
                await self._reject(send_wrapper, request_id, 413, "request body too large")
        except Exception as exc:
            if response_started:
                raise
            status, detail = classify_unhandled(
                exc, request_id=request_id, path=str(scope.get("path", ""))
            )
            await self._reject(send_wrapper, request_id, status, detail)

    @staticmethod
    async def _reject(send: Send, request_id: str, status: int, detail: str) -> None:
        body = json.dumps({"detail": detail, "request_id": request_id}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
