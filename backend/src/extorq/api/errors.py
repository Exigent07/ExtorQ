"""API error types and JSON error handlers.

Every error body has the shape ``{"detail": ..., "request_id": "..."}``. Messages are
fixed strings chosen by the API: database errors, SQL, stack traces and secrets are
never echoed to clients (they are logged server-side with the request id).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from extorq.api.logs import get_logger

log = get_logger("extorq.api.errors")


class ApiError(Exception):
    """An error with a client-safe message and HTTP status."""

    status_code = 500

    def __init__(self, detail: str, *, headers: dict[str, str] | None = None) -> None:
        super().__init__(detail)
        self.detail = detail
        self.headers = headers


class BadRequest(ApiError):
    status_code = 400


class Unauthorized(ApiError):
    status_code = 401


class Forbidden(ApiError):
    status_code = 403


class NotFound(ApiError):
    status_code = 404


class Conflict(ApiError):
    status_code = 409


class TooManyRequests(ApiError):
    status_code = 429


class ServiceUnavailable(ApiError):
    """A dependency (storage, correlation, AI) is absent, disabled or unreachable."""

    status_code = 503


def request_id_of(request: Request) -> str | None:
    value = getattr(request.state, "request_id", None)
    return value if isinstance(value, str) else None


def _body(request: Request, detail: Any) -> dict[str, Any]:
    return {"detail": detail, "request_id": request_id_of(request)}


def _is_storage_error(exc: Exception) -> bool:
    module = type(exc).__module__ or ""
    return module.startswith("clickhouse_connect")


#: Seconds a client should wait after the read identity's ClickHouse quota is exhausted
#: (quota intervals are one minute, PLAN 4.4 / migration 0002).
QUOTA_RETRY_AFTER_SECONDS = 30


def _is_quota_exceeded(exc: Exception) -> bool:
    """ClickHouse error 201 (QUOTA_EXCEEDED): a load limit, not an outage."""
    text = str(exc)
    return "QUOTA_EXCEEDED" in text or "Code: 201." in text or "code: 201," in text


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code, content=_body(request, exc.detail), headers=exc.headers
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, str) else "request failed"
        return JSONResponse(
            status_code=exc.status_code,
            content=_body(request, detail),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Do not reflect submitted values back (``input``/``ctx``): only location + message.
        errors = [
            {
                "loc": [str(part) for part in err.get("loc", ())],
                "msg": str(err.get("msg", "invalid value"))[:300],
                "type": str(err.get("type", "value_error")),
            }
            for err in exc.errors()[:20]
        ]
        return JSONResponse(status_code=422, content=_body(request, errors))

    @app.exception_handler(ResponseValidationError)
    async def _response_validation_error(
        request: Request, exc: ResponseValidationError
    ) -> JSONResponse:
        log.error(
            "response_validation_failed",
            request_id=request_id_of(request),
            path=request.url.path,
            errors=len(exc.errors()),
        )
        return JSONResponse(
            status_code=500,
            content=_body(request, "stored data did not match the API response schema"),
        )


def classify_unhandled(exc: BaseException, *, request_id: str, path: str) -> tuple[int, str]:
    """Map an unexpected exception to a client-safe (status, detail) and log it.

    Called by :class:`extorq.api.middleware.SecurityMiddleware` so that even 500/503
    responses carry the request id and security headers. ClickHouse driver errors become
    503 (their messages may contain SQL and are only logged, truncated).
    """
    if isinstance(exc, Exception) and _is_storage_error(exc) and _is_quota_exceeded(exc):
        # 429 (not 503): clients must not retry immediately, which would only extend it.
        log.warning("storage_quota_exceeded", request_id=request_id, path=path)
        return 429, "storage query quota of the API is exhausted for this minute; retry shortly"
    if isinstance(exc, Exception) and _is_storage_error(exc):
        log.error(
            "storage_error",
            request_id=request_id,
            path=path,
            error_type=type(exc).__name__,
            error=str(exc)[:500],
        )
        return 503, "storage query failed or unavailable"
    log.error("unhandled_error", request_id=request_id, path=path, error_type=type(exc).__name__)
    return 500, "internal error"
