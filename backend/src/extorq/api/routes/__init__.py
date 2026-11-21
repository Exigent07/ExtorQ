"""API routers (mounted under ``/api/v1``)."""

from __future__ import annotations

from fastapi import APIRouter

from extorq.api import schemas as s
from extorq.api.routes import (
    alerts,
    assets,
    events,
    findings,
    health,
    overview,
    rules,
    services,
    timeseries,
)

_COMMON_ERRORS: dict[int | str, dict[str, object]] = {
    400: {"model": s.ErrorResponse, "description": "Invalid parameters"},
    401: {"model": s.ErrorResponse, "description": "Missing/invalid bearer token or user header"},
    403: {"model": s.ErrorResponse, "description": "Missing/unsupported role or insufficient role"},
    422: {"model": s.ErrorResponse, "description": "Request validation failed"},
    503: {"model": s.ErrorResponse, "description": "Dependency unavailable"},
}

api_router = APIRouter(responses=_COMMON_ERRORS)
# Order matters: ``/assets/{asset_id:path}/services`` must be tried before the asset
# detail route ``/assets/{asset_id:path}``, which would otherwise capture it.
api_router.include_router(services.asset_services_router)
for module in (overview, assets, findings, rules, alerts, events, health, timeseries, services):
    api_router.include_router(module.router)

__all__ = ["api_router"]
