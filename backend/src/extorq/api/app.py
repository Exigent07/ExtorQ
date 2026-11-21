"""FastAPI application factory for the ExtorQ analyst API (``extorq api``)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from fastapi import FastAPI
from fastapi.routing import APIRoute

from extorq.api import schemas as s
from extorq.api.auth import TokenVerifier
from extorq.api.errors import install_error_handlers
from extorq.api.integrations import Integrations, PlatformIntegrations
from extorq.api.logs import get_logger
from extorq.api.middleware import SecurityMiddleware
from extorq.api.repository import ClickHouseRepository, Repository
from extorq.api.routes import api_router
from extorq.api.service import SummaryGate, utc_now
from extorq.api.settings import ApiSettings
from extorq.version import __version__

log = get_logger("extorq.api")

API_PREFIX = "/api/v1"

DESCRIPTION = """
Read API over ExtorQ's ClickHouse store plus two audited analyst mutations.

**Authentication.** Every `/api/v1` call needs `Authorization: Bearer <api service token>`
(held only by the console's Next.js server), `X-ExtorQ-User` and `X-ExtorQ-Role`
(`analyst` | `viewer`). Viewers cannot mutate (403). Mutations write an
`analyst_actions` audit row before the change.

**Data honesty.** Values come from stored telemetry; unknown values are `null`; empty
sources yield empty lists plus explicit flags. All strings are untrusted: render as text.
"""


def _operation_id(route: APIRoute) -> str:
    return route.name


def create_app(
    *,
    settings: ApiSettings | None = None,
    repository: Repository | None = None,
    integrations: Integrations | None = None,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    """Build the API. Arguments exist for tests; production uses the defaults."""
    settings = settings or ApiSettings()
    app = FastAPI(
        title="ExtorQ Analyst API",
        version=__version__,
        description=DESCRIPTION,
        openapi_url=f"{API_PREFIX}/openapi.json" if settings.enable_docs else None,
        docs_url=f"{API_PREFIX}/docs" if settings.enable_docs else None,
        redoc_url=None,
        generate_unique_id_function=_operation_id,
    )
    app.state.settings = settings
    app.state.repository = repository if repository is not None else ClickHouseRepository()
    app.state.integrations = integrations if integrations is not None else PlatformIntegrations()
    app.state.clock = clock or utc_now
    app.state.token_verifier = TokenVerifier(settings)
    app.state.summary_gate = SummaryGate(settings.summary_requests_per_minute)

    install_error_handlers(app)
    app.include_router(api_router, prefix=API_PREFIX)

    @app.get("/healthz", response_model=s.ServiceHealth, include_in_schema=False)
    def healthz() -> s.ServiceHealth:
        """Liveness only (no auth, no detail)."""
        return s.ServiceHealth(status="ok")

    app.add_middleware(SecurityMiddleware, max_body_bytes=settings.max_body_bytes)
    log.info(
        "api_configured",
        docs_enabled=settings.enable_docs,
        token_configured=app.state.token_verifier.configured,
    )
    return app
