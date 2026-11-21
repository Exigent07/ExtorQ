"""Service authentication and analyst roles.

Trust model: the browser never talks to this API. The Next.js server holds the API
service token and forwards the signed-in user's identity in ``X-ExtorQ-User`` and role
in ``X-ExtorQ-Role``. The API therefore:

1. authenticates the *caller* with ``Authorization: Bearer <service token>`` compared in
   constant time (SHA-256 digests + :func:`hmac.compare_digest`); a missing server-side
   token fails closed with 503;
2. requires a well-formed user name (401 otherwise) and a known role (403 otherwise);
3. permits mutations only for ``analyst`` (viewers get 403).

The token value is never logged or echoed.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time
from dataclasses import dataclass
from typing import Annotated, Literal

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from extorq.api.errors import Forbidden, ServiceUnavailable, Unauthorized
from extorq.api.logs import get_logger
from extorq.api.settings import ApiSettings, read_service_token, resolve_token_source

log = get_logger("extorq.api.auth")

USER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$"
_USER_RE = re.compile(USER_PATTERN)
Role = Literal["analyst", "viewer"]
ROLES: tuple[Role, ...] = ("analyst", "viewer")


@dataclass(frozen=True)
class Principal:
    user: str
    role: Role

    @property
    def is_analyst(self) -> bool:
        return self.role == "analyst"

    @property
    def requested_by(self) -> str:
        """``AIAssessment.requested_by`` form for analyst-initiated requests."""
        return f"analyst:{self.user}"


class TokenVerifier:
    """Holds only the SHA-256 digest of the configured token.

    When the token is missing at startup, loading is retried at most every
    ``reload_interval`` seconds so the API recovers once bootstrap writes the file.
    """

    def __init__(self, settings: ApiSettings, *, reload_interval: float = 5.0) -> None:
        self._settings = settings
        self._reload_interval = reload_interval
        self._lock = threading.Lock()
        self._digest: bytes | None = None
        self._last_attempt = 0.0
        self._load()
        if self._digest is None:
            name, _ = resolve_token_source(settings)
            log.warning(
                "api_service_token_missing",
                setting=name,
                hint="authenticated endpoints return 503 until the token is configured",
            )

    def _load(self) -> None:
        token = read_service_token(self._settings)
        self._digest = hashlib.sha256(token.encode("utf-8")).digest() if token else None
        self._last_attempt = time.monotonic()

    @property
    def configured(self) -> bool:
        if self._digest is None and time.monotonic() - self._last_attempt >= self._reload_interval:
            with self._lock:
                if self._digest is None:
                    self._load()
        return self._digest is not None

    def verify(self, presented: str) -> bool:
        digest = self._digest
        if digest is None:
            return False
        candidate = hashlib.sha256(presented.encode("utf-8", "surrogateescape")).digest()
        return hmac.compare_digest(candidate, digest)


_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="ServiceToken",
    description="API service token. Held only by the Next.js server; never sent to browsers.",
)

UserHeader = Annotated[
    str | None,
    Header(
        alias="X-ExtorQ-User",
        description="Signed-in console user, set by the Next.js server.",
        max_length=128,
    ),
]
RoleHeader = Annotated[
    str | None,
    Header(
        alias="X-ExtorQ-Role",
        description="Role of the console user: `analyst` (may mutate) or `viewer` (read-only).",
        max_length=16,
    ),
]


def get_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    x_extorq_user: UserHeader = None,
    x_extorq_role: RoleHeader = None,
) -> Principal:
    verifier: TokenVerifier = request.app.state.token_verifier
    if not verifier.configured:
        raise ServiceUnavailable("API service token is not configured on the server")
    if credentials is None or not verifier.verify(credentials.credentials):
        raise Unauthorized(
            "missing or invalid bearer token", headers={"WWW-Authenticate": "Bearer"}
        )
    if x_extorq_user is None or not _USER_RE.fullmatch(x_extorq_user):
        raise Unauthorized("missing or invalid X-ExtorQ-User header")
    if x_extorq_role == "analyst":
        role: Role = "analyst"
    elif x_extorq_role == "viewer":
        role = "viewer"
    else:
        raise Forbidden("missing or unsupported X-ExtorQ-Role (expected analyst or viewer)")
    principal = Principal(user=x_extorq_user, role=role)
    request.state.principal = principal
    return principal


def require_analyst(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
    if not principal.is_analyst:
        raise Forbidden("this action requires the analyst role")
    return principal


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
AnalystPrincipal = Annotated[Principal, Depends(require_analyst)]
