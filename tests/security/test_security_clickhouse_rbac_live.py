"""Live ClickHouse privilege probe per service identity (PLAN 4.4; owner: agent F).

Marked ``integration``: needs the running stack with the ``debug`` profile proxy
on ``127.0.0.1:18123`` (``docker compose --profile debug up -d``). Run with::

    uv run pytest tests/security/test_security_clickhouse_rbac_live.py -m integration -q

Safety: read-only. Only SELECTs, settings changes that must be refused, and
INSERTs with an EMPTY body (``FORMAT JSONEachRow`` and no rows), so nothing is
written even where an INSERT is permitted. Passwords are read from
``var/secrets/clickhouse/<user>_password`` into memory, sent only as headers to
the loopback proxy, and never printed: failures report user, operation and the
ClickHouse error code only.
"""

from __future__ import annotations

import os
import urllib.error
import urllib.request

import pytest
from security_helpers import REPO_ROOT

pytestmark = pytest.mark.integration

PROXY = os.environ.get("EXTORQ_CLICKHOUSE_DEBUG_URL", "http://127.0.0.1:18123/")
#: Credentials are only ever sent to a loopback HTTP endpoint (the debug proxy).
LOOPBACK_PREFIXES = ("http://127.0.0.1:", "http://[::1]:", "http://localhost:")
PASSWORD_DIR = REPO_ROOT / "var" / "secrets" / "clickhouse"

#: ClickHouse error codes: 194 authentication required/failed (default user), 497 access
#: denied, 164 readonly mode, 516 authentication failed.
DENIED_CODES = {"164", "194", "497", "516"}

# (user, operation, query, expected_allowed)
CHECKS: list[tuple[str | None, str, str, bool]] = [
    (None, "default user without password", "SELECT 1", False),
    ("extorq_ingest", "SELECT events", "SELECT count() FROM extorq.events", False),
    ("extorq_ingest", "INSERT alerts", "INSERT INTO extorq.alerts FORMAT JSONEachRow", False),
    ("extorq_ingest", "INSERT events", "INSERT INTO extorq.events FORMAT JSONEachRow", True),
    ("extorq_ingest", "INSERT services", "INSERT INTO extorq.services FORMAT JSONEachRow", True),
    ("extorq_rules_ro", "SELECT events", "SELECT count() FROM extorq.events", True),
    ("extorq_rules_ro", "SELECT services", "SELECT count() FROM extorq.services", True),
    ("extorq_rules_ro", "SELECT alerts", "SELECT count() FROM extorq.alerts", False),
    ("extorq_rules_ro", "SELECT system.users", "SELECT name FROM system.users", False),
    ("extorq_rules_ro", "INSERT events", "INSERT INTO extorq.events FORMAT JSONEachRow", False),
    ("extorq_rules_ro", "SET max_execution_time", "SET max_execution_time = 1000", False),
    (
        "extorq_rules_ro",
        "url() table function",
        "SELECT * FROM url('http://127.0.0.1:1/', 'CSV', 'x String')",
        False,
    ),
    ("extorq_detect", "SELECT alerts", "SELECT count() FROM extorq.alerts", True),
    ("extorq_detect", "INSERT alerts", "INSERT INTO extorq.alerts FORMAT JSONEachRow", True),
    (
        "extorq_detect",
        "INSERT ai_assessments",
        "INSERT INTO extorq.ai_assessments FORMAT JSONEachRow",
        False,
    ),
    (
        "extorq_detect",
        "INSERT analyst_state",
        "INSERT INTO extorq.analyst_state FORMAT JSONEachRow",
        False,
    ),
    ("extorq_ai", "SELECT events", "SELECT count() FROM extorq.events", False),
    ("extorq_ai", "INSERT alerts", "INSERT INTO extorq.alerts FORMAT JSONEachRow", False),
    (
        "extorq_ai",
        "INSERT ai_assessments",
        "INSERT INTO extorq.ai_assessments FORMAT JSONEachRow",
        True,
    ),
    ("extorq_api_ro", "SELECT events", "SELECT count() FROM extorq.events", True),
    ("extorq_api_ro", "SELECT v_services", "SELECT count() FROM extorq.v_services", True),
    (
        "extorq_api_ro",
        "INSERT analyst_state",
        "INSERT INTO extorq.analyst_state FORMAT JSONEachRow",
        False,
    ),
    ("extorq_api_ro", "DROP TABLE", "DROP TABLE extorq.events", False),
    ("extorq_api_writer", "INSERT alerts", "INSERT INTO extorq.alerts FORMAT JSONEachRow", False),
    (
        "extorq_api_writer",
        "INSERT analyst_state",
        "INSERT INTO extorq.analyst_state FORMAT JSONEachRow",
        True,
    ),
    ("extorq_api_writer", "SELECT events", "SELECT count() FROM extorq.events", False),
    ("extorq_grafana", "SELECT events.raw", "SELECT raw FROM extorq.events LIMIT 1", False),
    ("extorq_grafana", "SELECT events.payload", "SELECT payload FROM extorq.events LIMIT 1", False),
    (
        "extorq_grafana",
        "SELECT events.event_id",
        "SELECT event_id FROM extorq.events LIMIT 1",
        True,
    ),
    (
        "extorq_grafana",
        "SELECT events.service_id",
        "SELECT service_id FROM extorq.events LIMIT 1",
        True,
    ),
    (
        "extorq_grafana",
        "SELECT quarantine excerpt",
        "SELECT payload_excerpt FROM extorq.ingest_quarantine LIMIT 1",
        False,
    ),
    ("extorq_grafana", "INSERT alerts", "INSERT INTO extorq.alerts FORMAT JSONEachRow", False),
]


def _proxy_up() -> bool:
    try:
        with urllib.request.urlopen(PROXY + "ping", timeout=3) as resp:  # noqa: S310 - loopback http only
            return resp.read().strip() == b"Ok."
    except (urllib.error.URLError, OSError):
        return False


def _run(user: str | None, query: str) -> tuple[bool, str]:
    request = urllib.request.Request(  # noqa: S310 - PROXY is checked to be loopback http
        PROXY, data=query.encode("utf-8"), method="POST"
    )
    if user is None:
        request.add_header("X-ClickHouse-User", "default")
    else:
        secret = (PASSWORD_DIR / f"{user}_password").read_text(encoding="utf-8").strip()
        request.add_header("X-ClickHouse-User", user)
        request.add_header("X-ClickHouse-Key", secret)
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:  # noqa: S310 - loopback only
            resp.read(4096)
            return True, "ok"
    except urllib.error.HTTPError as exc:
        text = exc.read(512).decode("utf-8", "replace")
        code = text.split("Code: ", 1)[1].split(".", 1)[0] if "Code: " in text else str(exc.code)
        return False, code


@pytest.fixture(scope="module", autouse=True)
def _require_stack() -> None:
    if not PROXY.startswith(LOOPBACK_PREFIXES):
        pytest.skip("EXTORQ_CLICKHOUSE_DEBUG_URL must be a loopback http URL")
    if not _proxy_up():
        pytest.skip("ClickHouse debug proxy 127.0.0.1:18123 not reachable (needs STACK READY)")
    if not PASSWORD_DIR.is_dir():
        pytest.skip("var/secrets/clickhouse missing (run scripts/bootstrap.py)")


@pytest.mark.parametrize(
    ("user", "operation", "query", "expected_allowed"),
    CHECKS,
    ids=[f"{u or 'default'}:{op}" for u, op, _, _ in CHECKS],
)
def test_identity_privileges_match_plan(
    user: str | None, operation: str, query: str, expected_allowed: bool
) -> None:
    allowed, detail = _run(user, query)
    if expected_allowed:
        assert allowed, f"{user}: {operation} should be allowed, got ClickHouse code {detail}"
    else:
        assert not allowed, f"{user}: {operation} must be DENIED but was allowed"
        assert detail in DENIED_CODES, f"{user}: {operation} failed with unexpected code {detail}"
