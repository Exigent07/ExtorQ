"""Canary tests for implemented HTTP service adapters (threat model T21; owner: agent F).

Feeds the adapters SYNTHETIC journald entries (clearly fake cursors and hosts)
whose query strings and Referer values carry runtime-generated canary secrets,
through the generic ``ServiceAdapter.parse(raw, ctx)`` interface, and asserts:

* the line was genuinely parsed (at least one event), so the check is not vacuous;
* no canary value appears in any field of any emitted event (route, raw, message,
  attributes ...): query strings are stripped before storage.

Skipped when B1's adapter package is not present. Canary values are never printed.
"""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from typing import Any

import pytest

adapters = pytest.importorskip("extorq_collectors.linux.adapters")

from extorq_collectors.services import AdapterContext, get_adapter  # noqa: E402

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
REALTIME_US = str(int(NOW.timestamp() * 1_000_000))
#: Clearly synthetic journald sequence/boot id (32 hex, all zeros but the last digit).
_SYNTHETIC_ID = "0" * 31 + "f"


def _canary() -> str:
    return "Fq" + secrets.token_hex(12)


def _ctx() -> AdapterContext:
    return AdapterContext(
        asset_id="linux:lab-vm-01",
        asset_type="linux_host",
        collector_id="f-security-test",
        collector_version="0.0.0",
        service=None,
        observed_time=NOW,
    )


def _entry(identifier: str, unit: str, message: str, seq: int) -> dict[str, Any]:
    # Synthetic journald export fields (cursor format only needs to be well-formed).
    return {
        "__CURSOR": f"s={_SYNTHETIC_ID};i={seq:x};b={_SYNTHETIC_ID};m={seq:x};t=1;x=f",
        "__REALTIME_TIMESTAMP": REALTIME_US,
        "SYSLOG_IDENTIFIER": identifier,
        "_SYSTEMD_UNIT": unit,
        "_PID": "4242",
        "_UID": "33",
        "_TRANSPORT": "syslog",
        "PRIORITY": "6",
        "MESSAGE": message,
    }


def _leaks(events: list[Any], values: list[str]) -> list[str]:
    """Field paths (never values) of emitted events that contain a canary."""
    found: list[str] = []
    for index, event in enumerate(events):
        stack: list[tuple[str, Any]] = [(f"event[{index}]", event.model_dump(mode="json"))]
        while stack:
            path, value = stack.pop()
            if isinstance(value, str):
                if any(v in value for v in values):
                    found.append(path)
            elif isinstance(value, dict):
                stack.extend((f"{path}.{k}", v) for k, v in value.items())
            elif isinstance(value, list):
                stack.extend((f"{path}[{i}]", v) for i, v in enumerate(value))
    return found


def _cases() -> list[tuple[str, str, dict[str, Any], list[str]]]:
    a, b, c, d, e, f, g = (_canary() for _ in range(7))
    nginx_access = json.dumps(
        {
            "time_iso8601": "2026-11-21T12:00:00+00:00",
            "msec": NOW.timestamp(),
            "remote_addr": "10.0.2.2",
            "request_method": "GET",
            "uri": f"/login?password={a}&token={b}",
            "status": 401,
            "body_bytes_sent": 12,
            "request_time": 0.001,
            "http_user_agent": "curl/8.0 (synthetic f-security-test)",
            "request_id": "0123456789abcdef0123456789abcdef",
            "host": "lab-vm-01",
        }
    )
    nginx_error = (
        "2026/11/21 12:00:00 [error] 1234#1234: *7 access forbidden by rule, "
        f'client: 10.0.2.2, server: _, request: "GET /admin?session={c} HTTP/1.1", '
        f'host: "127.0.0.1:8088", referrer: "http://127.0.0.1:8088/?token={d}"'
    )
    apache_access = (
        "10.0.2.2 - - [21/Nov/2026:12:00:00 +0000] "
        f'"GET /search?api_key={e} HTTP/1.1" 200 512 '
        f'"http://lab.invalid/prev?session={f}" "curl/8.0 (synthetic f-security-test)"'
    )
    portal = json.dumps(
        {
            "ts": "2026-11-21T12:00:00.000Z",
            "level": "warning",
            "service": "lab-portal",
            "event": "authz.denied",
            "user": None,
            "src_ip": "10.0.2.2",
            "request_id": "0123456789abcdef0123456789abcdef",
            "request_id_source": "propagated",
            "method": "GET",
            "route": f"/admin?token={g}",
            "status": 401,
            "reason": "missing_session",
            "user_agent": "curl/8.0 (synthetic f-security-test)",
            "duration_ms": 1.0,
        }
    )
    return [
        (
            "nginx access",
            "nginx",
            _entry("nginx_access", "nginx.service", nginx_access, 1),
            [a, b],
        ),
        ("nginx error", "nginx", _entry("nginx_error", "nginx.service", nginx_error, 2), [c, d]),
        (
            "apache access",
            "apache",
            _entry("apache_access", "apache2.service", apache_access, 3),
            [e, f],
        ),
        (
            "lab portal",
            "webapp-json",
            _entry("lab-portal", "lab-portal.service", portal, 4),
            [g],
        ),
    ]


@pytest.mark.parametrize(
    ("label", "adapter_id", "raw", "canaries"),
    _cases(),
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_http_adapters_strip_query_secrets(
    label: str, adapter_id: str, raw: dict[str, Any], canaries: list[str]
) -> None:
    adapter = get_adapter(adapter_id)
    if adapter is None:
        pytest.skip(f"adapter {adapter_id!r} not registered")
    assert adapter.accepts(raw), f"{label}: adapter does not accept its own record shape"
    events = adapter.parse(raw, _ctx())
    assert events, f"{label}: synthetic line was not parsed (test would be vacuous)"
    leaked = _leaks(events, canaries)
    assert not leaked, f"{label}: query/referrer secret survived in {leaked}"
