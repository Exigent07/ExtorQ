"""Apache HTTP Server adapter: access log (Common/Combined Log Format) and error log.

IMPLEMENTED and unit-tested against the formats documented by the Apache HTTP
Server project (https://httpd.apache.org/docs/2.4/logs.html), but NOT deployed in
the ExtorQ lab (the lab VM runs nginx). Expected routing when Apache is deployed:

* access: ``CustomLog "|/usr/bin/logger -t apache_access -p local6.info" combined``
  (the logger child runs inside ``apache2.service``, so journald's ``_SYSTEMD_UNIT``
  attests the origin);
* errors: ``ErrorLog syslog:local7`` (SYSLOG_IDENTIFIER ``apache2``/``httpd``) or a
  piped logger with tag ``apache_error``.

Query strings, the Referer header and request bodies are never stored.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any

from extorq.contracts import (
    Actor,
    ActorType,
    HttpInfo,
    Network,
    Outcome,
    SecurityEvent,
    ServiceCategory,
    Severity,
    SourceType,
)
from extorq_collectors.linux.adapters.base import LinuxJournalAdapter
from extorq_collectors.linux.common import ParseContext, build_event, clean, to_ms
from extorq_collectors.linux.http import strip_query
from extorq_collectors.linux.journal import (
    JournalEntry,
    Trust,
    forged_identity_event,
)
from extorq_collectors.services.registry import register

PARSER_APACHE_ACCESS = "linux-apache-access"
PARSER_APACHE_ERROR = "linux-apache-error"
APACHE_UNITS = ("apache2.service", "httpd.service")
ACCESS_TAGS = frozenset({"apache_access"})
ERROR_TAGS = frozenset({"apache_error", "apache2", "httpd"})

_Q = r'"(?P<{name}>(?:[^"\\]|\\.){{0,8192}})"'
ACCESS_LINE = re.compile(
    r"^(?P<host>\S{1,255}) (?P<ident>\S{1,128}) (?P<user>\S{1,128}) "
    r"\[(?P<time>[^\]]{1,40})\] " + _Q.format(name="request") + r" "
    r"(?P<status>\d{3}|-) (?P<bytes>\d{1,20}|-)"
    r"(?: " + _Q.format(name="referer") + r" " + _Q.format(name="agent") + r")?(?P<rest>.*)$"
)
ERROR_LINE = re.compile(
    r"^(?:\[(?P<time>[A-Z][a-z]{2} [A-Z][a-z]{2} [ 0-9]\d "
    r"\d{2}:\d{2}:\d{2}(?:\.\d{1,6})? \d{4})\] )?"
    r"\[(?:(?P<module>[a-z0-9_]{1,40}):)?(?P<level>[a-z0-9]{2,10})\] "
    r"\[pid (?P<pid>\d{1,10})(?::tid (?P<tid>\d{1,20}))?\]"
    r"(?: \[client (?P<client>[^\]]{1,80})\])? (?P<text>.*)$"
)
_REQUEST = re.compile(
    r"^(?P<method>[A-Z]{1,16}) (?P<target>\S{1,8192})(?: (?P<proto>HTTP/[0-9.]{1,3}))?$"
)
_AH_CODE = re.compile(r"^(?P<code>AH\d{5}): ")
_ERROR_CLASSES: tuple[tuple[str, str], ...] = (
    ("File does not exist", "file_not_found"),
    ("client denied by server configuration", "access_forbidden_by_rule"),
    ("Invalid URI in request", "invalid_request"),
    ("request failed: error reading the headers", "invalid_request"),
    ("Password Mismatch", "auth_basic_failure"),
    ("authentication failure for", "auth_basic_failure"),
    ("not found in", "auth_basic_failure"),
    ("attempt to connect to", "upstream_connect_failed"),
    ("error reading status line from remote server", "upstream_closed"),
    ("request body exceeds maximum size", "request_body_too_large"),
    ("Request body is larger than the configured limit", "request_body_too_large"),
    ("SSL Library Error", "tls_handshake_failed"),
    ("Permission denied", "permission_denied"),
)
_LEVEL_SEVERITY = {
    "emerg": Severity.CRITICAL,
    "alert": Severity.HIGH,
    "crit": Severity.HIGH,
    "error": Severity.MEDIUM,
    "warn": Severity.LOW,
    "notice": Severity.INFO,
    "info": Severity.INFO,
    "debug": Severity.INFO,
}


def _ip(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    if text.count(":") == 1 and "." in text:  # "1.2.3.4:5678"
        text = text.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(text.strip("[]")))
    except ValueError:
        return None


def _unescape(value: str) -> str:
    return value.replace('\\"', '"').replace("\\\\", "\\")


def _trust(entry: JournalEntry) -> Trust:
    if entry.unit is None:
        return Trust.UNVERIFIED
    return Trust.VERIFIED if entry.unit in APACHE_UNITS else Trust.MISMATCH


def parse_access_time(value: str) -> datetime | None:
    """``10/Oct/2000:13:55:36 -0700`` -> aware UTC datetime (None if malformed)."""
    try:
        return to_ms(datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z"))
    except ValueError:
        return None


def parse_apache_access(entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
    trust = _trust(entry)
    if trust is Trust.MISMATCH:
        return [forged_identity_event(entry, ctx, entry.identifier or "apache_access")]
    match = ACCESS_LINE.match(entry.message)
    if not match:
        return []
    request = _unescape(match.group("request"))
    method = route = None
    query_stripped = False
    req = _REQUEST.match(request)
    if req:
        method = req.group("method")
        route, query_stripped = strip_query(req.group("target"))
    status = int(match.group("status")) if match.group("status").isdigit() else None
    if status is not None and not 100 <= status <= 599:
        status = None
    size = match.group("bytes")
    user = match.group("user")
    agent = _unescape(match.group("agent")) if match.group("agent") else None
    src_ip = _ip(match.group("host"))
    attrs: dict[str, Any] = {
        "log_format": "combined" if match.group("agent") is not None else "common",
        "remote_host": None if src_ip else clean(match.group("host")),
        "malformed_request": True if req is None else None,
        "query_stripped": True if query_stripped else None,
        "boot_id": entry.boot_id,
    }
    if trust is not Trust.VERIFIED:
        attrs["source_verified"] = False
    if status is None:
        outcome = Outcome.UNKNOWN
    elif status in (401, 403):
        outcome = Outcome.DENIED
    else:
        outcome = Outcome.SUCCESS if status < 400 else Outcome.FAILURE
    # Evidence excerpt without the query string and without the Referer value.
    replacements = [(match.span("request"), f"{method} {route}" if req else "-")]
    if match.group("referer") is not None:
        replacements.append((match.span("referer"), "-"))
    safe_line = entry.message
    for (start, end), text in sorted(replacements, reverse=True):
        safe_line = safe_line[:start] + text + safe_line[end:]
    return [
        build_event(
            ctx,
            event_type="http.request",
            source_type=SourceType.LINUX_APACHE,
            native_key=entry.cursor,
            source_native_id=entry.cursor,
            event_time=parse_access_time(match.group("time")) or entry.time,
            parser=PARSER_APACHE_ACCESS,
            action="http.request",
            outcome=outcome,
            actor=Actor(type=ActorType.USER, name=clean(user), authenticated=True)
            if user not in ("-", "")
            else None,
            http=HttpInfo(
                method=method,
                route=clean(route, 2048) if route else None,
                status_code=status,
                user_agent=clean(agent, 2048) if agent and agent != "-" else None,
                bytes_sent=int(size) if size.isdigit() else (0 if size == "-" else None),
            ),
            network=Network(src_ip=src_ip, protocol="tcp", direction="inbound") if src_ip else None,
            message=f"{method or '?'} {route or '?'} -> {status if status is not None else '?'}",
            raw=safe_line,
            attributes=attrs,
            sim_texts=(agent, route),
        )
    ]


def classify_apache_error(text: str) -> str:
    for needle, error_class in _ERROR_CLASSES:
        if needle in text:
            return error_class
    return "other"


def parse_apache_error(entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
    trust = _trust(entry)
    if trust is Trust.MISMATCH:
        return [forged_identity_event(entry, ctx, entry.identifier or "apache_error")]
    match = ERROR_LINE.match(entry.message)
    if not match:
        return []
    text = match.group("text")
    code = _AH_CODE.match(text)
    level = match.group("level")
    route = method = None
    request_at = text.find(" request ")
    if request_at >= 0:
        req = _REQUEST.match(text[request_at + len(" request ") :].strip())
        if req:
            method = req.group("method")
            route = strip_query(req.group("target"))[0]
    safe_text = re.sub(r"(\S)\?\S*", r"\1", text)  # drop query strings from any URL/path
    src_ip = _ip(match.group("client"))
    attrs: dict[str, Any] = {
        "error_class": classify_apache_error(text),
        "log_level": level,
        "module": match.group("module"),
        "error_code": code.group("code") if code else None,
        "apache_pid": int(match.group("pid")),
        "source_stamp": match.group("time"),
        "boot_id": entry.boot_id,
    }
    if trust is not Trust.VERIFIED:
        attrs["source_verified"] = False
    return [
        build_event(
            ctx,
            event_type="http.server.error",
            source_type=SourceType.LINUX_APACHE,
            native_key=entry.cursor,
            source_native_id=entry.cursor,
            event_time=entry.time,
            parser=PARSER_APACHE_ERROR,
            action=f"http.error.{attrs['error_class']}",
            outcome=Outcome.FAILURE,
            severity_hint=_LEVEL_SEVERITY.get(level),
            http=HttpInfo(method=method, route=clean(route, 2048)) if (method or route) else None,
            network=Network(src_ip=src_ip, protocol="tcp", direction="inbound") if src_ip else None,
            message=f"apache {level}: {safe_text}",
            raw=re.sub(r"(\S)\?\S*", r"\1", entry.message),
            attributes=attrs,
            sim_texts=(route,),
        )
    ]


@register
class ApacheAdapter(LinuxJournalAdapter):
    adapter_id = "apache"
    category = ServiceCategory.HTTP_SERVER
    products = frozenset({"apache2", "httpd"})
    product_name = "apache-httpd"
    unit_patterns = APACHE_UNITS
    executables = frozenset({"apache2", "httpd"})
    well_known_ports = frozenset({("tcp", 80), ("tcp", 443)})
    source_types = (SourceType.LINUX_APACHE,)
    syslog_identifiers = ACCESS_TAGS | ERROR_TAGS
    packages = ("apache2", "apache2-bin")
    deployed_in_lab = False
    description = (
        "Apache HTTP Server: access log (Common/Combined Log Format) and error log via journald "
        "(implemented and tested on documented formats; not deployed in the lab)"
    )
    collects = (
        "HTTP requests: method, path without query, status, bytes, user agent, client, "
        "HTTP-authenticated user name",
        "error-log records: module, level, AH code, class, client, request path without query",
    )
    never_collects = (
        "query strings, request or response bodies",
        "Referer header",
        "Authorization header or passwords",
    )

    def parse_entry(self, entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
        if entry.identifier in ACCESS_TAGS:
            return parse_apache_access(entry, ctx)
        return parse_apache_error(entry, ctx)
