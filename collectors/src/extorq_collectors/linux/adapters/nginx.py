"""nginx adapter: JSON access log and error log, both routed to journald.

The lab configuration (infra/vm/files/nginx/extorq-lab.conf) sends access lines as
JSON with tag ``nginx_access`` and error-log records with tag ``nginx_error`` to
``/dev/log``. Paths are ``$uri`` (no query string); error-log request lines are
stripped of query strings before storage.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from extorq.contracts import SecurityEvent, ServiceCategory, SourceType
from extorq_collectors.linux import http
from extorq_collectors.linux.adapters.base import LinuxJournalAdapter
from extorq_collectors.linux.common import ParseContext
from extorq_collectors.linux.journal import JournalEntry
from extorq_collectors.services.registry import register

ACCESS_TAG = "nginx_access"
ERROR_TAG = "nginx_error"


def _log_directives(configs: Mapping[str, Any], name: str) -> list[str]:
    nginx = configs.get("nginx")
    if not isinstance(nginx, Mapping):
        return []
    values: list[str] = []
    for ctx in nginx.get("contexts") or []:
        if isinstance(ctx, Mapping) and isinstance(ctx.get("directives"), Mapping):
            values.extend(str(v) for v in ctx["directives"].get(name) or [])
    return values


@register
class NginxAdapter(LinuxJournalAdapter):
    adapter_id = "nginx"
    category = ServiceCategory.HTTP_SERVER
    products = frozenset({"nginx"})
    product_name = "nginx"
    unit_patterns = ("nginx.service",)
    executables = frozenset({"nginx"})
    well_known_ports = frozenset({("tcp", 80), ("tcp", 443)})
    source_types = (SourceType.LINUX_NGINX,)
    syslog_identifiers = frozenset({ACCESS_TAG, ERROR_TAG})
    packages = ("nginx", "nginx-core", "nginx-full", "nginx-light", "nginx-extras")
    description = "nginx: JSON access log and error log via journald"
    collects = (
        "HTTP requests: method, path without query, status, bytes, duration, user agent, "
        "client address, $request_id",
        "error-log records: class (body too large, upstream failures, access denied ...), "
        "client, request path without query",
    )
    never_collects = (
        "query strings, request or response bodies",
        "Authorization or Cookie headers",
        "Referer query strings",
    )

    def parse_entry(self, entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
        if entry.identifier == ERROR_TAG:
            return http.parse_nginx_error(entry, ctx)
        return http.parse_nginx_access(entry, ctx)

    def prerequisite_problems(self, configs: Mapping[str, Any]) -> list[str]:
        if not isinstance(configs.get("nginx"), Mapping):
            return []  # configuration not observed: unknown, not a problem claim
        problems: list[str] = []
        access = _log_directives(configs, "access_log")
        if not any("syslog:" in v and f"tag={ACCESS_TAG}" in v for v in access):
            problems.append(f"access_log is not sent to journald (syslog tag {ACCESS_TAG})")
        errors = _log_directives(configs, "error_log")
        if not any("syslog:" in v and f"tag={ERROR_TAG}" in v for v in errors):
            problems.append(f"error_log is not sent to journald (syslog tag {ERROR_TAG})")
        return problems
