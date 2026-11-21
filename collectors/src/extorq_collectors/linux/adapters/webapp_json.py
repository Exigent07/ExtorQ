"""Custom web application adapter for the structured ``lab-portal.log.v1`` JSON schema.

The lab portal (lab/apps/lab-portal) writes one JSON object per line to stdout;
systemd sends it to journald with ``SyslogIdentifier=lab-portal``. The schema is
the shared contract in docs/team/interface-changes/B1.md section 1. Other
applications emitting the same schema can be configured under
``settings.adapters.webapp-json.apps`` in config/collectors/linux.yaml
(``{name, unit, syslog_identifier}``); their origin is verified against the
configured systemd unit.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from extorq.contracts import SecurityEvent, ServiceCategory, SourceType
from extorq_collectors.linux import http
from extorq_collectors.linux.adapters.base import LinuxJournalAdapter
from extorq_collectors.linux.common import ParseContext
from extorq_collectors.linux.journal import JournalEntry
from extorq_collectors.services.base import ServiceCandidate
from extorq_collectors.services.registry import register

LOG_SCHEMA = "lab-portal.log.v1"
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._-]{0,127}")


@dataclass(frozen=True)
class WebAppBinding:
    """One application emitting the supported JSON schema."""

    name: str
    unit: str
    syslog_identifier: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> WebAppBinding:
        name = str(raw.get("name") or "")
        unit = str(raw.get("unit") or "")
        ident = str(raw.get("syslog_identifier") or name)
        for value, what in ((name, "name"), (unit, "unit"), (ident, "syslog_identifier")):
            if not _NAME_RE.fullmatch(value):
                raise ValueError(f"invalid webapp-json {what}: {value!r}")
        if not unit.endswith(".service"):
            raise ValueError("webapp-json unit must be a .service unit")
        return cls(name=name, unit=unit, syslog_identifier=ident)


DEFAULT_APPS = (WebAppBinding("lab-portal", "lab-portal.service", "lab-portal"),)


@register
class WebAppJsonAdapter(LinuxJournalAdapter):
    adapter_id = "webapp-json"
    category = ServiceCategory.WEB_APPLICATION
    products = frozenset({"lab-portal"})
    product_name = None  # product only from configuration (the app name)
    unit_patterns = tuple(app.unit for app in DEFAULT_APPS)
    source_types = (SourceType.LINUX_APP,)
    syslog_identifiers = frozenset(app.syslog_identifier for app in DEFAULT_APPS)
    description = (
        f"Custom web applications emitting structured security events ({LOG_SCHEMA}): "
        "authentication, authorization and optional access records"
    )
    collects = (
        "login failures/successes (user, reason, client, propagated request id)",
        "authorization denials (route, reason)",
        "HTTP access records when the application logs them (LOG_ACCESS=1)",
    )
    never_collects = (
        "passwords or session tokens (the schema has no field for them)",
        "request bodies or query strings",
    )

    def matches(self, candidate: ServiceCandidate) -> bool:
        if candidate.attributes.get("log_schema") == LOG_SCHEMA:
            return True
        return super().matches(candidate)

    def infer_product(self, candidate: ServiceCandidate) -> str | None:
        app = candidate.attributes.get("app_name")
        if isinstance(app, str) and app:
            return app
        return super().infer_product(candidate)

    def parse_entry(self, entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
        return self.parse_for(entry, ctx, DEFAULT_APPS[0])

    @staticmethod
    def parse_for(
        entry: JournalEntry, ctx: ParseContext, app: WebAppBinding
    ) -> list[SecurityEvent]:
        return http.parse_lab_portal(entry, ctx, expected_unit=app.unit, app_name=app.name)
