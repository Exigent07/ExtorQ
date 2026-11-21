"""macOS service telemetry adapters (implemented on the shared services interface).

Two bindings exist, both backed by unified logging (``macos.unified_log``):

* ``macos-sshd``: Remote Login (OpenSSH, launchd job ``com.openssh.sshd``),
  records of processes ``sshd`` / ``sshd-session``.
* ``macos-screensharing``: Screen Sharing (launchd job ``com.apple.screensharing``),
  records of process ``screensharingd``.

They match ONLY on the macOS launchd label (``unit_patterns``); they declare no
product or executable matchers, so the shared registry can never hand them a
Linux candidate (and the macOS discovery never accepts another platform's
implemented adapter: see :func:`extorq_collectors.macos.services.match_macos_adapter`).

Both only see what unified logging exposes to a non-root reader; message
arguments that the producer marks private appear as ``<private>``.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from typing import Any, ClassVar

from extorq.contracts import SecurityEvent, SourceType
from extorq.contracts.service import AdapterSupport, ServiceCategory
from extorq_collectors.macos import unified_log
from extorq_collectors.macos.common import SourceContext
from extorq_collectors.services.base import AdapterContext, ServiceAdapter
from extorq_collectors.services.registry import register


class _UnifiedLogAdapter(ServiceAdapter):
    """Common parse path: unified-log record -> classified SecurityEvent carrying ServiceRef."""

    processes: ClassVar[frozenset[str]] = frozenset()

    def accepts(self, raw: Mapping[str, Any]) -> bool:
        path = raw.get("processImagePath")
        return isinstance(path, str) and os.path.basename(path) in self.processes

    def accepts_record(self, record: unified_log.LogRecord) -> bool:
        return record.process_name in self.processes

    def event_for(
        self,
        record: unified_log.LogRecord,
        ctx: AdapterContext,
        *,
        resolve_actor: Callable[[str], str | None] | None = None,
    ) -> SecurityEvent:
        """Event for an already parsed record (keeps the original raw line for provenance)."""
        event = unified_log.to_event(
            record,
            unified_log.classify(record),
            SourceContext(
                collector_id=ctx.collector_id,
                asset_id=ctx.asset_id,
                collector_version=ctx.collector_version,
            ),
            observed_time=ctx.observed_time,
            resolve_actor=resolve_actor,
        )
        if ctx.service is not None:
            event = SecurityEvent.model_validate(
                {**event.model_dump(mode="json"), "service": ctx.service.model_dump(mode="json")}
            )
        return event

    def parse(self, raw: Mapping[str, Any], ctx: AdapterContext) -> list[SecurityEvent]:
        """Generic interface entry point: one decoded ndjson record -> zero or one event.

        The provenance hash then covers the canonical JSON of ``raw`` (the original
        bytes are not available through this interface); the event id is the same
        either way because it derives from the record's native identity.
        """
        if not self.accepts(raw):
            return []
        raw_line = json.dumps(dict(raw), sort_keys=True, separators=(",", ":")).encode("utf-8")
        record = unified_log.parse_record(dict(raw), raw_line=raw_line)
        if record is None:
            return []
        return [self.event_for(record, ctx)]


@register
class MacOSSshdAdapter(_UnifiedLogAdapter):
    adapter_id = "macos-sshd"
    support = AdapterSupport.IMPLEMENTED
    category = ServiceCategory.SSH
    unit_patterns = ("com.openssh.sshd",)
    processes = frozenset({"sshd", "sshd-session"})
    source_types = (SourceType.MACOS_UNIFIED_LOG,)
    description = (
        "macOS Remote Login (OpenSSH sshd, launchd job com.openssh.sshd) via unified logging"
    )
    collects = (
        "authentication failures and successes (user, method, source address and port)",
        "invalid-user attempts",
        "other sshd/sshd-session messages as system.log.notable",
    )
    never_collects = (
        "passwords, private keys or key material",
        "session contents, commands or file transfers",
        "message arguments that unified logging marks private",
    )


@register
class MacOSScreenSharingAdapter(_UnifiedLogAdapter):
    adapter_id = "macos-screensharing"
    support = AdapterSupport.IMPLEMENTED
    category = ServiceCategory.OTHER
    unit_patterns = ("com.apple.screensharing",)
    processes = frozenset({"screensharingd"})
    source_types = (SourceType.MACOS_UNIFIED_LOG,)
    description = (
        "macOS Screen Sharing (VNC, launchd job com.apple.screensharing) via unified logging"
    )
    collects = ("VNC/Screen Sharing authentication results with viewer address",)
    never_collects = ("screen contents, keystrokes or clipboard", "passwords")


#: macOS adapters by id (the discovery uses these, never another platform's).
MACOS_ADAPTERS: dict[str, _UnifiedLogAdapter] = {
    adapter.adapter_id: adapter for adapter in (MacOSSshdAdapter(), MacOSScreenSharingAdapter())
}
#: unified-log producer (unified_log.PRODUCERS) that feeds each adapter.
ADAPTER_PRODUCER: dict[str, str] = {"macos-sshd": "sshd", "macos-screensharing": "screensharing"}
#: launchd label of the service each adapter binds to.
ADAPTER_LABEL: dict[str, str] = {
    "macos-sshd": "com.openssh.sshd",
    "macos-screensharing": "com.apple.screensharing",
}
