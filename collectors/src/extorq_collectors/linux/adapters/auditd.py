"""auditd adapter: the Linux audit log (``/var/log/audit/audit.log``, ENRICHED format).

Audit records are read by offset through the dispatch boundary (``audit``
command), not from journald. Only events produced by the ExtorQ rules (keys
``extorq_*``) become file/process events; ``CONFIG_CHANGE`` / ``DAEMON_END`` become
``audit.config.changed``. The records are attributed to the ``auditd`` service.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from extorq.contracts import SecurityEvent, ServiceCategory, SourceType
from extorq_collectors.linux import auditd
from extorq_collectors.linux.adapters.base import LinuxJournalAdapter
from extorq_collectors.linux.common import ParseContext
from extorq_collectors.linux.journal import JournalEntry
from extorq_collectors.services.base import AdapterContext
from extorq_collectors.services.registry import register


@register
class AuditdAdapter(LinuxJournalAdapter):
    adapter_id = "auditd"
    category = ServiceCategory.SECURITY_AGENT
    products = frozenset({"auditd"})
    product_name = "auditd"
    unit_patterns = ("auditd.service",)
    executables = frozenset({"auditd"})
    source_types = (SourceType.LINUX_AUDITD,)
    syslog_identifiers = frozenset()
    packages = ("auditd",)
    description = "Linux audit log: ExtorQ watch/exec rules and audit configuration changes"
    collects = (
        "writes/attribute changes on watched paths (systemd units, sshd config, sudoers, "
        "passwd/shadow, cron.d) with syscall, auid, process",
        "execve with euid 0 on behalf of logged-in users (redacted command line)",
        "audit rule changes and audit daemon stop",
    )
    never_collects = (
        "file contents",
        "audit records outside the ExtorQ rule keys (kept on the host only)",
    )

    def accepts(self, raw: Mapping[str, Any]) -> bool:
        return isinstance(raw.get("audit_payload"), bytes | bytearray)

    def parse(self, raw: Mapping[str, Any], ctx: AdapterContext) -> list[SecurityEvent]:
        """``{"audit_payload": bytes, "base_offset": int}`` (complete lines) -> events."""
        if not self.accepts(raw):
            return []
        pctx = ParseContext(
            asset_id=ctx.asset_id,
            collector_id=ctx.collector_id,
            collector_version=ctx.collector_version,
            observed_time=ctx.observed_time,
            service=ctx.service,
        )
        payload = bytes(raw["audit_payload"])
        base = int(raw.get("base_offset") or 0)
        return auditd.parse_audit_chunk(payload, base, pctx).events

    def parse_entry(self, entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
        return []  # audit records never arrive through journald in this collector
