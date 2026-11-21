"""systemd adapter: service lifecycle (journald, PID 1) and persistence (unit inventory).

Lifecycle records come only from the system manager (``_PID == 1``, kernel
attested). Persistence-related changes (unit files created/modified/deleted,
units enabled, drop-ins) come from the inventory snapshot diff
(``linux.inventory``). Both are attributed to the ``systemd`` service (the
manager in ``init.scope``); the unit a record is about is in ``resource.name``
and, when that unit is a discovered service, ``attributes.subject_service_id``.
"""

from __future__ import annotations

from extorq.contracts import SecurityEvent, ServiceCategory, SourceType
from extorq_collectors.linux import systemd
from extorq_collectors.linux.adapters.base import LinuxJournalAdapter
from extorq_collectors.linux.common import ParseContext
from extorq_collectors.linux.journal import JournalEntry
from extorq_collectors.services.registry import register

MANAGER_UNIT = "init.scope"


@register
class SystemdAdapter(LinuxJournalAdapter):
    adapter_id = "systemd"
    category = ServiceCategory.SERVICE_MANAGER
    products = frozenset({"systemd"})
    product_name = "systemd"
    unit_patterns = (MANAGER_UNIT,)
    executables = frozenset({"systemd", "init"})
    source_types = (SourceType.LINUX_JOURNALD, SourceType.LINUX_INVENTORY)
    syslog_identifiers = frozenset({"systemd"})
    packages = ("systemd",)
    description = "systemd system manager: unit lifecycle (journald) and persistence (unit files)"
    collects = (
        "unit started/stopped/reloaded/finished/failed/restart scheduled, daemon reloads "
        "with the requesting process",
        "unit files created/modified/deleted (sha256, ExecStart), units enabled, drop-ins",
    )
    never_collects = (
        "Environment= / EnvironmentFile= values of units (may carry credentials)",
        "unit file contents beyond ExecStart, Description and a fixed directive allow-list",
    )

    def parse_entry(self, entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
        return systemd.parse_systemd(entry, ctx)
