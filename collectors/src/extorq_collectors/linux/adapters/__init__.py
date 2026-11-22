"""Implemented Linux service telemetry adapters (registered with the shared registry).

Importing this package registers: ``ssh``, ``nginx``, ``apache`` (tested on documented
formats; no Apache runs on the monitored VM), ``webapp-json``, ``systemd`` and ``auditd``. Planned
adapters (ftp, postgresql, mysql, dns, redis) are registered by
:mod:`extorq_collectors.services`.
"""

from extorq_collectors import services as _services  # noqa: F401  (planned adapters)
from extorq_collectors.linux.adapters.apache import ApacheAdapter
from extorq_collectors.linux.adapters.auditd import AuditdAdapter
from extorq_collectors.linux.adapters.base import LinuxJournalAdapter
from extorq_collectors.linux.adapters.nginx import NginxAdapter
from extorq_collectors.linux.adapters.ssh import SshAdapter
from extorq_collectors.linux.adapters.systemd import SystemdAdapter
from extorq_collectors.linux.adapters.webapp_json import WebAppBinding, WebAppJsonAdapter

LINUX_ADAPTERS: tuple[type[LinuxJournalAdapter], ...] = (
    SshAdapter,
    NginxAdapter,
    ApacheAdapter,
    WebAppJsonAdapter,
    SystemdAdapter,
    AuditdAdapter,
)

__all__ = [
    "LINUX_ADAPTERS",
    "ApacheAdapter",
    "AuditdAdapter",
    "LinuxJournalAdapter",
    "NginxAdapter",
    "SshAdapter",
    "SystemdAdapter",
    "WebAppBinding",
    "WebAppJsonAdapter",
]
