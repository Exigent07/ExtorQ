"""SSH adapter (OpenSSH sshd): authentication and session activity from journald."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from extorq.contracts import SecurityEvent, ServiceCategory, SourceType
from extorq_collectors.linux import auth
from extorq_collectors.linux.adapters.base import LinuxJournalAdapter
from extorq_collectors.linux.common import ParseContext
from extorq_collectors.linux.journal import JournalEntry
from extorq_collectors.services.registry import register


@register
class SshAdapter(LinuxJournalAdapter):
    adapter_id = "ssh"
    category = ServiceCategory.SSH
    products = frozenset({"openssh"})
    product_name = "openssh"
    unit_patterns = ("ssh.service", "sshd.service", "ssh.socket", "sshd.socket", "ssh@*.service")
    executables = frozenset({"sshd"})
    well_known_ports = frozenset({("tcp", 22)})
    source_types = (SourceType.LINUX_JOURNALD,)
    syslog_identifiers = frozenset({"sshd", "sshd-session", "sshd-auth"})
    packages = ("openssh-server",)
    description = "OpenSSH server: authentication and session activity (journald, LogLevel VERBOSE)"
    collects = (
        "failed/accepted authentication (method, user, source ip/port, key fingerprint)",
        "invalid users, pre-auth disconnects, MaxAuthTries exhaustion",
        "PAM authentication failures and session open/close",
    )
    never_collects = (
        "passwords or keyboard-interactive responses (sshd never logs them)",
        "private keys",
        "session contents, commands typed or file transfers",
    )

    def parse_entry(self, entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
        return auth.parse_sshd(entry, ctx)

    def prerequisite_problems(self, configs: Mapping[str, Any]) -> list[str]:
        sshd = configs.get("sshd")
        if not isinstance(sshd, Mapping):
            return []
        level = str(sshd.get("loglevel") or "INFO").upper()
        if level in ("QUIET", "FATAL", "ERROR"):
            return [f"sshd LogLevel {level}: authentication records are not logged"]
        return []
