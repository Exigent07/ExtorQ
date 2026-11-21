"""Planned service adapters: extension points that recognise services but collect nothing.

Registering them means a discovered vsftpd/PostgreSQL/MySQL/DNS/Redis service is
shown honestly as "planned adapter: unmonitored" instead of disappearing. To
implement one, subclass it in a platform module with ``support = IMPLEMENTED``,
override ``accepts``/``parse``, register it, add catalog event types and parser
tests, and keep every ``never_collects`` promise.
"""

from __future__ import annotations

from extorq.contracts.service import AdapterSupport, ServiceCategory
from extorq_collectors.services.base import ServiceAdapter
from extorq_collectors.services.registry import register


@register
class FtpAdapter(ServiceAdapter):
    adapter_id = "ftp"
    support = AdapterSupport.PLANNED
    category = ServiceCategory.FTP
    products = frozenset({"vsftpd", "proftpd", "pure-ftpd"})
    unit_patterns = ("vsftpd.service", "proftpd.service", "pure-ftpd*.service")
    executables = frozenset({"vsftpd", "proftpd", "pure-ftpd"})
    well_known_ports = frozenset({("tcp", 21)})
    description = "FTP servers (vsftpd, ProFTPD, Pure-FTPd)"
    collects = ("planned: authentication success/failure, session open/close, client address",)
    never_collects = (
        "file contents or transfer payloads",
        "passwords or credentials",
        "directory listings",
    )


@register
class PostgresAdapter(ServiceAdapter):
    adapter_id = "postgresql"
    support = AdapterSupport.PLANNED
    category = ServiceCategory.DATABASE
    products = frozenset({"postgresql"})
    unit_patterns = ("postgresql*.service",)
    executables = frozenset({"postgres", "postmaster"})
    well_known_ports = frozenset({("tcp", 5432)})
    description = "PostgreSQL"
    collects = ("planned: connection authorisation failures, role/privilege changes (DDL audit)",)
    never_collects = ("query text or parameters", "result sets", "passwords or credentials")


@register
class MySqlAdapter(ServiceAdapter):
    adapter_id = "mysql"
    support = AdapterSupport.PLANNED
    category = ServiceCategory.DATABASE
    products = frozenset({"mysql", "mariadb"})
    unit_patterns = ("mysql.service", "mysqld.service", "mariadb.service")
    executables = frozenset({"mysqld", "mariadbd"})
    well_known_ports = frozenset({("tcp", 3306)})
    description = "MySQL / MariaDB"
    collects = ("planned: authentication failures, account/grant changes",)
    never_collects = ("query text or parameters", "result sets", "passwords or credentials")


@register
class DnsAdapter(ServiceAdapter):
    adapter_id = "dns"
    support = AdapterSupport.PLANNED
    category = ServiceCategory.DNS
    products = frozenset({"bind9", "unbound", "dnsmasq", "systemd-resolved"})
    unit_patterns = (
        "named.service",
        "bind9.service",
        "unbound.service",
        "dnsmasq.service",
        "systemd-resolved.service",
    )
    executables = frozenset({"named", "unbound", "dnsmasq", "systemd-resolved"})
    well_known_ports = frozenset({("udp", 53), ("tcp", 53)})
    description = "DNS servers and resolvers"
    collects = ("planned: zone transfer attempts, refused queries, configuration reloads",)
    never_collects = ("full client query logs by default (privacy)", "TSIG keys")


@register
class RedisAdapter(ServiceAdapter):
    adapter_id = "redis"
    support = AdapterSupport.PLANNED
    category = ServiceCategory.CACHE
    products = frozenset({"redis"})
    unit_patterns = ("redis*.service",)
    executables = frozenset({"redis-server"})
    well_known_ports = frozenset({("tcp", 6379)})
    description = "Redis"
    collects = ("planned: AUTH failures, CONFIG/ACL changes, protected-mode exposure",)
    never_collects = ("keys or values", "command arguments", "passwords or ACL secrets")
