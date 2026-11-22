"""Agentless Linux collector (the Ubuntu VM ``linux:lab-vm-01``, or any host with the boundary).

Telemetry is read over SSH through the VM's read-only dispatch boundary
(``/usr/local/sbin/extorq-collect-dispatch``, source ``infra/vm/files/``):
journald, the audit log, an inventory document (systemd units, processes with
cgroups, listening sockets with cgroups, accounts, cron, sensitive file hashes,
sshd/nginx configuration references), dpkg packages and posture facts.

Entry points:

* :class:`extorq_collectors.linux.collector.LinuxSSHCollector` (``extorq-collect run``);
* :class:`extorq_collectors.linux.ssh.SSHDispatchClient` (reused by C3 for ``packages``);
* :mod:`extorq_collectors.linux.adapters` (implemented service adapters);
* :mod:`extorq_collectors.linux.discovery` (service discovery);
* ``python -m extorq_collectors.linux.verify`` (read-only ClickHouse verification).

Documentation: docs/telemetry/linux.md and collectors/AGENTS.md.
"""
