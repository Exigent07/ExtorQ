"""Service discovery for the macOS host (contract schema 1.1, shared services interface).

Evidence (all collected without privileges):

* **launchd job definitions**: third-party plists in ``~/Library/LaunchAgents``,
  ``/Library/LaunchAgents`` and ``/Library/LaunchDaemons`` (launchd source), plus
  the definitions of a fixed list of Apple *sharing* services on the sealed system
  volume (:data:`APPLE_SERVICES`: Remote Login, Screen Sharing, File Sharing, ...),
  parsed read-only from ``/System/Library``.
* **loaded jobs**: ``launchctl print system`` / ``gui/<uid>`` (label, pid, overrides).
  Apple's own ~900 jobs are NOT turned into services (noise); only the Apple
  sharing services above and Apple jobs that own a listening socket are.
* **processes**: ``ps`` snapshot (pid, ppid, user, start time, executable path).
* **listening sockets**: ``netstat`` (all sockets, "last pid" attribution) or the
  ``lsof`` fallback (current user's processes only, socket owner pid).

Rules (PLAN 10.1):

* a service exists only with evidence (``discovered_via`` never empty);
* a process is not assumed to be a network service: only processes that own an
  observed listening socket, or whose executable is a known server binary
  (:data:`KNOWN_SERVER_EXECUTABLES`), become services, and the latter carry no
  endpoints unless a socket was observed;
* port attribution: ``confirmed`` only when lsof/netstat reported the owning pid
  and that pid is the service's process (or a descendant of its launchd job);
  ``inferred`` for sockets launchd holds on behalf of a socket-activated job
  (owner is launchd, pid 1, not the service); a listener whose owner cannot be
  determined is left unattributed (reported in health, never guessed);
* coverage is explicit: implemented macOS adapters (``macos-sshd``,
  ``macos-screensharing``), planned extension points (redis, mysql, postgresql,
  ftp, dns: shared registry) or none. An implemented adapter of another
  platform (e.g. the Linux nginx adapter) is never claimed for macOS.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from extorq.contracts import Outcome, Resource, SecurityEvent, SourceType
from extorq.contracts.identity import instance_id as make_instance_id
from extorq.contracts.identity import service_id as make_service_id
from extorq.contracts.service import (
    AdapterSupport,
    DiscoveryEvidence,
    InstanceKind,
    MonitoringStatus,
    PortAttribution,
    Service,
    ServiceCategory,
    ServiceEndpoint,
    ServiceInstance,
    ServiceKind,
    ServiceRef,
)
from extorq_collectors.macos.adapters import ADAPTER_LABEL, ADAPTER_PRODUCER, MACOS_ADAPTERS
from extorq_collectors.macos.common import SourceContext, bounded_attributes, make_event, to_ms
from extorq_collectors.macos.inventory import Listener, ProcessRow
from extorq_collectors.macos.launchctl import DomainListing, LoadedJob, domain_name
from extorq_collectors.macos.launchd import LaunchItem, SocketSpec
from extorq_collectors.services import (
    ServiceAdapter,
    ServiceCandidate,
    all_adapters,
    build_service,
    classify_coverage,
    exposure_of,
    match_adapter,
)

PARSER = "macos-services"
SOURCE = SourceType.MACOS_INVENTORY
MAX_SERVICES = 400
MAX_INSTANCES_PER_SERVICE = 32
MAX_ENDPOINTS_PER_SERVICE = 64
MAX_TREE_DEPTH = 64


@dataclass(frozen=True, slots=True)
class AppleService:
    """An Apple sharing / remote-access service ExtorQ always reports (on or off)."""

    label: str
    name: str
    category: ServiceCategory
    definition: str
    executables: frozenset[str]
    #: "loaded": socket-activated daemon, loaded == launchd listens == enabled.
    #: "running": the job is always loaded; it is active only while its process runs.
    enabled_when: str
    domain: str  # system | gui


APPLE_SERVICES: tuple[AppleService, ...] = (
    AppleService(
        "com.openssh.sshd",
        "Remote Login (OpenSSH sshd)",
        ServiceCategory.SSH,
        "/System/Library/LaunchDaemons/ssh.plist",
        frozenset(
            {"/usr/sbin/sshd", "/usr/libexec/sshd-session", "/usr/libexec/sshd-keygen-wrapper"}
        ),
        "loaded",
        "system",
    ),
    AppleService(
        "com.apple.screensharing",
        "Screen Sharing (VNC)",
        ServiceCategory.OTHER,
        "/System/Library/LaunchDaemons/com.apple.screensharing.plist",
        frozenset(
            {
                "/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/"
                "MacOS/screensharingd"
            }
        ),
        "loaded",
        "system",
    ),
    AppleService(
        "com.apple.smbd",
        "File Sharing (SMB)",
        ServiceCategory.OTHER,
        "/System/Library/LaunchDaemons/com.apple.smbd.plist",
        frozenset({"/usr/sbin/smbd"}),
        "loaded",
        "system",
    ),
    AppleService(
        "com.apple.RemoteDesktop.agent",
        "Remote Management (Apple Remote Desktop agent)",
        ServiceCategory.OTHER,
        "/System/Library/LaunchAgents/com.apple.RemoteDesktop.plist",
        frozenset(
            {"/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent"}
        ),
        "running",
        "gui",
    ),
    AppleService(
        "com.apple.ftp-proxy",
        "FTP proxy (ftp-proxy)",
        ServiceCategory.FTP,
        "/System/Library/LaunchDaemons/com.apple.ftp-proxy.plist",
        frozenset({"/usr/libexec/ftp-proxy"}),
        "loaded",
        "system",
    ),
    AppleService(
        "com.apple.tftpd",
        "TFTP server",
        ServiceCategory.OTHER,
        "/System/Library/LaunchDaemons/tftp.plist",
        frozenset({"/usr/libexec/tftpd"}),
        "loaded",
        "system",
    ),
    AppleService(
        "org.apache.httpd",
        "Apache HTTP Server (macOS built-in)",
        ServiceCategory.HTTP_SERVER,
        "/System/Library/LaunchDaemons/org.apache.httpd.plist",
        frozenset({"/usr/sbin/httpd"}),
        "loaded",
        "system",
    ),
    AppleService(
        "com.apple.nfsd",
        "NFS server",
        ServiceCategory.OTHER,
        "/System/Library/LaunchDaemons/com.apple.nfsd.plist",
        frozenset({"/sbin/nfsd"}),
        "running",
        "system",
    ),
    AppleService(
        "org.cups.cupsd",
        "Printing (CUPS)",
        ServiceCategory.OTHER,
        "/System/Library/LaunchDaemons/org.cups.cupsd.plist",
        frozenset({"/usr/sbin/cupsd"}),
        "running",
        "system",
    ),
)
APPLE_BY_LABEL: dict[str, AppleService] = {s.label: s for s in APPLE_SERVICES}

#: Server binaries that make a process a service candidate even without a launchd
#: job or an observed socket (process evidence only; never assumed to listen).
KNOWN_SERVER_EXECUTABLES: frozenset[str] = frozenset(
    {
        "sshd",
        "nginx",
        "httpd",
        "apache2",
        "vsftpd",
        "proftpd",
        "pure-ftpd",
        "postgres",
        "postmaster",
        "mysqld",
        "mariadbd",
        "mongod",
        "redis-server",
        "named",
        "unbound",
        "dnsmasq",
        "memcached",
        "php-fpm",
    }
)

_HOMEBREW = re.compile(
    r"^/(?:opt/homebrew|usr/local)/(?P<kind>opt|Cellar)/(?P<formula>[A-Za-z0-9._+-]+(?:@[0-9.]+)?)/"
    r"(?:(?P<version>[0-9][A-Za-z0-9._+-]*)/)?"
)
_CONFIG_SUFFIXES = (".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".json", ".plist")
_RANK = {PortAttribution.CONFIRMED: 2, PortAttribution.INFERRED: 1, PortAttribution.UNKNOWN: 0}


def homebrew_product(executable: str | None) -> tuple[str | None, str | None]:
    """(formula, version) when the executable lives in a Homebrew prefix.

    The formula name is evidence of the installed package (e.g. ``redis`` for
    ``/opt/homebrew/opt/redis/bin/redis-server``); the version is taken only from
    a ``Cellar/<formula>/<version>/`` path, never guessed.
    """
    if not executable:
        return None, None
    match = _HOMEBREW.match(executable)
    if not match:
        return None, None
    formula = match.group("formula").split("@", 1)[0].lower()
    version = match.group("version") if match.group("kind") == "Cellar" else None
    return formula, version


def is_apple_label(label: str) -> bool:
    return label.startswith("com.apple.")


def is_app_instance_label(label: str) -> bool:
    """LaunchServices GUI application instances (``application.<bundle>.<n>.<n>``)."""
    return label.startswith("application.")


def app_display_name(executable: str) -> str:
    """``/Applications/Docker.app/Contents/MacOS/com.docker.backend`` -> ``com.docker.backend``."""
    return os.path.basename(executable) or executable


def app_bundle(executable: str) -> str | None:
    marker = ".app/"
    index = executable.find(marker)
    if index < 0:
        return None
    return os.path.basename(executable[: index + len(marker) - 1])


# ── endpoints ────────────────────────────────────────────────────────


def _port_of(service: str | None, protocol: str) -> int | None:
    if not service:
        return None
    if service.isdigit():
        port = int(service)
        return port if 0 < port <= 65535 else None
    try:
        return socket.getservbyname(service, protocol)
    except OSError:
        return None


def endpoints_from_socket_specs(
    specs: Sequence[SocketSpec], *, observed_launchd_ports: set[tuple[str, int]] | None = None
) -> list[ServiceEndpoint]:
    """Endpoints launchd holds for a loaded socket-activated job (attribution INFERRED)."""
    out: list[ServiceEndpoint] = []
    for spec in specs:
        if spec.path or spec.sock_type not in ("stream", "dgram"):
            continue  # Unix domain socket or unsupported type: not a network endpoint
        protocol = "udp" if spec.sock_type == "dgram" else "tcp"
        port = _port_of(spec.service, protocol)
        if port is None:
            continue
        seen = (protocol, port) in (observed_launchd_ports or set())
        basis = (
            f"launchd Sockets entry '{spec.name}' (SockServiceName={spec.service}"
            + (f", SockNodeName={spec.node}" if spec.node else "")
            + "): socket held by launchd for on-demand activation"
            + ("; observed owned by launchd (pid 1)" if seen else "")
        )
        families = (
            ("ipv4",)
            if spec.family == "IPv4"
            else ("ipv6",)
            if spec.family == "IPv6"
            else ("ipv4", "ipv6")
        )
        if spec.node is None:
            out.append(
                ServiceEndpoint(
                    protocol=protocol,
                    address=None,
                    port=port,
                    exposure="any",
                    attribution=PortAttribution.INFERRED,
                    attribution_basis=basis[:256],
                )
            )
            continue
        if spec.node == "localhost":
            addresses = [a for f, a in (("ipv4", "127.0.0.1"), ("ipv6", "::1")) if f in families]
        else:
            try:
                addresses = [str(ipaddress.ip_address(spec.node))]
            except ValueError:
                addresses = []
        if not addresses:
            out.append(
                ServiceEndpoint(
                    protocol=protocol,
                    address=None,
                    port=port,
                    exposure="unknown",
                    attribution=PortAttribution.INFERRED,
                    attribution_basis=basis[:256],
                )
            )
        for address in addresses:
            out.append(
                ServiceEndpoint(
                    protocol=protocol,
                    address=address,
                    port=port,
                    exposure=exposure_of(address),
                    attribution=PortAttribution.INFERRED,
                    attribution_basis=basis[:256],
                )
            )
    return out


def endpoint_from_listener(listener: Listener, basis: str) -> ServiceEndpoint:
    address = listener.address if listener.address_valid else None
    return ServiceEndpoint(
        protocol="udp" if listener.protocol == "udp" else "tcp",
        address=address,
        port=listener.port,
        exposure=exposure_of(address) if address else "unknown",
        attribution=PortAttribution.CONFIRMED,
        attribution_basis=basis[:256],
    )


def endpoint_key(endpoint: ServiceEndpoint) -> str:
    addr = endpoint.address or "*"
    if ":" in addr:
        addr = f"[{addr}]"
    return f"{endpoint.protocol}:{addr}:{endpoint.port}"


def endpoint_label(endpoint: ServiceEndpoint) -> str:
    return f"{endpoint_key(endpoint)} {endpoint.exposure} {endpoint.attribution.value}"


# ── discovery ────────────────────────────────────────────────────────


@dataclass(slots=True)
class _Builder:
    kind: ServiceKind
    key: str
    name: str
    evidence: set[DiscoveryEvidence] = field(default_factory=set)
    unit: str | None = None
    executable: str | None = None
    product: str | None = None
    version: str | None = None
    category: ServiceCategory | None = None
    endpoints: dict[str, ServiceEndpoint] = field(default_factory=dict)
    config_refs: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    instance_pids: list[int] = field(default_factory=list)
    job: LoadedJob | None = None
    apple: AppleService | None = None
    #: not_loaded | loaded_idle | running | process
    state: str = "process"

    def add_endpoint(self, endpoint: ServiceEndpoint) -> None:
        key = endpoint_key(endpoint)
        existing = self.endpoints.get(key)
        if existing is None or _RANK[endpoint.attribution] > _RANK[existing.attribution]:
            if existing is None and len(self.endpoints) >= MAX_ENDPOINTS_PER_SERVICE:
                return
            self.endpoints[key] = endpoint

    def add_config_ref(self, ref: str | None) -> None:
        if ref and ref not in self.config_refs and len(self.config_refs) < 16:
            self.config_refs.append(ref[:2048])

    def add_pid(self, pid: int) -> None:
        if pid not in self.instance_pids and len(self.instance_pids) < MAX_INSTANCES_PER_SERVICE:
            self.instance_pids.append(pid)


@dataclass(frozen=True, slots=True)
class DiscoveryInputs:
    asset_id: str
    launch_items: Mapping[str, LaunchItem]
    apple_definitions: Mapping[str, LaunchItem]
    domains: Sequence[DomainListing]
    processes: Mapping[int, ProcessRow]
    listeners: Mapping[str, Listener]
    listener_method: str  # netstat | lsof | unavailable


@dataclass(slots=True)
class DiscoveredService:
    candidate: ServiceCandidate
    category: ServiceCategory | None
    state: str
    job: LoadedJob | None
    apple: AppleService | None
    instance_pids: list[int]
    version: str | None


@dataclass(slots=True)
class DiscoveryResult:
    services: dict[str, DiscoveredService] = field(default_factory=dict)
    #: listener key -> service_id, only for CONFIRMED (owner pid observed) attribution.
    listener_service: dict[str, str] = field(default_factory=dict)
    unattributed_listeners: list[str] = field(default_factory=list)
    truncated: bool = False


class _JobIndex:
    """Loaded jobs by label and by pid, plus the process tree for ownership walks."""

    def __init__(self, domains: Sequence[DomainListing], processes: Mapping[int, ProcessRow]):
        self.by_label: dict[str, LoadedJob] = {}
        self.by_pid: dict[int, LoadedJob] = {}
        self.overrides: dict[str, bool] = {}
        # system first so a label present in both domains resolves to the system job
        for listing in sorted(domains, key=lambda d: domain_name(d.domain) != "system"):
            for label, job in listing.jobs.items():
                self.by_label.setdefault(label, job)
                if job.pid is not None and not is_app_instance_label(label):
                    self.by_pid.setdefault(job.pid, job)
            for label, enabled in listing.overrides.items():
                self.overrides.setdefault(label, enabled)
        self.processes = processes

    def owner_job(self, pid: int) -> LoadedJob | None:
        """The launchd job whose process tree contains ``pid`` (GUI app instances excluded)."""
        current: int | None = pid
        for _ in range(MAX_TREE_DEPTH):
            if current is None or current <= 1:
                return None
            job = self.by_pid.get(current)
            if job is not None:
                return job
            proc = self.processes.get(current)
            current = proc.ppid if proc is not None else None
        return None

    def descendants(self, root: int, limit: int = MAX_INSTANCES_PER_SERVICE) -> list[int]:
        children: dict[int, list[int]] = {}
        for proc in self.processes.values():
            children.setdefault(proc.ppid, []).append(proc.pid)
        out: list[int] = []
        queue = sorted(children.get(root, []))
        while queue and len(out) < limit:
            pid = queue.pop(0)
            if pid in out or pid == root:
                continue
            out.append(pid)
            queue.extend(sorted(children.get(pid, [])))
        return out


def _job_state(job: LoadedJob | None) -> str:
    if job is None:
        return "not_loaded"
    return "running" if job.running else "loaded_idle"


def _job_attributes(builder: _Builder, job: LoadedJob | None, index: _JobIndex) -> None:
    label = builder.unit or builder.key
    builder.attributes.update(
        {
            "launchd_label": label,
            "launchd_domain": domain_name(job.domain) if job else None,
            "job_loaded": job is not None,
            "job_running": job.running if job else False,
            "job_pid": job.pid if job else None,
            "job_last_exit": job.last_exit if job else None,
            "override": ("enabled" if index.overrides[label] else "disabled")
            if label in index.overrides
            else None,
            "service_state": builder.state,
        }
    )


def _apply_definition(builder: _Builder, item: LaunchItem) -> None:
    builder.add_config_ref(item.path)
    if item.program and not builder.executable and item.program.startswith("/"):
        builder.executable = item.program
    for arg in item.program_arguments[1:]:
        if arg.startswith("/") and arg.lower().endswith(_CONFIG_SUFFIXES):
            builder.add_config_ref(arg)
    builder.attributes.update(
        {
            "definition_path": item.path,
            "definition_scope": item.scope,
            "definition_kind": item.kind,
            "definition_sha256": item.sha256,
            "program": item.program,
            "run_at_load": item.run_at_load,
            "keep_alive": item.keep_alive,
            "allowlisted": item.allowlisted,
            "socket_listeners": [s.render() for s in item.socket_specs] or None,
        }
    )


def discover(inputs: DiscoveryInputs) -> DiscoveryResult:
    """Pure discovery over one consistent set of observations (see module docstring)."""
    index = _JobIndex(inputs.domains, inputs.processes)
    builders: dict[str, _Builder] = {}
    result = DiscoveryResult()

    def host_service(label: str, name: str | None = None) -> _Builder:
        builder = builders.get(label)
        if builder is None:
            builder = _Builder(kind=ServiceKind.HOST_SERVICE, key=label, name=name or label)
            builder.unit = label
            builders[label] = builder
        return builder

    # 1. Apple sharing services: always reported when their definition exists.
    for apple in APPLE_SERVICES:
        definition = inputs.apple_definitions.get(apple.label)
        job = index.by_label.get(apple.label)
        if definition is None and job is None:
            continue  # not present on this macOS version: no evidence, no service
        builder = host_service(apple.label, apple.name)
        builder.evidence.add(DiscoveryEvidence.LAUNCHD_JOB)
        builder.apple = apple
        builder.category = apple.category
        builder.job = job
        builder.state = _job_state(job)
        if definition is not None:
            _apply_definition(builder, definition)
        enabled = (job is not None) if apple.enabled_when == "loaded" else bool(job and job.running)
        builder.attributes["sharing_enabled"] = enabled
        builder.attributes["apple_service"] = True

    # 2. Third-party job definitions on disk (loaded or not).
    for item in inputs.launch_items.values():
        label = item.label or item.path
        builder = host_service(label, None if item.label else os.path.basename(item.path))
        builder.evidence.add(DiscoveryEvidence.LAUNCHD_JOB)
        _apply_definition(builder, item)
        builder.job = index.by_label.get(label)
        builder.state = _job_state(builder.job)

    # 3. Loaded third-party jobs without a readable definition (e.g. SMAppService items).
    for label, job in index.by_label.items():
        if is_apple_label(label) or is_app_instance_label(label) or label in builders:
            continue
        builder = host_service(label)
        builder.evidence.add(DiscoveryEvidence.LAUNCHD_JOB)
        builder.job = job
        builder.state = _job_state(job)
        builder.attributes["definition_path"] = None

    # 4. Listening sockets -> owning process -> launchd job or application.
    launchd_held: set[tuple[str, int]] = set()
    for key, listener in sorted(inputs.listeners.items()):
        pids = sorted(listener.pids)
        if pids == [1]:
            launchd_held.add((listener.protocol, listener.port))
            continue  # launchd holds it for a socket-activated job: matched in step 5
        owners: set[str] = set()
        for pid in pids:
            if pid <= 1:
                continue
            job = index.owner_job(pid)
            proc = inputs.processes.get(pid)
            source = "lsof" if listener.attribution == "lsof" else "netstat (last pid)"
            if job is not None:
                builder = host_service(job.label)
                builder.evidence.add(DiscoveryEvidence.LAUNCHD_JOB)
                builder.job = job
                builder.state = _job_state(job)
                basis = f"{source}: socket owned by pid {pid}" + (
                    f" (launchd job {job.label}, pid {job.pid})" if job.pid != pid else ""
                )
            elif proc is not None and proc.executable.startswith("/"):
                exe = proc.executable
                builder = builders.get(exe) or _Builder(
                    kind=ServiceKind.APPLICATION, key=exe, name=app_display_name(exe)
                )
                builders[exe] = builder
                builder.executable = exe
                builder.evidence.add(DiscoveryEvidence.PROCESS)
                builder.attributes["executable_verified"] = proc.verified
                bundle = app_bundle(exe)
                if bundle:
                    builder.attributes["app_bundle"] = bundle
                basis = f"{source}: socket owned by pid {pid} ({os.path.basename(exe)})"
            else:
                continue  # owner pid not in the process snapshot: leave unattributed
            builder.evidence.add(DiscoveryEvidence.LISTENING_SOCKET)
            builder.add_endpoint(endpoint_from_listener(listener, basis))
            builder.add_pid(pid)
            owners.add(builder.key)
        if len(owners) == 1:
            result.listener_service[key] = _candidate_id(inputs.asset_id, builders[owners.pop()])
        elif not owners:
            result.unattributed_listeners.append(key)

    # 5. Socket-activated jobs: endpoints launchd holds while the job is loaded.
    for builder in builders.values():
        if builder.job is None or builder.kind is not ServiceKind.HOST_SERVICE:
            continue
        definition = (
            inputs.apple_definitions.get(builder.key)
            if builder.apple is not None
            else next(
                (i for i in inputs.launch_items.values() if (i.label or i.path) == builder.key),
                None,
            )
        )
        if definition is None or not definition.socket_specs:
            continue
        inferred = endpoints_from_socket_specs(
            definition.socket_specs, observed_launchd_ports=launchd_held
        )
        for endpoint in inferred:
            builder.add_endpoint(endpoint)
        if inferred:
            builder.evidence.add(DiscoveryEvidence.CONFIGURATION)
    for proto, port in sorted(launchd_held):
        matched = any(
            e.port == port and e.protocol == proto
            for b in builders.values()
            for e in b.endpoints.values()
            if e.attribution is PortAttribution.INFERRED
        )
        if not matched:
            result.unattributed_listeners.append(f"{proto}:*:{port} (launchd)")

    # 6. Instances: job process trees, Apple service executables, application processes.
    for builder in builders.values():
        if builder.job is not None and builder.job.pid is not None:
            builder.add_pid(builder.job.pid)
            for pid in index.descendants(builder.job.pid):
                builder.add_pid(pid)
        if builder.apple is not None:
            for proc in inputs.processes.values():
                if proc.executable in builder.apple.executables:
                    builder.add_pid(proc.pid)
                    if builder.state == "not_loaded":
                        builder.attributes["process_without_loaded_job"] = True
                    builder.evidence.add(DiscoveryEvidence.PROCESS)

    # 7. Known server binaries outside any job tree (process evidence only).
    for proc in sorted(inputs.processes.values(), key=lambda p: p.pid):
        base = os.path.basename(proc.executable)
        if base not in KNOWN_SERVER_EXECUTABLES or not proc.executable.startswith("/"):
            continue
        if index.owner_job(proc.pid) is not None:
            continue  # part of a launchd job's tree: already represented by that job
        if any(proc.pid in b.instance_pids for b in builders.values()):
            continue
        builder = builders.get(proc.executable) or _Builder(
            kind=ServiceKind.APPLICATION, key=proc.executable, name=base
        )
        builders[proc.executable] = builder
        builder.executable = proc.executable
        builder.evidence.add(DiscoveryEvidence.PROCESS)
        builder.attributes["executable_verified"] = proc.verified
        builder.add_pid(proc.pid)

    # 8. Product / version evidence and executables of running instances.
    for builder in builders.values():
        if builder.executable is None:
            running = [inputs.processes[p] for p in builder.instance_pids if p in inputs.processes]
            if running and running[0].executable.startswith("/"):
                builder.executable = running[0].executable
        formula, version = homebrew_product(builder.executable)
        version_source: str | None = None
        if version:
            verified = {
                proc.executable
                for pid in builder.instance_pids
                if (proc := inputs.processes.get(pid)) is not None and proc.verified
            }
            version_source = (
                "running executable (proc_pidpath)"
                if builder.executable in verified
                else "job definition"
            )
        # Running instances: a kernel-verified Cellar path shows the version actually running.
        for pid in builder.instance_pids:
            if version and formula:
                break
            proc = inputs.processes.get(pid)
            if proc is None:
                continue
            found, found_version = homebrew_product(proc.executable)
            if found is None or (formula is not None and found != formula):
                continue
            formula = found
            if found_version and proc.verified:
                version, version_source = found_version, "running executable (proc_pidpath)"
        if formula:
            builder.product = formula
            builder.version = version
            builder.attributes["product_evidence"] = "homebrew installation path"
            builder.attributes["version_evidence"] = version_source

    if len(builders) > MAX_SERVICES:
        result.truncated = True
    for builder in sorted(builders.values(), key=lambda b: (b.kind.value, b.key))[:MAX_SERVICES]:
        if builder.kind is ServiceKind.HOST_SERVICE:
            _job_attributes(builder, builder.job, index)
        if builder.state == "process" and builder.instance_pids:
            builder.state = "running"
            builder.attributes["service_state"] = "running"
        has_listener = any(
            e.attribution is PortAttribution.CONFIRMED for e in builder.endpoints.values()
        )
        candidate = ServiceCandidate(
            asset_id=inputs.asset_id,
            service_kind=builder.kind,
            service_key=builder.key[:2048],
            name=builder.name[:256],
            evidence=frozenset(builder.evidence) or frozenset({DiscoveryEvidence.LAUNCHD_JOB}),
            unit=builder.unit,
            executable=builder.executable,
            product=builder.product,
            endpoints=tuple(builder.endpoints[k] for k in sorted(builder.endpoints)),
            config_refs=tuple(builder.config_refs),
            is_network_service=True if builder.endpoints else None,
            attributes=bounded_attributes(
                {**builder.attributes, "owns_listening_socket": has_listener or None}
            ),
        )
        result.services[candidate.service_id] = DiscoveredService(
            candidate=candidate,
            category=builder.category,
            state=builder.state,
            job=builder.job,
            apple=builder.apple,
            instance_pids=sorted(builder.instance_pids),
            version=builder.version,
        )
    return result


def _candidate_id(asset_id: str, builder: _Builder) -> str:
    return make_service_id(asset_id, builder.kind.value, builder.key[:2048])


# ── adapters and coverage ────────────────────────────────────────────


def match_macos_adapter(candidate: ServiceCandidate) -> tuple[ServiceAdapter | None, str | None]:
    """(adapter usable on macOS, id of another platform's implemented adapter that matched).

    macOS adapters first; then the shared registry, accepting only PLANNED extension
    points (platform-neutral). An IMPLEMENTED adapter of another platform is never
    returned because the macOS collector does not collect its telemetry.
    """
    for adapter in MACOS_ADAPTERS.values():
        if adapter.matches(candidate):
            return adapter, None
    other = match_adapter(candidate)
    if other is None:
        return None, None
    if other.support is AdapterSupport.PLANNED or other.adapter_id in MACOS_ADAPTERS:
        return other, None
    planned = sorted(
        (a for a in all_adapters() if a.support is AdapterSupport.PLANNED and a.matches(candidate)),
        key=lambda a: a.adapter_id,
    )
    return (planned[0] if planned else None), other.adapter_id


@dataclass(frozen=True, slots=True)
class CoverageInputs:
    """What the collector knows about its own telemetry sources this cycle."""

    enabled_producers: frozenset[str]
    #: End of the newest unified-log window read successfully (source freshness).
    unified_log_fresh_until: datetime | None
    unified_log_failing: bool
    stale_after_seconds: float
    #: adapter id -> time of the newest event that adapter produced (if any).
    adapter_last_event: Mapping[str, datetime]


def coverage_for(
    discovered: DiscoveredService,
    adapter: ServiceAdapter | None,
    other_platform: str | None,
    inputs: CoverageInputs,
    now: datetime,
) -> tuple[AdapterSupport, MonitoringStatus, str]:
    if adapter is not None and adapter.adapter_id in MACOS_ADAPTERS:
        producer = ADAPTER_PRODUCER[adapter.adapter_id]
        if discovered.state == "not_loaded":
            what = discovered.apple.name if discovered.apple else discovered.candidate.name
            return (
                AdapterSupport.IMPLEMENTED,
                MonitoringStatus.UNMONITORED,
                f"{what} is off: launchd job {discovered.candidate.service_key} is not loaded, "
                f"so there is no telemetry to collect; the {adapter.adapter_id} binding "
                f"(unified-log producer '{producer}') applies as soon as it is loaded",
            )
        return classify_coverage(
            adapter,
            enabled=producer in inputs.enabled_producers,
            last_telemetry_at=inputs.unified_log_fresh_until,
            now=now,
            stale_after_seconds=inputs.stale_after_seconds,
            source_failing=inputs.unified_log_failing,
        )
    support, status, note = classify_coverage(
        adapter,
        enabled=False,
        last_telemetry_at=None,
        now=now,
        stale_after_seconds=inputs.stale_after_seconds,
    )
    if other_platform and adapter is None:
        note = (
            f"no macOS adapter; the '{other_platform}' adapter is implemented for another "
            "platform's collector and does not run on this host"
        )
    return support, status, note


def service_ref_for_label(
    asset_id: str, label: str, name: str, adapter_id: str | None
) -> ServiceRef:
    """Deterministic reference to a launchd-job service (no discovery state needed)."""
    return ServiceRef(
        service_id=make_service_id(asset_id, ServiceKind.HOST_SERVICE.value, label),
        name=name[:256],
        adapter_id=adapter_id,
    )


def adapter_service_ref(asset_id: str, adapter_id: str) -> ServiceRef:
    label = ADAPTER_LABEL[adapter_id]
    apple = APPLE_BY_LABEL.get(label)
    return service_ref_for_label(asset_id, label, apple.name if apple else label, adapter_id)


# ── records ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ServiceSummary:
    """What is kept between discovery cycles (snapshot item) to diff and tombstone."""

    @staticmethod
    def of(service: Service) -> dict[str, Any]:
        return {
            "kind": service.service_kind.value,
            "key": service.service_key,
            "name": service.name,
            "category": service.category.value,
            "evidence": [e.value for e in service.discovered_via],
            "adapter_id": service.adapter_id,
            "support": service.adapter_support.value,
            "endpoints": sorted(endpoint_label(e) for e in service.endpoints),
            "first_seen": service.first_seen.isoformat(),
        }


def build_records(
    result: DiscoveryResult,
    *,
    ctx: SourceContext,
    now: datetime,
    first_seen: Mapping[str, str],
    coverage: CoverageInputs,
    processes: Mapping[int, ProcessRow],
) -> tuple[list[Service], list[ServiceInstance]]:
    """Service + ServiceInstance records for every discovered service."""
    services: list[Service] = []
    instances: list[ServiceInstance] = []
    observed = to_ms(now)
    for service_id, discovered in sorted(result.services.items()):
        candidate = discovered.candidate
        adapter, other = match_macos_adapter(candidate)
        support, status, note = coverage_for(discovered, adapter, other, coverage, now)
        seen = first_seen.get(service_id)
        first = to_ms(datetime.fromisoformat(seen)) if seen else observed
        attributes = dict(candidate.attributes)
        if other:
            attributes["other_platform_adapter"] = other
        if adapter is not None and adapter.adapter_id in MACOS_ADAPTERS:
            attributes["telemetry_producer"] = ADAPTER_PRODUCER[adapter.adapter_id]
        last_event = coverage.adapter_last_event.get(adapter.adapter_id) if adapter else None
        record = build_service(
            ServiceCandidate(
                asset_id=candidate.asset_id,
                service_kind=candidate.service_kind,
                service_key=candidate.service_key,
                name=candidate.name,
                evidence=candidate.evidence,
                unit=candidate.unit,
                executable=candidate.executable,
                product=candidate.product,
                endpoints=candidate.endpoints,
                config_refs=candidate.config_refs,
                is_network_service=candidate.is_network_service,
                attributes=bounded_attributes(attributes),
            ),
            adapter,
            support=support,
            status=status,
            coverage_note=note[:2048],
            observed_by=ctx.collector_id,
            first_seen=first,
            now=observed,
            instance_count=len(discovered.instance_pids),
            last_telemetry_at=to_ms(last_event) if last_event else None,
            version=discovered.version,
        )
        category = discovered.category or record.category
        if category is not record.category:
            record = Service.model_validate({**record.model_dump(), "category": category})
        services.append(record)
        members = set(discovered.instance_pids)
        for pid in discovered.instance_pids:
            proc = processes.get(pid)
            if proc is None:
                continue  # no start time: identity would not be stable
            instances.append(
                instance_record(record.service_id, proc, ctx, observed, processes, members=members)
            )
    return services, instances


def instance_record(
    service_id_value: str,
    proc: ProcessRow,
    ctx: SourceContext,
    observed: datetime,
    processes: Mapping[int, ProcessRow],
    *,
    members: set[int] | None = None,
) -> ServiceInstance:
    """Process instance; ``parent_instance_id`` only links a parent of the SAME service."""
    parent = processes.get(proc.ppid) if members is None or proc.ppid in members else None
    return ServiceInstance(
        instance_id=make_instance_id(service_id_value, InstanceKind.PROCESS.value, proc.key),
        service_id=service_id_value,
        asset_id=ctx.asset_id,
        instance_kind=InstanceKind.PROCESS,
        instance_key=proc.key,
        parent_instance_id=make_instance_id(
            service_id_value, InstanceKind.PROCESS.value, parent.key
        )
        if parent is not None and parent.pid > 1
        else None,
        state="running",
        pid=proc.pid,
        process_name=proc.name[:256],
        user=proc.user[:256],
        started_at=to_ms(proc.started_at) if proc.started_at else None,
        observed_at=observed,
        present=True,
        observed_by=ctx.collector_id,
        attributes=bounded_attributes(
            {"executable": proc.executable, "executable_verified": proc.verified, "ppid": proc.ppid}
        ),
    )


def instance_tombstone(
    item: Mapping[str, Any], ctx: SourceContext, observed: datetime
) -> ServiceInstance:
    return ServiceInstance(
        instance_id=str(item["instance_id"]),
        service_id=str(item["service_id"]),
        asset_id=ctx.asset_id,
        instance_kind=InstanceKind.PROCESS,
        instance_key=str(item["key"]),
        state="stopped",
        pid=item.get("pid") if isinstance(item.get("pid"), int) else None,
        process_name=item.get("name") if isinstance(item.get("name"), str) else None,
        observed_at=observed,
        present=False,
        observed_by=ctx.collector_id,
    )


def instance_summary(instance: ServiceInstance) -> dict[str, Any]:
    return {
        "instance_id": instance.instance_id,
        "service_id": instance.service_id,
        "key": instance.instance_key,
        "pid": instance.pid,
        "name": instance.process_name,
    }


def service_tombstone(
    service_id_value: str, previous: Mapping[str, Any], ctx: SourceContext, now: datetime
) -> Service | None:
    """Service record with ``present=False`` for a service no longer observed."""
    try:
        evidence = [DiscoveryEvidence(e) for e in previous.get("evidence") or []]
        first = datetime.fromisoformat(str(previous["first_seen"]))
        return Service(
            service_id=service_id_value,
            asset_id=ctx.asset_id,
            service_kind=ServiceKind(previous["kind"]),
            service_key=str(previous["key"]),
            name=str(previous["name"]),
            category=ServiceCategory(previous.get("category") or "unknown"),
            discovered_via=evidence or [DiscoveryEvidence.LAUNCHD_JOB],
            adapter_id=previous.get("adapter_id"),
            adapter_support=AdapterSupport(previous.get("support") or "none"),
            monitoring_status=MonitoringStatus.UNMONITORED,
            coverage_note="service no longer observed",
            endpoints=[],
            instance_count=0,
            first_seen=to_ms(first),
            last_seen=to_ms(now),
            present=False,
            observed_by=ctx.collector_id,
        )
    except (KeyError, ValueError, TypeError):
        return None


def _ref(service: Service | Mapping[str, Any], service_id_value: str) -> ServiceRef:
    if isinstance(service, Service):
        return ServiceRef(
            service_id=service.service_id, name=service.name, adapter_id=service.adapter_id
        )
    return ServiceRef(
        service_id=service_id_value,
        name=str(service.get("name") or service_id_value)[:256],
        adapter_id=service.get("adapter_id")
        if isinstance(service.get("adapter_id"), str)
        else None,
    )


def discovered_event(
    service: Service, ctx: SourceContext, *, observed_at: datetime, snapshot: str, baseline: bool
) -> SecurityEvent:
    return make_event(
        ctx=ctx,
        event_type="service.discovered",
        source_type=SOURCE,
        native_key=f"service:{service.service_id}:discovered:{snapshot}",
        event_time=observed_at,
        observed_time=observed_at,
        parser=PARSER,
        message=f"service discovered: {service.name} ({service.service_kind.value}, "
        f"{service.monitoring_status.value})",
        action="service_discovered",
        outcome=Outcome.SUCCESS,
        resource=Resource(type="service", name=service.name, id=service.service_id),
        attributes={
            "service_kind": service.service_kind.value,
            "service_key": service.service_key,
            "category": service.category.value,
            "discovered_via": [e.value for e in service.discovered_via],
            "adapter_id": service.adapter_id,
            "adapter_support": service.adapter_support.value,
            "monitoring_status": service.monitoring_status.value,
            "coverage_note": service.coverage_note,
            "endpoints": [endpoint_label(e) for e in service.endpoints] or None,
            "product": service.product,
            "baseline": baseline,
        },
        service=_ref(service, service.service_id),
    )


def removed_event(
    service_id_value: str,
    previous: Mapping[str, Any],
    ctx: SourceContext,
    *,
    observed_at: datetime,
    snapshot: str,
) -> SecurityEvent:
    name = str(previous.get("name") or service_id_value)
    return make_event(
        ctx=ctx,
        event_type="service.removed",
        source_type=SOURCE,
        native_key=f"service:{service_id_value}:removed:{snapshot}",
        event_time=observed_at,
        observed_time=observed_at,
        parser=PARSER,
        message=f"service no longer observed: {name}",
        action="service_removed",
        outcome=Outcome.SUCCESS,
        resource=Resource(type="service", name=name, id=service_id_value),
        attributes={
            "service_kind": previous.get("kind"),
            "service_key": previous.get("key"),
            "endpoints": previous.get("endpoints") or None,
        },
        service=_ref(previous, service_id_value),
    )


def exposure_event(
    service: Service,
    previous: Mapping[str, Any],
    ctx: SourceContext,
    *,
    observed_at: datetime,
    snapshot: str,
) -> SecurityEvent | None:
    before = {str(e) for e in previous.get("endpoints") or []}
    after = {endpoint_label(e) for e in service.endpoints}
    added, removed = sorted(after - before), sorted(before - after)
    if not added and not removed:
        return None
    exposures = sorted({e.exposure for e in service.endpoints})
    return make_event(
        ctx=ctx,
        event_type="service.exposure.changed",
        source_type=SOURCE,
        native_key=f"service:{service.service_id}:exposure:{snapshot}",
        event_time=observed_at,
        observed_time=observed_at,
        parser=PARSER,
        message=f"service exposure changed: {service.name} (+{len(added)} / -{len(removed)})",
        action="service_exposure_changed",
        outcome=Outcome.SUCCESS,
        resource=Resource(type="service", name=service.name, id=service.service_id),
        attributes={
            "endpoints_added": added or None,
            "endpoints_removed": removed or None,
            "attribution": sorted({e.attribution.value for e in service.endpoints}) or None,
            "exposure": exposures or None,
            "non_loopback_exposure": any(e.exposure != "loopback" for e in service.endpoints),
        },
        service=_ref(service, service.service_id),
    )


def counts(services: Iterable[Service]) -> dict[str, int]:
    out: dict[str, int] = {}
    for service in services:
        out[service.monitoring_status.value] = out.get(service.monitoring_status.value, 0) + 1
        out[f"support_{service.adapter_support.value}"] = (
            out.get(f"support_{service.adapter_support.value}", 0) + 1
        )
    return out
