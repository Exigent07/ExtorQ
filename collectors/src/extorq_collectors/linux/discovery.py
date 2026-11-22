"""Linux service discovery from the dispatch boundary's ``inventory`` document.

Evidence (each genuinely observed by the unprivileged collector account):

* ``SYSTEMD_UNIT``      unit files (``/etc``, ``/run``, ``/usr/lib`` ...) and ``*.wants`` links;
* ``PROCESS``           ``/proc/<pid>/cgroup`` places a running process in a systemd unit
                        (kernel attested, world-readable);
* ``LISTENING_SOCKET``  ``ss -e --cgroup`` reports, per listening socket, the cgroup of the
                        process that created it (kernel ``sock_diag``; no root needed);
* ``CONFIGURATION``     sshd and nginx configuration (file paths and directive values only);
* ``ADAPTER_CONFIG``    applications declared in ``config/collectors/linux.yaml``.

Rules (PLAN.md section 10.1):

* A process is never assumed to be a network service: only ``.service`` units with running
  processes, a listening socket, a local enabled unit file or adapter configuration become
  services. User sessions and per-user managers (``user.slice``) are not host services.
* A port is attributed to a service only with stated confidence: ``confirmed`` when the
  kernel reports the socket's cgroup as the service's unit (or the ``.socket`` unit that
  activates it), ``inferred`` from configuration or a well-known port when no owner is
  observable, otherwise the listener stays ``unattributed`` at asset level.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from extorq.contracts import DiscoveryEvidence, PortAttribution, ServiceEndpoint, ServiceKind
from extorq.contracts.identity import instance_id as make_instance_id
from extorq_collectors.linux.adapters.webapp_json import LOG_SCHEMA, WebAppBinding
from extorq_collectors.linux.common import unit_exec_paths
from extorq_collectors.services.base import ServiceAdapter, ServiceCandidate, exposure_of
from extorq_collectors.services.registry import match_adapter

UNIT_SERVICE_SUFFIXES = (".service",)
_UNIT_COMPONENT = re.compile(r"^[A-Za-z0-9@:._\\-]{1,255}\.(service|scope|socket)$")
#: systemd unit search order (first wins), as reported by the dispatcher.
UNIT_DIR_PRECEDENCE = (
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
)
LOCAL_UNIT_DIRS = ("/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system")
#: Persistent administrator unit directories: an enabled unit file here is a service even when
#: it is not running (persistence). /run holds generator output and is excluded.
ADMIN_UNIT_DIRS = ("/etc/systemd/system", "/usr/local/lib/systemd/system")
MANAGER_UNIT = "init.scope"
MAX_CONFIG_REFS = 16
MAX_ENDPOINTS = 64


def unit_from_cgroup(path: str | None) -> str | None:
    """First unit component of a cgroup v2 path (``/system.slice/nginx.service`` -> nginx.service).

    Sub-cgroups delegated below a unit (``/system.slice/systemd-udevd.service/udev``) map to
    the unit; nested slices (``/system.slice/system-getty.slice/getty@tty1.service``) are
    skipped. Returns None for the root cgroup or unparseable paths.
    """
    if not isinstance(path, str) or not path.startswith("/"):
        return None
    for component in path.split("/"):
        if _UNIT_COMPONENT.match(component):
            return component
    return None


def template_of(unit: str) -> str | None:
    """``getty@tty1.service`` -> ``getty@.service`` (the template unit file); else None."""
    prefix, at, rest = unit.partition("@")
    if not at or "." not in rest:
        return None
    return f"{prefix}@.{rest.rsplit('.', 1)[-1]}"


def is_host_cgroup(path: str | None) -> bool:
    """True for system services and PID 1; False for user sessions/managers and unknown."""
    return isinstance(path, str) and (path.startswith("/system.slice/") or path == "/init.scope")


def socket_activated_service(socket_unit: str, units: Mapping[str, Mapping[str, Any]]) -> str:
    """The service a ``.socket`` unit activates: ``Service=`` if set, else the same name."""
    facts = units.get(socket_unit) or {}
    directives = facts.get("directives") if isinstance(facts, Mapping) else None
    if isinstance(directives, Mapping):
        values = directives.get("Service")
        if isinstance(values, list) and values and isinstance(values[0], str):
            return values[0]
    return socket_unit[: -len(".socket")] + ".service"


@dataclass(frozen=True)
class ProcessFact:
    pid: int
    ppid: int
    uid: int | None
    user: str | None
    comm: str
    executable: str | None
    start_ticks: int | None
    cgroup: str | None

    @property
    def unit(self) -> str | None:
        return unit_from_cgroup(self.cgroup) if is_host_cgroup(self.cgroup) else None

    @classmethod
    def from_doc(cls, raw: Mapping[str, Any]) -> ProcessFact | None:
        pid, ppid = raw.get("pid"), raw.get("ppid")
        if not isinstance(pid, int) or not isinstance(ppid, int) or pid <= 0:
            return None
        ticks = raw.get("start_ticks")
        uid = raw.get("uid")
        return cls(
            pid=pid,
            ppid=ppid,
            uid=uid if isinstance(uid, int) else None,
            user=raw["user"][:64] if isinstance(raw.get("user"), str) else None,
            comm=str(raw.get("comm") or "")[:64],
            executable=raw["executable"][:1024]
            if isinstance(raw.get("executable"), str) and raw["executable"].startswith("/")
            else None,
            start_ticks=ticks if isinstance(ticks, int) else None,
            cgroup=raw["cgroup"][:1024] if isinstance(raw.get("cgroup"), str) else None,
        )


@dataclass
class ListenerFact:
    proto: str
    address: str | None
    port: int
    interface: str | None
    uid: int | None
    cgroup: str | None
    pids: tuple[int, ...]

    @property
    def key(self) -> str:
        return f"{self.proto}:{self.address or '*'}:{self.port}"

    @classmethod
    def from_doc(cls, raw: Mapping[str, Any]) -> ListenerFact | None:
        port = raw.get("local_port")
        proto = raw.get("proto")
        if not isinstance(port, int) or not 0 <= port <= 65535 or proto not in ("tcp", "udp"):
            return None
        address = raw.get("local_address")
        try:
            address = str(ipaddress.ip_address(address)) if isinstance(address, str) else None
        except ValueError:
            address = None
        pids = tuple(
            p["pid"]
            for p in raw.get("processes") or []
            if isinstance(p, Mapping) and isinstance(p.get("pid"), int)
        )
        uid = raw.get("uid")
        return cls(
            proto=str(proto),
            address=address,
            port=port,
            interface=raw["interface"][:32] if isinstance(raw.get("interface"), str) else None,
            uid=uid if isinstance(uid, int) else None,
            cgroup=raw["cgroup"][:1024] if isinstance(raw.get("cgroup"), str) else None,
            pids=pids,
        )


@dataclass
class AttributedEndpoint:
    listener: ListenerFact
    endpoint: ServiceEndpoint


@dataclass
class DiscoveredService:
    """A discovered service plus the facts needed for records and coverage."""

    candidate: ServiceCandidate
    adapter: ServiceAdapter | None
    unit: str | None
    unit_path: str | None
    running: bool
    main_processes: list[ProcessFact] = field(default_factory=list)
    process_count: int = 0
    enabled_targets: list[str] = field(default_factory=list)
    endpoints: list[AttributedEndpoint] = field(default_factory=list)

    @property
    def service_id(self) -> str:
        return self.candidate.service_id


@dataclass
class DiscoveryResult:
    asset_id: str
    boot_id: str | None
    collected_at: datetime | None
    services: list[DiscoveredService]
    unattributed: list[ListenerFact]
    #: pid -> (service_id, instance_id) for main processes and their descendants (this boot).
    pid_instances: dict[int, tuple[str, str]]
    btime: int | None
    clk_tck: int | None

    def by_unit(self) -> dict[str, DiscoveredService]:
        return {s.unit: s for s in self.services if s.unit}

    def by_adapter(self, adapter_id: str) -> list[DiscoveredService]:
        return [s for s in self.services if s.adapter and s.adapter.adapter_id == adapter_id]

    def started_at(self, process: ProcessFact) -> datetime | None:
        if self.btime is None or not self.clk_tck or process.start_ticks is None:
            return None
        return datetime.fromtimestamp(self.btime + process.start_ticks / self.clk_tck, tz=UTC)

    def instance_key(self, process: ProcessFact) -> str:
        return f"{self.boot_id or '-'}:{process.pid}:{process.start_ticks}"

    def instance_id(self, service: DiscoveredService, process: ProcessFact) -> str:
        return make_instance_id(service.service_id, "process", self.instance_key(process))


def _units_by_name(units: Iterable[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    """Effective unit file per name (systemd precedence: /etc > /run > /usr/local > /usr/lib)."""
    ranked: dict[str, tuple[int, Mapping[str, Any]]] = {}
    for unit in units:
        name = unit.get("name")
        if unit.get("role") != "unit" or not isinstance(name, str):
            continue
        unit_dir = unit.get("unit_dir")
        rank = UNIT_DIR_PRECEDENCE.index(unit_dir) if unit_dir in UNIT_DIR_PRECEDENCE else 99
        if name not in ranked or rank < ranked[name][0]:
            ranked[name] = (rank, unit)
    return {name: facts for name, (_, facts) in ranked.items()}


def _enablement(entries: Iterable[Mapping[str, Any]]) -> dict[str, list[str]]:
    targets: dict[str, list[str]] = {}
    for entry in entries:
        unit, target = entry.get("unit"), entry.get("target")
        if isinstance(unit, str) and isinstance(target, str):
            targets.setdefault(unit, [])
            if target not in targets[unit]:
                targets[unit].append(target)
    return targets


def _config_ports(values: Sequence[str]) -> list[tuple[str | None, int]]:
    """nginx ``listen`` / sshd ``Port`` values -> [(address or None, port)]."""
    result: list[tuple[str | None, int]] = []
    for value in values:
        token = str(value).split()[0] if str(value).split() else ""
        address: str | None = None
        port_text = token
        if token.startswith("["):
            address, _, port_text = token[1:].partition("]:")
        elif ":" in token:
            address, _, port_text = token.rpartition(":")
        if port_text.isdigit() and 0 < int(port_text) <= 65535:
            result.append((address or None, int(port_text)))
    return result


def _nginx_directives(
    configs: Mapping[str, Any], name: str, context: str | None = None
) -> list[str]:
    nginx = configs.get("nginx")
    values: list[str] = []
    if not isinstance(nginx, Mapping):
        return values
    for ctx in nginx.get("contexts") or []:
        if not isinstance(ctx, Mapping) or (context and ctx.get("context") != context):
            continue
        directives = ctx.get("directives")
        if isinstance(directives, Mapping):
            values.extend(str(v)[:512] for v in directives.get(name) or [])
    return values


def _upstream_targets(configs: Mapping[str, Any]) -> list[tuple[str, int]]:
    targets: list[tuple[str, int]] = []
    for value in _nginx_directives(configs, "proxy_pass"):
        match = re.match(r"^https?://(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(?::(\d{1,5}))?", value)
        if match:
            host = match.group(1).strip("[]")
            port = (
                int(match.group(2))
                if match.group(2)
                else (443 if value.startswith("https") else 80)
            )
            targets.append((host, port))
    return targets


def _last(values: Sequence[str]) -> str | None:
    return values[-1] if values else None


def _endpoint(listener: ListenerFact, attribution: PortAttribution, basis: str) -> ServiceEndpoint:
    return ServiceEndpoint(
        protocol="tcp" if listener.proto == "tcp" else "udp",
        address=listener.address,
        port=listener.port,
        exposure=exposure_of(listener.address),
        attribution=attribution,
        attribution_basis=basis[:256],
    )


def discover(
    inventory: Mapping[str, Any],
    asset_id: str,
    *,
    webapps: Sequence[WebAppBinding] = (),
    known_units: Iterable[str] = (),
) -> DiscoveryResult:
    """Evidence-backed services of one Linux host (pure function of the inventory document).

    ``known_units`` are services discovered earlier: they remain services (not running)
    while their unit file still exists, so a service that stops is not "removed".
    """
    raw_host = inventory.get("host")
    host: Mapping[str, Any] = raw_host if isinstance(raw_host, Mapping) else {}
    raw_configs = inventory.get("configs")
    configs: Mapping[str, Any] = raw_configs if isinstance(raw_configs, Mapping) else {}
    units = _units_by_name(
        u for u in inventory.get("systemd_units") or [] if isinstance(u, Mapping)
    )
    enabled = _enablement(e for e in inventory.get("enablement") or [] if isinstance(e, Mapping))
    processes = [
        p
        for p in (
            ProcessFact.from_doc(r)
            for r in inventory.get("processes") or []
            if isinstance(r, Mapping)
        )
        if p is not None
    ]
    listeners = [
        lf
        for lf in (
            ListenerFact.from_doc(r)
            for r in inventory.get("listeners") or []
            if isinstance(r, Mapping)
        )
        if lf is not None
    ]
    by_pid = {p.pid: p for p in processes}

    # ── processes per host unit ──
    unit_procs: dict[str, list[ProcessFact]] = {}
    for proc in processes:
        unit = proc.unit
        if unit and (unit.endswith(UNIT_SERVICE_SUFFIXES) or unit == MANAGER_UNIT):
            unit_procs.setdefault(unit, []).append(proc)

    # ── socket ownership from kernel-reported cgroups ──
    owner_of: dict[int, tuple[str, str]] = {}  # listener index -> (service unit, basis)
    for index, listener in enumerate(listeners):
        if not is_host_cgroup(listener.cgroup):
            continue
        cg_unit = unit_from_cgroup(listener.cgroup)
        if cg_unit is None:
            continue
        if cg_unit.endswith(".service"):
            owner_of[index] = (cg_unit, f"socket cgroup {listener.cgroup} (kernel sock_diag)")
        elif cg_unit.endswith(".socket"):
            service_unit = socket_activated_service(cg_unit, units)
            owner_of[index] = (
                service_unit,
                f"socket cgroup {listener.cgroup}: socket unit {cg_unit} activates {service_unit}",
            )
    for index, listener in enumerate(listeners):
        if index in owner_of or not listener.pids:
            continue
        owner_proc = by_pid.get(listener.pids[0])
        if owner_proc is not None and owner_proc.unit and owner_proc.unit.endswith(".service"):
            owner_of[index] = (
                owner_proc.unit,
                f"socket owner pid {owner_proc.pid} in {owner_proc.unit} (ss -p)",
            )

    # ── which units are services ──
    service_units: dict[str, set[DiscoveryEvidence]] = {}
    for unit in unit_procs:
        service_units.setdefault(unit, set()).add(DiscoveryEvidence.PROCESS)
    for owner, _basis in owner_of.values():
        service_units.setdefault(owner, set()).add(DiscoveryEvidence.LISTENING_SOCKET)
    for name, facts in units.items():
        if (
            name.endswith(".service")
            and facts.get("unit_dir") in ADMIN_UNIT_DIRS
            and facts.get("kind") == "file"
            and name in enabled
            and "@" not in name
        ):
            service_units.setdefault(name, set())
    for unit in known_units:
        if unit not in service_units and (unit in units or template_of(unit) in units):
            service_units[unit] = set()
    app_by_unit = {app.unit: app for app in webapps}
    for app in webapps:
        service_units.setdefault(app.unit, set()).add(DiscoveryEvidence.ADAPTER_CONFIG)
    for unit, evidence in service_units.items():
        if unit in units or template_of(unit) in units:
            evidence.add(DiscoveryEvidence.SYSTEMD_UNIT)

    # ── configuration references ──
    sshd_cfg = configs.get("sshd") if isinstance(configs.get("sshd"), Mapping) else None
    nginx_cfg = configs.get("nginx") if isinstance(configs.get("nginx"), Mapping) else None
    config_refs: dict[str, list[str]] = {}
    config_attrs: dict[str, dict[str, Any]] = {}
    if sshd_cfg is not None:
        for unit in ("ssh.service", "sshd.service"):
            if unit in service_units:
                service_units[unit].add(DiscoveryEvidence.CONFIGURATION)
                config_refs[unit] = [str(p) for p in sshd_cfg.get("files_read") or []]
                ports = [str(p) for p in sshd_cfg.get("port") or []]
                config_attrs[unit] = {
                    "configured_ports": [p for _, p in _config_ports(ports)] or [22],
                    "configured_ports_basis": "sshd_config Port" if ports else "sshd default",
                    "sshd_log_level": sshd_cfg.get("loglevel"),
                }
    if nginx_cfg is not None and "nginx.service" in service_units:
        service_units["nginx.service"].add(DiscoveryEvidence.CONFIGURATION)
        config_refs["nginx.service"] = [
            str(p) for p in nginx_cfg.get("files_read") or [] if not str(p).endswith("mime.types")
        ]
        config_attrs["nginx.service"] = {
            "configured_ports": sorted(
                {p for _, p in _config_ports(_nginx_directives(configs, "listen"))}
            ),
            "server_tokens": _last(_nginx_directives(configs, "server_tokens")),
            "proxy_targets": [f"{h}:{p}" for h, p in _upstream_targets(configs)][:16],
            "access_log": _nginx_directives(configs, "access_log")[:8],
            "error_log": _nginx_directives(configs, "error_log")[:8],
        }

    # ── build discovered services ──
    asset = asset_id
    services: dict[str, DiscoveredService] = {}
    for unit, evidence in sorted(service_units.items()):
        if not evidence:
            continue
        facts = units.get(unit) or units.get(template_of(unit) or "") or {}
        procs = unit_procs.get(unit, [])
        unit_pids = {p.pid for p in procs}
        mains = sorted((p for p in procs if p.ppid not in unit_pids), key=lambda p: p.pid)
        binding = app_by_unit.get(unit)
        attributes: dict[str, Any] = {"unit": unit}
        if isinstance(facts, Mapping) and facts:
            attributes["unit_path"] = facts.get("path")
            attributes["unit_dir"] = facts.get("unit_dir")
            attributes["vendor_unit"] = facts.get("unit_dir") not in LOCAL_UNIT_DIRS
            if facts.get("description"):
                attributes["unit_description"] = str(facts["description"])[:256]
            exec_start = unit_exec_paths(facts.get("exec_start"))
            if exec_start:
                attributes["exec_start"] = exec_start[0]
            directives = (
                facts.get("directives") if isinstance(facts.get("directives"), Mapping) else {}
            )
            for key, attr in (
                ("Type", "unit_type"),
                ("User", "run_as_user"),
                ("DynamicUser", "dynamic_user"),
            ):
                values = directives.get(key) if isinstance(directives, Mapping) else None
                if isinstance(values, list) and values:
                    attributes[attr] = str(values[0])[:64]
        if unit in enabled:
            attributes["enabled_by"] = enabled[unit][:16]
        if binding is not None:
            attributes["log_schema"] = LOG_SCHEMA
            attributes["app_name"] = binding.name
            attributes["syslog_identifier"] = binding.syslog_identifier
        attributes.update(config_attrs.get(unit, {}))
        is_manager = unit == MANAGER_UNIT
        executable = None
        if mains:
            executable = mains[0].executable or mains[0].comm
        candidate = ServiceCandidate(
            asset_id=asset,
            service_kind=ServiceKind.HOST_SERVICE,
            service_key=unit,
            name="systemd" if is_manager else unit.removesuffix(".service"),
            evidence=frozenset(evidence),
            unit=unit,
            executable=executable,
            config_refs=tuple(config_refs.get(unit, [])[:MAX_CONFIG_REFS]),
            is_network_service=None,
            attributes=attributes,
        )
        services[unit] = DiscoveredService(
            candidate=candidate,
            adapter=match_adapter(candidate),
            unit=unit,
            unit_path=str(facts.get("path"))
            if isinstance(facts, Mapping) and facts.get("path")
            else None,
            running=bool(procs),
            main_processes=mains,
            process_count=len(procs),
            enabled_targets=enabled.get(unit, [])[:16],
        )

    # ── endpoints: confirmed by socket cgroup, else inferred, else unattributed ──
    unattributed: list[ListenerFact] = []
    for index, listener in enumerate(listeners):
        owned = owner_of.get(index)
        if owned and owned[0] in services:
            services[owned[0]].endpoints.append(
                AttributedEndpoint(
                    listener, _endpoint(listener, PortAttribution.CONFIRMED, owned[1])
                )
            )
            continue
        if listener.cgroup is None:
            inferred = _infer_owner(listener, services)
            if inferred is not None:
                service, basis = inferred
                service.endpoints.append(
                    AttributedEndpoint(
                        listener, _endpoint(listener, PortAttribution.INFERRED, basis)
                    )
                )
                continue
        unattributed.append(listener)

    # ── finalise candidates with endpoints + upstream relationships ──
    upstreams = _upstream_targets(configs) if nginx_cfg is not None else []
    for service in services.values():
        if service.endpoints:
            service.candidate = _with_endpoints(service.candidate, service.endpoints)
    nginx = services.get("nginx.service")
    if nginx is not None:
        for host_name, port in upstreams:
            for other in services.values():
                if other is nginx:
                    continue
                if any(
                    ep.endpoint.port == port
                    and ep.endpoint.attribution is PortAttribution.CONFIRMED
                    and _host_matches(host_name, ep.listener.address)
                    for ep in other.endpoints
                ):
                    _append_attr(nginx, "upstream_services", other.unit or other.candidate.name)
                    _append_attr(other, "fronted_by", "nginx.service")

    pid_instances: dict[int, tuple[str, str]] = {}
    result = DiscoveryResult(
        asset_id=asset,
        boot_id=str(host.get("boot_id")) if host.get("boot_id") else None,
        collected_at=_parse_time(inventory.get("collected_at")),
        services=sorted(services.values(), key=lambda s: s.candidate.service_key),
        unattributed=unattributed,
        pid_instances=pid_instances,
        btime=host.get("btime") if isinstance(host.get("btime"), int) else None,
        clk_tck=host.get("clk_tck") if isinstance(host.get("clk_tck"), int) else None,
    )
    children: dict[int, list[int]] = {}
    for proc in processes:
        children.setdefault(proc.ppid, []).append(proc.pid)
    for service in result.services:
        for main in service.main_processes:
            iid = result.instance_id(service, main)
            stack = [main.pid]
            while stack:
                pid = stack.pop()
                if pid in pid_instances:
                    continue
                pid_instances[pid] = (service.service_id, iid)
                if pid != 1:  # PID 1 is the parent of everything: only itself
                    stack.extend(children.get(pid, []))
    return result


def _infer_owner(
    listener: ListenerFact, services: Mapping[str, DiscoveredService]
) -> tuple[DiscoveredService, str] | None:
    """Owner inferred from configuration, else a unique well-known-port adapter match."""
    for service in services.values():
        ports = service.candidate.attributes.get("configured_ports")
        if isinstance(ports, list) and listener.port in ports:
            basis = service.candidate.attributes.get("configured_ports_basis") or "configuration"
            return service, f"{basis} lists port {listener.port} (socket owner not observable)"
    matches = [
        s
        for s in services.values()
        if s.adapter is not None and (listener.proto, listener.port) in s.adapter.well_known_ports
    ]
    if len(matches) == 1:
        return matches[0], (
            f"well-known port {listener.proto}/{listener.port} of adapter "
            f"{matches[0].adapter.adapter_id if matches[0].adapter else '?'} "
            "(socket owner not observable)"
        )
    return None


def _host_matches(host_name: str, address: str | None) -> bool:
    """Does a proxy target host reach a socket bound to ``address``?"""
    if address is None:
        return False
    try:
        bound = ipaddress.ip_address(address)
    except ValueError:
        return False
    if bound.is_unspecified:  # bound to every address
        return True
    if host_name == "localhost":
        return bound.is_loopback
    try:
        return ipaddress.ip_address(host_name) == bound
    except ValueError:
        return False


def _append_attr(service: DiscoveredService, key: str, value: str) -> None:
    attributes = dict(service.candidate.attributes)
    values = list(attributes.get(key) or [])
    if value not in values:
        values.append(value)
    attributes[key] = values[:16]
    service.candidate = _replace(service.candidate, attributes=attributes)


def _with_endpoints(
    candidate: ServiceCandidate, endpoints: Sequence[AttributedEndpoint]
) -> ServiceCandidate:
    ordered = sorted(
        (ep.endpoint for ep in endpoints), key=lambda e: (e.protocol, e.port, e.address or "")
    )[:MAX_ENDPOINTS]
    return _replace(candidate, endpoints=tuple(ordered), is_network_service=True)


def _replace(candidate: ServiceCandidate, **changes: Any) -> ServiceCandidate:
    from dataclasses import replace

    return replace(candidate, **changes)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo else None
