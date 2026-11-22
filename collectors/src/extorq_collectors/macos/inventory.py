"""Host inventory: listening sockets, process snapshot, installed applications.

Sources (all non-privileged, read-only):

* ``/usr/sbin/netstat -anvW -p tcp|udp``: every socket on the host, including
  root-owned ones. On current macOS the verbose output carries a
  ``process:pid`` column: the *last* process that used the socket (kernel
  ``so_last_pid``), with the name truncated to 16 characters. Socket-activated
  launchd services therefore show ``launchd:1``. IPv6 addresses can be
  truncated in this output; such addresses are kept verbatim and flagged.
* ``/bin/ps -axww -o pid=,ppid=,uid=,user=,lstart=,comm=``: process snapshot.
  ``comm`` is argv[0] as the process set it (often, but not always, a path; it is
  not verified). The collector adds the kernel-reported executable path from
  ``proc_pidpath`` (:mod:`extorq_collectors.macos.procinfo`) when available.
  Full arguments are NOT collected by default (privacy); ``include_process_args``
  adds a redacted ``args`` column.
* ``/usr/sbin/lsof -nP -iTCP -sTCP:LISTEN`` / ``-iUDP`` (field output): fallback
  when netstat returns an empty socket table. On macOS 27 the kernel withholds
  the socket table from processes that have a live ad-hoc-signed ancestor (such
  as the uv-managed CPython running the collector). lsof only sees the current
  user's processes, so root-owned listeners (launchd-activated sshd / Screen
  Sharing, mDNSResponder) are invisible in that mode; this is reported as a gap
  and the dependent posture checks report ``error`` (unknown), never ``pass``.
* ``/usr/sbin/system_profiler -json -detailLevel mini SPApplicationsDataType``:
  installed applications with provenance (``obtained_from``) and signing chain.

Listening sockets are diffed (``network.listener.opened|closed``); processes and
applications are inventory-only (the catalog has no macOS process/package events).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from extorq.contracts import (
    Actor,
    ActorType,
    InventoryItem,
    InventoryItemType,
    Network,
    Outcome,
    ProcessInfo,
    Resource,
    SecurityEvent,
    ServiceRef,
    SourceType,
)
from extorq.contracts.identity import canonical_json, sha256_hex
from extorq_collectors.macos.commands import CommandResult, CommandRunner
from extorq_collectors.macos.common import (
    SourceContext,
    bounded_attributes,
    clean_text,
    make_event,
    to_ms,
)
from extorq_collectors.services.base import exposure_of

PARSER = "macos-inventory"
SOURCE = SourceType.MACOS_INVENTORY

NETSTAT_TCP = ["/usr/sbin/netstat", "-anvW", "-p", "tcp"]
NETSTAT_UDP = ["/usr/sbin/netstat", "-anvW", "-p", "udp"]
PS_ARGV = ["/bin/ps", "-axww", "-o", "pid=,ppid=,uid=,user=,lstart=,comm="]
PS_ARGS_ARGV = ["/bin/ps", "-axww", "-o", "pid=,args="]
LSOF_TCP_LISTEN_ARGV = [
    "/usr/sbin/lsof",
    "-nP",
    "-iTCP",
    "-sTCP:LISTEN",
    "-F",
    "pcLnPtT",
    "+c",
    "0",
]
LSOF_UDP_ARGV = ["/usr/sbin/lsof", "-nP", "-iUDP", "-F", "pcLnPt", "+c", "0"]
SYSTEM_PROFILER_APPS = [
    "/usr/sbin/system_profiler",
    "-json",
    "-detailLevel",
    "mini",
    "SPApplicationsDataType",
]

MAX_PROCESSES = 5000
MAX_APPS = 5000
MAX_SOCKETS = 20000

# ── netstat ──────────────────────────────────────────────────────────

_NETSTAT_ROW = re.compile(
    r"^(?P<proto>(?:tcp|udp)(?:46|4|6))\s+(?P<recvq>\d+)\s+(?P<sendq>\d+)\s+"
    r"(?P<local>\S+)\s+(?P<foreign>\S+)\s+(?:(?P<state>[A-Z][A-Z0-9_]*)\s+)?"
    r"(?P<rest>.*)$"
)
_NETSTAT_PROC_TAIL = re.compile(
    r"^(?P<rx>\d+)\s+(?P<tx>\d+)\s+(?P<rhiwat>\d+)\s+(?P<shiwat>\d+)\s+"
    r"(?P<proc>.*):(?P<pid>\d+)\s+(?P<tail>(?:[0-9a-f]+\s+){7}[0-9a-f]+)\s*$"
)


@dataclass(frozen=True, slots=True)
class SocketRow:
    proto: str  # tcp4 | tcp6 | tcp46 | udp4 | udp6 | udp46
    local: str
    foreign: str
    state: str | None
    process_name: str | None
    pid: int | None


def parse_netstat(text: str) -> list[SocketRow]:
    rows: list[SocketRow] = []
    for line in text.splitlines():
        match = _NETSTAT_ROW.match(line)
        if not match:
            continue
        proc_name: str | None = None
        pid: int | None = None
        tail = _NETSTAT_PROC_TAIL.match(match.group("rest"))
        if tail:
            proc_name = tail.group("proc").strip() or None
            pid = int(tail.group("pid"))
        rows.append(
            SocketRow(
                proto=match.group("proto"),
                local=match.group("local"),
                foreign=match.group("foreign"),
                state=match.group("state"),
                process_name=proc_name,
                pid=pid,
            )
        )
        if len(rows) >= MAX_SOCKETS:
            break
    return rows


def split_endpoint(endpoint: str) -> tuple[str, str]:
    """``127.0.0.1.8021`` -> (``127.0.0.1``, ``8021``); ``*.*`` -> (``*``, ``*``)."""
    host, sep, port = endpoint.rpartition(".")
    if not sep:
        return endpoint, "*"
    return host, port


@dataclass(slots=True)
class Listener:
    """One listening socket (TCP LISTEN or unconnected UDP), keyed by protocol/address/port.

    ``bind_scope`` is the collector's internal classification of the bind address (it also
    separates link-local and specific addresses, which posture needs). Events and inventory
    report ``exposure`` with the contract's ServiceEndpoint vocabulary instead
    (:func:`extorq_collectors.services.base.exposure_of`: ``any`` = all interfaces,
    ``loopback``, ``private``, ``unknown``) so listener events and service endpoints agree.
    """

    protocol: str  # tcp | udp
    family: str  # ipv4 | ipv6 | dual
    address: str  # normalised textual address, or the raw (truncated) token
    port: int
    bind_scope: str  # any | loopback | link_local | specific | unknown
    address_valid: bool
    processes: set[str] = field(default_factory=set)
    pids: set[int] = field(default_factory=set)
    executables: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    attribution: str = "unavailable"  # netstat_last_pid | lsof | unavailable

    @property
    def key(self) -> str:
        addr = f"[{self.address}]" if ":" in self.address else self.address
        return f"{self.protocol}:{addr}:{self.port}"

    @property
    def exposed(self) -> bool:
        """Bound to a non-loopback address (reachable from other hosts, firewall permitting)."""
        return self.bind_scope in ("any", "specific", "link_local")

    def fingerprint(self) -> str:
        return sha256_hex(canonical_json(sorted(self.processes)))

    @property
    def exposure(self) -> str:
        return exposure_of(self.address) if self.address_valid else "unknown"

    def attributes(self) -> dict[str, Any]:
        return bounded_attributes(
            {
                "protocol": self.protocol,
                "family": self.family,
                "bind_address": self.address,
                "port": self.port,
                "exposure": self.exposure,
                "address_truncated": None if self.address_valid else True,
                "processes": sorted(self.processes) or None,
                "pids": sorted(self.pids) or None,
                "executables": sorted(self.executables) or None,
                "users": sorted(self.users) or None,
                "process_attribution": self.attribution,
            }
        )

    def summary(self) -> dict[str, Any]:
        return {
            "fp": self.fingerprint(),
            "processes": sorted(self.processes)[:8],
            "address": self.address,
            "port": self.port,
            "protocol": self.protocol,
            "family": self.family,
        }


def _family(proto: str) -> str:
    if proto.endswith("46"):
        return "dual"
    return "ipv6" if proto.endswith("6") else "ipv4"


def _normalise_host(host: str, family: str) -> tuple[str, str, bool]:
    """Return (address, bind_scope, valid)."""
    if host == "*":
        return ("0.0.0.0" if family == "ipv4" else "::"), "any", True  # noqa: S104 - wildcard bind
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host, "unknown", False
    if ip.is_loopback:
        scope = "loopback"
    elif ip.is_unspecified:
        scope = "any"
    elif ip.is_link_local:
        scope = "link_local"
    else:
        scope = "specific"
    return str(ip), scope, True


def listeners_from_rows(
    rows: Iterable[SocketRow],
    *,
    include_udp: bool = True,
    process_index: Mapping[int, ProcessRow] | None = None,
) -> dict[str, Listener]:
    listeners: dict[str, Listener] = {}
    for row in rows:
        protocol = row.proto[:3]
        if protocol == "tcp":
            if row.state != "LISTEN":
                continue
        else:
            if not include_udp or row.foreign != "*.*":
                continue
        host, port_text = split_endpoint(row.local)
        if not port_text.isdigit():
            continue
        port = int(port_text)
        if not 0 < port <= 65535:
            continue
        family = _family(row.proto)
        address, scope, valid = _normalise_host(host, family)
        listener = Listener(protocol, family, address, port, scope, valid)
        existing = listeners.setdefault(listener.key, listener)
        if row.process_name:
            existing.processes.add(row.process_name)
            existing.attribution = "netstat_last_pid"
        if row.pid is not None:
            existing.pids.add(row.pid)
            proc = (process_index or {}).get(row.pid)
            if proc is not None:
                existing.executables.add(proc.executable)
                existing.users.add(proc.user)
    return listeners


# ── lsof (fallback when the socket table is withheld) ────────────────


@dataclass(frozen=True, slots=True)
class LsofSocket:
    pid: int
    command: str | None
    login: str | None
    family: str | None  # IPv4 | IPv6
    protocol: str | None  # TCP | UDP
    name: str  # e.g. *:7000, 127.0.0.1:27017, [::1]:27017 (connected UDP: a->b)
    state: str | None  # TCP state (LISTEN) when reported


def parse_lsof_fields(text: str) -> list[LsofSocket]:
    """Parse ``lsof -F pcuLnPtT`` output (one tagged field per line, per process/fd)."""
    results: list[LsofSocket] = []
    pid: int | None = None
    command: str | None = None
    login: str | None = None
    fd: dict[str, str] | None = None

    def flush() -> None:
        if pid is not None and fd is not None and "n" in fd:
            results.append(
                LsofSocket(
                    pid=pid,
                    command=command,
                    login=login,
                    family=fd.get("t"),
                    protocol=fd.get("P"),
                    name=fd["n"],
                    state=fd.get("ST"),
                )
            )

    for line in text.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            flush()
            fd = None
            pid = int(value) if value.isdigit() else None
            command = None
            login = None
        elif tag == "c":
            command = value or None
        elif tag == "L":
            login = value or None
        elif tag == "f":
            flush()
            fd = {}
        elif fd is not None and tag in ("t", "P", "n"):
            fd[tag] = value
        elif fd is not None and tag == "T" and value.startswith("ST="):
            fd["ST"] = value[3:]
    flush()
    return results


def listeners_from_lsof(
    entries: Iterable[LsofSocket], *, include_udp: bool = True
) -> dict[str, Listener]:
    """Build listeners from lsof sockets (current user's processes only)."""
    listeners: dict[str, Listener] = {}
    for entry in entries:
        protocol = (entry.protocol or "").lower()
        if protocol == "tcp":
            if entry.state != "LISTEN":
                continue
        elif protocol == "udp":
            if not include_udp or "->" in entry.name:
                continue
        else:
            continue
        host, _, port_text = entry.name.rpartition(":")
        if not port_text.isdigit():
            continue
        port = int(port_text)
        if not 0 < port <= 65535:
            continue
        family = "ipv6" if entry.family == "IPv6" else "ipv4"
        address, scope, valid = _normalise_host(host.strip("[]") or "*", family)
        listener = Listener(protocol, family, address, port, scope, valid, attribution="lsof")
        existing = listeners.setdefault(listener.key, listener)
        if entry.command:
            existing.processes.add(entry.command)
        existing.pids.add(entry.pid)
        if entry.login:
            existing.users.add(entry.login)
    return listeners


def socket_table_withheld(result: CommandResult) -> bool:
    """netstat exited 0 but printed nothing at all, not even its header.

    Observed on macOS 27 when a live ancestor of netstat is an ad-hoc signed
    binary (for example the uv-managed CPython running the collector): the
    kernel returns an empty socket table. A genuinely empty table still prints
    the "Active Internet connections" header, so the two cases are distinct.
    """
    return result.ok and "Active Internet connections" not in result.text()


@dataclass(slots=True)
class ListenerSnapshot:
    listeners: dict[str, Listener]
    #: netstat (all sockets) | lsof (current user's processes only) | unavailable
    method: str
    errors: list[str] = field(default_factory=list)

    @property
    def full_visibility(self) -> bool:
        return self.method == "netstat"


def collect_listeners(
    runner: CommandRunner,
    *,
    include_udp: bool,
    timeout: float,
    process_index: Mapping[int, ProcessRow] | None = None,
) -> ListenerSnapshot:
    """Listening sockets via netstat, falling back to lsof when the table is withheld."""
    errors: list[str] = []
    tcp = runner.run(NETSTAT_TCP, timeout=timeout)
    if tcp.ok and not socket_table_withheld(tcp):
        rows = parse_netstat(tcp.text())
        if include_udp:
            udp = runner.run(NETSTAT_UDP, timeout=timeout)
            if udp.ok and not socket_table_withheld(udp):
                rows += parse_netstat(udp.text())
            else:
                errors.append(f"netstat udp: {udp.summary()}")
        listeners = listeners_from_rows(rows, include_udp=include_udp, process_index=process_index)
        return ListenerSnapshot(listeners, "netstat", errors)
    if tcp.ok:
        errors.append(
            "netstat returned an empty socket table (withheld for this process tree); "
            "falling back to lsof (current user's processes only)"
        )
    else:
        errors.append(f"netstat tcp: {tcp.summary()}")
    entries: list[LsofSocket] = []
    lsof_ok = False
    for argv in (LSOF_TCP_LISTEN_ARGV, *((LSOF_UDP_ARGV,) if include_udp else ())):
        result = runner.run(argv, timeout=timeout)
        # lsof exits 1 when nothing matched; that is an empty result, not an error.
        if result.ok or (
            result.returncode == 1
            and not result.stderr.strip()
            and not result.timed_out
            and result.error is None
        ):
            entries.extend(parse_lsof_fields(result.text()))
            lsof_ok = True
        else:
            errors.append(f"lsof: {result.summary()}")
    if not lsof_ok:
        return ListenerSnapshot({}, "unavailable", errors)
    listeners = listeners_from_lsof(entries, include_udp=include_udp)
    for listener in listeners.values():
        for pid in listener.pids:
            proc = (process_index or {}).get(pid)
            if proc is not None:
                listener.executables.add(proc.executable)
    return ListenerSnapshot(listeners, "lsof", errors)


# ── ps ───────────────────────────────────────────────────────────────

_PS_ROW = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<ppid>\d+)\s+(?P<uid>\d+)\s+(?P<user>\S+)\s+"
    r"(?P<lstart>[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+"
    r"(?P<comm>.+?)\s*$"
)


@dataclass(frozen=True, slots=True)
class ProcessRow:
    pid: int
    ppid: int
    uid: int
    user: str
    started_at: datetime | None
    #: ``ps -o comm``: argv[0] as chosen by the process itself (unverified).
    command: str
    #: Executable path reported by the kernel (``proc_pidpath``), when available.
    path: str | None = None
    args: str | None = None

    @property
    def executable(self) -> str:
        """Verified kernel path when known, else the (unverified) ps command."""
        return self.path or self.command

    @property
    def verified(self) -> bool:
        return self.path is not None

    @property
    def name(self) -> str:
        return os.path.basename(self.executable) or self.executable

    @property
    def key(self) -> str:
        started = int(self.started_at.timestamp()) if self.started_at else 0
        return f"{self.pid}:{started}"

    def attributes(self) -> dict[str, Any]:
        return bounded_attributes(
            {
                "pid": self.pid,
                "ppid": self.ppid,
                "uid": self.uid,
                "user": self.user,
                "name": self.name,
                "executable": self.executable,
                "executable_verified": self.verified,
                "command": self.command if self.command != self.executable else None,
                "started_at": self.started_at.isoformat().replace("+00:00", "Z")
                if self.started_at
                else None,
                "args": self.args,
            }
        )


def with_verified_paths(
    rows: list[ProcessRow], resolve: Callable[[int], str | None]
) -> list[ProcessRow]:
    """Attach kernel-reported executable paths (see :mod:`extorq_collectors.macos.procinfo`)."""
    return [replace(row, path=resolve(row.pid)) for row in rows]


def parse_lstart(value: str) -> datetime | None:
    """``Sun Nov 15 14:21:19 2026`` (host local time) -> aware UTC datetime."""
    try:
        naive = datetime.strptime(" ".join(value.split()), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None
    return naive.astimezone().astimezone(UTC)


def parse_ps(text: str) -> list[ProcessRow]:
    rows: list[ProcessRow] = []
    for line in text.splitlines():
        match = _PS_ROW.match(line)
        if not match:
            continue
        rows.append(
            ProcessRow(
                pid=int(match.group("pid")),
                ppid=int(match.group("ppid")),
                uid=int(match.group("uid")),
                user=match.group("user"),
                started_at=parse_lstart(match.group("lstart")),
                command=match.group("comm"),
            )
        )
        if len(rows) >= MAX_PROCESSES:
            break
    return rows


_PS_ARGS_ROW = re.compile(r"^\s*(?P<pid>\d+)\s+(?P<args>.*?)\s*$")


def parse_ps_args(text: str) -> tuple[dict[int, str], int]:
    """pid -> redacted, truncated argument string (only when explicitly enabled)."""
    out: dict[int, str] = {}
    redactions = 0
    for line in text.splitlines():
        match = _PS_ARGS_ROW.match(line)
        if not match:
            continue
        cleaned, count = clean_text(match.group("args"), 1024)
        redactions += count
        if cleaned:
            out[int(match.group("pid"))] = cleaned
    return out, redactions


# ── system_profiler applications ─────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AppRow:
    path: str
    name: str | None
    version: str | None
    obtained_from: str | None
    signed_by: tuple[str, ...]
    arch_kind: str | None
    last_modified: str | None

    def attributes(self) -> dict[str, Any]:
        return bounded_attributes(
            {
                "name": self.name,
                "version": self.version,
                "obtained_from": self.obtained_from,
                "signer": self.signed_by[0] if self.signed_by else None,
                "signing_chain": list(self.signed_by) or None,
                "signed": bool(self.signed_by),
                "arch_kind": self.arch_kind,
                "last_modified": self.last_modified,
            }
        )


def parse_system_profiler_apps(text: str) -> list[AppRow]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"system_profiler output is not JSON: {exc.msg}") from exc
    apps = data.get("SPApplicationsDataType") if isinstance(data, dict) else None
    if not isinstance(apps, list):
        raise ValueError("system_profiler output lacks SPApplicationsDataType")
    rows: list[AppRow] = []
    for app in apps[:MAX_APPS]:
        if not isinstance(app, dict) or not isinstance(app.get("path"), str):
            continue
        signed = app.get("signed_by")
        rows.append(
            AppRow(
                path=app["path"],
                name=app.get("_name") if isinstance(app.get("_name"), str) else None,
                version=app.get("version") if isinstance(app.get("version"), str) else None,
                obtained_from=app.get("obtained_from")
                if isinstance(app.get("obtained_from"), str)
                else None,
                signed_by=tuple(s for s in signed if isinstance(s, str))
                if isinstance(signed, list)
                else (),
                arch_kind=app.get("arch_kind") if isinstance(app.get("arch_kind"), str) else None,
                last_modified=app.get("lastModified")
                if isinstance(app.get("lastModified"), str)
                else None,
            )
        )
    return rows


# ── generic keyed snapshot diff ──────────────────────────────────────


@dataclass(frozen=True, slots=True)
class KeyedDiff:
    added: list[str]
    changed: list[str]
    removed: list[str]


def diff_fingerprints(previous: Mapping[str, str], current: Mapping[str, str]) -> KeyedDiff:
    prev_keys, cur_keys = set(previous), set(current)
    return KeyedDiff(
        added=sorted(cur_keys - prev_keys),
        changed=sorted(k for k in prev_keys & cur_keys if previous[k] != current[k]),
        removed=sorted(prev_keys - cur_keys),
    )


def attributes_fingerprint(attributes: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json(dict(attributes)))[:32]


# ── records ──────────────────────────────────────────────────────────


def inventory_item(
    item_type: InventoryItemType,
    key: str,
    attributes: Mapping[str, Any],
    ctx: SourceContext,
    *,
    observed_at: datetime,
    snapshot: str,
    present: bool = True,
) -> InventoryItem:
    return InventoryItem(
        asset_id=ctx.asset_id,
        item_type=item_type,
        item_key=key[:2048],
        attributes=dict(attributes),
        snapshot_id=snapshot,
        observed_at=to_ms(observed_at),
        present=present,
        collector_id=ctx.collector_id,
    )


def listener_event(
    kind: str,
    key: str,
    listener: Listener | None,
    previous: Mapping[str, Any] | None,
    ctx: SourceContext,
    *,
    observed_at: datetime,
    snapshot: str,
    service: ServiceRef | None = None,
    extra_attributes: Mapping[str, Any] | None = None,
) -> SecurityEvent:
    """``network.listener.opened`` (kind=opened) or ``network.listener.closed``.

    ``service`` is set only when the socket owner (pid) was observed and belongs to
    exactly one discovered service (PortAttribution ``confirmed``).
    """
    if listener is not None:
        protocol, address, port = listener.protocol, listener.address, listener.port
        valid = listener.address_valid
        attrs = listener.attributes()
        names = sorted(listener.processes)
        pids = sorted(listener.pids)
        executables = sorted(listener.executables)
        fingerprint = listener.fingerprint()
    else:
        prev = previous or {}
        protocol = str(prev.get("protocol") or key.split(":", 1)[0])
        address = str(prev.get("address") or "")
        port_value = prev.get("port")
        port = port_value if isinstance(port_value, int) else 0
        valid = (
            _normalise_host(address, "ipv6" if ":" in address else "ipv4")[2] if address else False
        )
        names = [p for p in prev.get("processes") or [] if isinstance(p, str)]
        pids = []
        executables = []
        attrs = bounded_attributes(
            {
                "protocol": protocol,
                "bind_address": address,
                "port": port,
                "exposure": exposure_of(address) if valid else "unknown",
                "family": prev.get("family"),
                # Owners last seen while the socket was open (the socket is gone now).
                "processes": names or None,
            }
        )
        fingerprint = str(prev.get("fp") or "")
    network = Network(
        dst_ip=address if valid else None,
        dst_port=port if 0 < port <= 65535 else None,
        protocol="tcp" if protocol == "tcp" else "udp",
    )
    process = None
    if len(names) == 1 or len(pids) == 1:
        process = ProcessInfo(
            name=names[0] if len(names) == 1 else None,
            pid=pids[0] if len(pids) == 1 else None,
            executable=executables[0] if len(executables) == 1 else None,
        )
    event_type = "network.listener.opened" if kind == "opened" else "network.listener.closed"
    if extra_attributes:
        attrs = {**attrs, **{k: v for k, v in extra_attributes.items() if v is not None}}
    who = f" by {', '.join(names[:4])}" if names else ""
    return make_event(
        ctx=ctx,
        event_type=event_type,
        source_type=SOURCE,
        native_key=f"{key}:{kind}:{fingerprint}:{snapshot}",
        event_time=observed_at,
        observed_time=observed_at,
        parser=PARSER,
        message=f"listening socket {kind}: {key}{who}",
        action=f"listener_{kind}",
        outcome=Outcome.SUCCESS,
        resource=Resource(type="listener", name=key),
        network=network,
        process=process,
        attributes=attrs,
        service=service,
    )


def now_utc() -> datetime:  # pragma: no cover - trivial
    return datetime.now(UTC)


# ── local accounts (dscl) ────────────────────────────────────────────

DSCL_USERS_UID = ["/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"]
DSCL_USERS_SHELL = ["/usr/bin/dscl", ".", "-list", "/Users", "UserShell"]
MAX_ACCOUNTS = 2000
_NO_LOGIN_SHELLS = frozenset({"/usr/bin/false", "/bin/false", "/sbin/nologin", "/usr/sbin/nologin"})
_ACCOUNT_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,254}$")


def parse_dscl_list(text: str) -> dict[str, str]:
    """``dscl . -list /Users <Attribute>`` -> {record name: value} (value may contain spaces)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2 or not _ACCOUNT_NAME.match(parts[0]):
            continue
        out[parts[0]] = parts[1].strip()
        if len(out) >= MAX_ACCOUNTS:
            break
    return out


@dataclass(frozen=True, slots=True)
class Account:
    """A local account: short name, UID and login shell only (RealName is never read)."""

    name: str
    uid: int | None
    shell: str | None

    @property
    def system_account(self) -> bool:
        return self.name.startswith("_") or (self.uid is not None and self.uid < 500)

    @property
    def can_login(self) -> bool | None:
        if self.shell is None:
            return None
        return self.shell not in _NO_LOGIN_SHELLS

    def attributes(self) -> dict[str, Any]:
        return bounded_attributes(
            {
                "uid": self.uid,
                "shell": self.shell,
                "system_account": self.system_account,
                "login_shell": self.can_login,
            }
        )

    def summary(self) -> dict[str, Any]:
        return {"uid": self.uid, "shell": self.shell}


def accounts_from(uid_text: str, shell_text: str | None) -> dict[str, Account]:
    uids = parse_dscl_list(uid_text)
    shells = parse_dscl_list(shell_text) if shell_text is not None else {}
    accounts: dict[str, Account] = {}
    for name, uid_value in uids.items():
        uid = int(uid_value) if re.fullmatch(r"-?\d{1,10}", uid_value) else None
        accounts[name] = Account(name=name, uid=uid, shell=shells.get(name))
    return accounts


def account_event(
    kind: str,
    name: str,
    data: Mapping[str, Any],
    ctx: SourceContext,
    *,
    observed_at: datetime,
    snapshot: str,
) -> SecurityEvent:
    """``account.user.created`` (kind=created) or ``account.user.deleted`` (snapshot diff)."""
    uid = data.get("uid") if isinstance(data.get("uid"), int) else None
    shell = data.get("shell") if isinstance(data.get("shell"), str) else None
    account = Account(name=name, uid=uid, shell=shell)
    return make_event(
        ctx=ctx,
        event_type=f"account.user.{kind}",
        source_type=SOURCE,
        native_key=f"account:{name}:{kind}:{uid}:{snapshot}",
        event_time=observed_at,
        observed_time=observed_at,
        parser=PARSER,
        message=f"local account {kind}: {name} (uid {uid if uid is not None else 'unknown'})",
        action=f"account_{kind}",
        outcome=Outcome.SUCCESS,
        actor=Actor(type=ActorType.USER, name=name[:256], id=str(uid) if uid is not None else None),
        resource=Resource(type="local_account", name=name[:256]),
        attributes=account.attributes(),
    )
