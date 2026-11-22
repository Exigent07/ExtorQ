"""Builders for rule-test fixtures (schema 2.0).

Every fixture event carries ``labels["extorq.fixture"]`` saying where it came from:

* ``derived-captured``: a record captured from a real system (the VM, the kind cluster)
  turned into a SecurityEvent by the PRODUCER'S OWN CODE (the Linux collector's journal,
  audit and inventory parsers; the OTLP audit normaliser). Unmodified.
* ``synthetic``: everything else: events built here from the catalog key fields and the
  producers' published attribute names, captured records that were edited (renamed,
  reshaped), and producer code applied to inputs written here (a plist, a workflow file, a
  unified-log line). External addresses come from the RFC 5737 documentation ranges
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); artefact names follow the detection-test
  matrix (``extorq-test-*``).

Nothing here is telemetry and nothing is presented as such. Event ids are deterministic
(``identity.event_id`` of a fixed native key, or the producer's own id), so regenerating a
fixture gives byte-identical files that can be reviewed in a diff.
"""

from __future__ import annotations

import hashlib
import json
import plistlib
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from extorq.contracts.catalog import EVENT_CATALOG
from extorq.contracts.event import SecurityEvent
from extorq.contracts.identity import event_id

REPO = Path(__file__).resolve().parents[2]
SYNTHETIC_LABELS = {"extorq.fixture": "synthetic"}
DERIVED_LABELS = {"extorq.fixture": "derived-captured"}
BASE = datetime(2026, 11, 20, 10, 0, 0, tzinfo=UTC)
S = timedelta(seconds=1)
M = timedelta(minutes=1)
LINUX = ("linux:lab-vm-01", "linux_host")
K8S = ("k8s:extorq-lab", "kubernetes_cluster")
MACOS = ("macos:workstation-01", "macos_host")
GITHUB_REPO = ("github:example-org/extorq-lab", "github_repository")
METHOD_BY_SOURCE = {
    "linux.journald": "ssh_pull",
    "linux.auditd": "ssh_pull",
    "linux.nginx": "ssh_pull",
    "linux.app": "ssh_pull",
    "linux.inventory": "ssh_pull",
    "k8s.audit": "otel_filelog",
    "k8s.container_log": "otel_filelog",
    "k8s.api_inventory": "api_poll",
    "github.api": "api_poll",
    "macos.launchd": "native_command",
    "macos.inventory": "native_command",
    "macos.unified_log": "native_command",
}


def labelled(events: Iterable[SecurityEvent], labels: dict[str, str]) -> list[SecurityEvent]:
    """Producer events with the fixture provenance label added (producer labels kept)."""
    return [e.model_copy(update={"labels": {**e.labels, **labels}}) for e in events]


class FixtureWriter:
    """Accumulates the events of one fixture file with deterministic ids."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.events: list[SecurityEvent] = []
        self._seq = 0

    def add(
        self,
        event_type: str,
        t: datetime,
        *,
        asset: tuple[str, str] = LINUX,
        source_type: str | None = None,
        native_key: str | None = None,
        **fields: Any,
    ) -> SecurityEvent:
        """A SYNTHETIC event of ``event_type`` at ``t`` with the given contract fields."""
        spec = EVENT_CATALOG[event_type]
        src = source_type or sorted(s.value for s in spec.sources)[0]
        self._seq += 1
        key = native_key or f"fixture:{self.name}:{self._seq:05d}"
        data: dict[str, Any] = {
            "event_id": event_id(src, asset[0], key),
            "event_type": event_type,
            "category": spec.category.value,
            "asset_id": asset[0],
            "asset_type": asset[1],
            "source": {
                "source_type": src,
                "collector_id": "fixture-synthetic",
                "collector_version": "0.0.0",
                "collection_method": METHOD_BY_SOURCE.get(src, "api_poll"),
                "source_native_id": key,
            },
            "event_time": t,
            "observed_time": t + timedelta(seconds=2),
            "labels": dict(SYNTHETIC_LABELS),
            "provenance": {"parser": "fixture-synthetic", "parser_version": "0"},
        }
        data.update(fields)
        event = SecurityEvent.model_validate(data)
        self.events.append(event)
        return event

    def extend(self, events: Iterable[SecurityEvent]) -> None:
        self.events.extend(events)

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            json.dumps(e.model_dump(mode="json", exclude_none=True), sort_keys=True)
            for e in sorted(self.events, key=lambda e: (e.event_time, e.event_id))
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── Linux: sshd (journald) ───────────────────────────────────────────


def _ssh_common(user: str | None, ip: str, port: int, pid: int) -> dict[str, Any]:
    common: dict[str, Any] = {
        "outcome": "failure",
        "network": {"src_ip": ip, "src_port": port, "protocol": "tcp", "direction": "inbound"},
        "process": {"pid": pid, "name": "sshd"},
    }
    if user is not None:
        common["actor"] = {"type": "user", "name": user}
    return common


def ssh_failed_connection(
    fx: FixtureWriter,
    t: datetime,
    ip: str,
    port: int,
    user: str,
    *,
    invalid: bool = True,
    attempts: int = 1,
    pid: int = 4000,
) -> None:
    """One sshd connection that fails password authentication (OpenSSH 9.6 line shapes)."""
    common = _ssh_common(user, ip, port, pid)
    offset = 0.0
    if invalid:
        line = f"Invalid user {user} from {ip} port {port}"
        fx.add("auth.ssh.invalid_user", t, action="ssh_login", message=line, raw=line, **common)
        offset += 0.4
    who = f"invalid user {user}" if invalid else user
    for _ in range(attempts):
        line = f"Failed password for {who} from {ip} port {port} ssh2"
        fx.add(
            "auth.ssh.login_failed",
            t + timedelta(seconds=offset),
            action="ssh_login",
            message=line,
            raw=line,
            attributes={"auth_method": "password", "invalid_user": invalid},
            **common,
        )
        offset += 2.1
    if attempts >= 6:
        line = (
            f"error: maximum authentication attempts exceeded for {who} from {ip} "
            f"port {port} ssh2 [preauth]"
        )
        fx.add(
            "auth.ssh.max_auth_exceeded",
            t + timedelta(seconds=offset),
            action="ssh_login",
            message=line,
            raw=line,
            **common,
        )
        offset += 0.1
    kind = "invalid" if invalid else "authenticating"
    line = f"Connection closed by {kind} user {user} {ip} port {port} [preauth]"
    fx.add(
        "auth.ssh.preauth_closed",
        t + timedelta(seconds=offset + 0.3),
        action="ssh_login",
        message=line,
        raw=line,
        attributes={"invalid_user": invalid},
        **common,
    )


def ssh_key_rejected_connection(
    fx: FixtureWriter, t: datetime, ip: str, port: int, user: str, *, exists: bool, pid: int
) -> None:
    """A client offering a throwaway key that the server rejects (captured VM line shapes).

    Existing account: ``Failed publickey for <user>`` then ``Connection closed by
    authenticating user``; unknown account: ``Invalid user`` then ``Connection closed by
    invalid user`` (as in tests/fixtures/linux/journal/sshd.ndjson).
    """
    common = _ssh_common(user, ip, port, pid)
    if exists:
        line = f"Failed publickey for {user} from {ip} port {port} ssh2: ED25519 SHA256:fixture"
        fx.add(
            "auth.ssh.login_failed",
            t,
            action="ssh_login",
            message=line,
            raw=line,
            attributes={"auth_method": "publickey", "invalid_user": False},
            **common,
        )
    else:
        line = f"Invalid user {user} from {ip} port {port}"
        fx.add("auth.ssh.invalid_user", t, action="ssh_login", message=line, raw=line, **common)
    kind = "authenticating" if exists else "invalid"
    line = f"Connection closed by {kind} user {user} {ip} port {port} [preauth]"
    fx.add(
        "auth.ssh.preauth_closed",
        t + timedelta(milliseconds=11),
        action="ssh_login",
        message=line,
        raw=line,
        attributes={"invalid_user": not exists},
        **common,
    )


def ssh_success(
    fx: FixtureWriter, t: datetime, ip: str, port: int, user: str, *, pid: int = 4100
) -> None:
    line = f"Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 SHA256:fixture"
    fx.add(
        "auth.ssh.login_succeeded",
        t,
        action="ssh_login",
        outcome="success",
        actor={"type": "user", "name": user},
        network={"src_ip": ip, "src_port": port, "protocol": "tcp", "direction": "inbound"},
        process={"pid": pid, "name": "sshd"},
        message=line,
        raw=line,
        attributes={"auth_method": "publickey"},
    )


# ── Linux / Kubernetes: web access and application authentication ────

PROBE_ROUTES = (
    "/.env",
    "/.git/config",
    "/wp-login.php",
    "/phpmyadmin/index.php",
    "/server-status",
    "/actuator/health",
    "/cgi-bin/test.cgi",
    "/backup.zip",
    "/.aws/credentials",
    "/admin.php",
    "/xmlrpc.php",
    "/config.json",
)


def nginx_request(
    fx: FixtureWriter,
    t: datetime,
    ip: str,
    route: str,
    status: int,
    *,
    method: str = "GET",
    user_agent: str = "fixture-synthetic-scanner/1.0",
) -> None:
    """One nginx JSON access line as the Linux collector's nginx parser maps it."""
    fx.add(
        "http.request",
        t,
        source_type="linux.nginx",
        action="http.request",
        outcome="failure" if status >= 400 else "success",
        network={"src_ip": ip, "protocol": "tcp", "direction": "inbound"},
        http={
            "method": method,
            "route": route,
            "status_code": status,
            "request_id": hashlib.sha256(f"{fx.name}:{len(fx.events)}".encode()).hexdigest()[:32],
            "user_agent": user_agent,
        },
        message=f"{method} {route} -> {status}",
    )


def http_probe(
    fx: FixtureWriter,
    t: datetime,
    ip: str,
    *,
    routes: tuple[str, ...] = PROBE_ROUTES,
    spacing_s: float = 4.0,
    status: int = 404,
) -> None:
    """A scanner requesting probe-like paths, each answered with a client error."""
    for i, route in enumerate(routes):
        nginx_request(fx, t + timedelta(seconds=i * spacing_s), ip, route, status)


WEB_APP_POD = {
    "cluster": "extorq-lab",
    "namespace": "extorq-apps",
    "pod_name": "lab-portal-7c9d8f6b5-x2x4q",
    "pod_uid": "0f6e2c1a-9a8b-4c3d-8e7f-112233445566",
    "container_name": "lab-portal",
    "workload_kind": "Deployment",
    "workload_name": "lab-portal",
}


def app_login(
    fx: FixtureWriter,
    t: datetime,
    user: str,
    ip: str,
    *,
    k8s: bool = False,
    success: bool = False,
    reason: str = "invalid_password",
) -> None:
    """A structured login event of the web application (VM: linux.app; cluster: container log)."""
    fields: dict[str, object] = {"kubernetes": dict(WEB_APP_POD)} if k8s else {}
    fx.add(
        "app.auth.login_succeeded" if success else "app.auth.login_failed",
        t,
        asset=K8S if k8s else LINUX,
        source_type="k8s.container_log" if k8s else "linux.app",
        action="login",
        outcome="success" if success else "failure",
        actor={"type": "user", "name": user},
        network={"src_ip": ip},
        http={"method": "POST", "route": "/login", "status_code": 302 if success else 401},
        message=f"login {'succeeded' if success else 'failed'} for {user}",
        attributes={"service": "lab-portal", "request_id_source": "generated"}
        | ({} if success else {"reason": reason}),
        **fields,
    )


# ── Linux: systemd, auditd, inventory (synthetic shapes) ─────────────


def unit_event(
    fx: FixtureWriter,
    event_type: str,
    t: datetime,
    path: str,
    sha: str,
    *,
    prev: str | None = None,
    baseline: bool = False,
) -> None:
    """A systemd unit inventory diff with the Linux collector's attribute names."""
    name = path.rsplit("/", 1)[-1]
    attrs: dict[str, object] = {
        "sha256": sha,
        "exec_start": "/bin/sh -c 'sleep infinity'",
        "vendor_unit": False,
    }
    if prev:
        attrs["previous_sha256"] = prev
    if baseline:
        attrs["baseline"] = True
    fx.add(
        event_type,
        t,
        asset=LINUX,
        action=event_type.rsplit(".", 1)[-1],
        outcome="success",
        resource={"type": "systemd_unit", "name": name, "path": path},
        message=f"systemd unit {name} {event_type.rsplit('_', 1)[-1]} (snapshot diff)",
        attributes=attrs,
    )


def unit_enabled(
    fx: FixtureWriter, t: datetime, unit: str, wanted_by: str = "multi-user.target"
) -> None:
    fx.add(
        "persistence.systemd.unit_enabled",
        t,
        asset=LINUX,
        action="unit_enabled",
        outcome="success",
        resource={"type": "systemd_unit", "name": unit},
        message=f"systemd unit {unit} enabled ({wanted_by})",
        attributes={"wanted_by": wanted_by},
    )


#: Name type of the primary PATH record as the Linux auditd parser reports it (live values
#: on the VM: openat CREATE/NORMAL, unlinkat DELETE, fchmodat/fchownat/fsetxattr NORMAL).
_NAMETYPE_BY_SYSCALL = {"unlinkat": "DELETE", "unlink": "DELETE", "rmdir": "DELETE"}


def audit_watch(
    fx: FixtureWriter,
    t: datetime,
    path: str | None,
    key: str,
    serial: int,
    *,
    syscall: str = "openat",
    exe: str = "/usr/bin/tee",
    nametype: str | None = None,
    success: bool = True,
    paths: list[str] | None = None,
) -> None:
    """One auditd watch hit with the attribute shape of the Linux auditd parser.

    ``path`` is the primary (first non-PARENT) PATH item, which the parser maps to
    ``resource.path``; ``paths`` lists every PATH item as ``NAMETYPE:/abs/path``.
    """
    nt = nametype or _NAMETYPE_BY_SYSCALL.get(
        syscall, "CREATE" if syscall in ("openat", "open", "creat") else "NORMAL"
    )
    if paths is None:
        if path is None:
            paths = [f"{nt}:?"]
        elif nt == "NORMAL":
            paths = [f"NORMAL:{path}"]
        else:
            paths = [f"PARENT:{path.rsplit('/', 1)[0]}/", f"{nt}:{path}"]
    fields: dict[str, object] = {}
    if path is not None:
        fields["resource"] = {"type": "file", "path": path, "name": path.rsplit("/", 1)[-1]}
    fx.add(
        "file.audit.watch",
        t,
        asset=LINUX,
        action=f"audit.{syscall}",
        outcome="success" if success else "failure",
        process={"executable": exe, "name": exe.rsplit("/", 1)[-1], "pid": 7021},
        actor={"type": "user", "name": "extorq-admin", "id": "1000"},
        message=f"auditd {key}: {syscall} {path or '?'} by 1000 via {exe.rsplit('/', 1)[-1]}",
        attributes={
            "audit_key": key,
            "syscall": syscall,
            "audit_serial": serial,
            "success": success,
            "exit_code": "0" if success else "-13",
            "nametype": nt,
            "paths": paths,
            "arch": "aarch64",
            "auid": 1000,
            "euid": 0 if success else 1000,
            "cwd": "/home/extorq-admin",
        },
        **fields,
    )


def cron_changed(
    fx: FixtureWriter,
    t: datetime,
    path: str,
    change: str,
    sha: str | None,
    *,
    prev: str | None = None,
    mode: str = "0644",
    baseline: bool = False,
) -> None:
    """A cron inventory diff with the Linux collector's attribute names (cron_events)."""
    attrs: dict[str, object] = {
        "change": change,
        "readable": True,
        "file_mode": mode,
        "owner_uid": 0,
    }
    if sha:
        attrs["sha256"] = sha
    if prev:
        attrs["previous_sha256"] = prev
    if baseline:
        attrs["baseline"] = True
    fx.add(
        "persistence.cron.changed",
        t,
        asset=LINUX,
        action=f"cron.{change}",
        outcome="success",
        resource={"type": "cron", "name": path.rsplit("/", 1)[-1], "path": path},
        message=f"cron configuration {change}: {path}",
        attributes=attrs,
    )


def account_created(
    fx: FixtureWriter,
    t: datetime,
    name: str,
    uid: int,
    *,
    login_shell: str,
    groups: list[str],
    home: str | None = None,
) -> None:
    """An account inventory diff with the Linux collector's attribute names (user_events)."""
    fx.add(
        "account.user.created",
        t,
        asset=LINUX,
        action="account.created",
        outcome="success",
        actor={"type": "user", "name": name, "id": str(uid)},
        message=f"local account created: {name} (uid {uid}, shell {login_shell})",
        attributes={
            "uid": uid,
            "gid": uid,
            "shell": login_shell,
            "home": home or f"/home/{name}",
            "groups": groups,
            "interactive_shell": login_shell not in ("/usr/sbin/nologin", "/bin/false"),
        },
    )


# ── Linux: the collector's own parsers on captured VM output ─────────

LINUX_FIXTURES = REPO / "tests" / "fixtures" / "linux"


def _linux_parse_ctx() -> Any:
    from extorq_collectors.linux.common import ParseContext

    return ParseContext()


def load_linux_inventory(name: str) -> dict[str, Any]:
    """A captured dispatcher ``inventory`` document (tests/fixtures/linux/inventory)."""
    loaded: dict[str, Any] = json.loads(
        (LINUX_FIXTURES / "inventory" / name).read_text(encoding="utf-8")
    )
    return loaded


def linux_inventory_events(
    category: str, before: dict[str, Any], after: dict[str, Any]
) -> list[SecurityEvent]:
    """Snapshot diff ``before`` -> ``after`` of one category, mapped by the collector's code.

    The event time is the ``after`` document's ``collected_at`` (the VM's clock), exactly
    as the collector stamps inventory events.
    """
    from extorq_collectors.linux import inventory as inv
    from extorq_collectors.sdk.base import SnapshotDiff

    extract = inv.CATEGORIES[category][0]
    old, new = extract(before), extract(after)
    added = {k: v for k, v in new.items() if k not in old}
    removed = {k: v for k, v in old.items() if k not in new}
    changed = {k: v for k, v in new.items() if k in old and old[k] != v}
    previous = {**{k: old[k] for k in changed}, **removed}
    diff = SnapshotDiff(added, changed, removed, previous)
    collected = datetime.fromisoformat(str(after["collected_at"]).replace("Z", "+00:00"))
    dctx = inv.DiffContext(parse=_linux_parse_ctx(), event_time=collected)
    mappers: dict[str, Callable[..., list[SecurityEvent]]] = {
        "units": inv.unit_events,
        "enablement": inv.enablement_events,
        "users": inv.user_events,
        "cron": inv.cron_events,
    }
    return mappers[category](diff, dctx)


def linux_audit_events(name: str, *, text: bytes | None = None) -> list[SecurityEvent]:
    """auditd records parsed by the collector's auditd parser (captured log or ``text``)."""
    from extorq_collectors.linux.auditd import parse_audit_chunk

    data = text if text is not None else (LINUX_FIXTURES / "audit" / name).read_bytes()
    return list(parse_audit_chunk(data, 0, _linux_parse_ctx()).events)


def linux_journal_events(
    name: str, keep: Callable[[SecurityEvent], bool] = lambda _e: True
) -> list[SecurityEvent]:
    """Captured journald entries parsed by the collector's journal parser."""
    from extorq_collectors.linux.journal import entry_from_json, parse_entry

    events: list[SecurityEvent] = []
    for line in (LINUX_FIXTURES / "journal" / name).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = entry_from_json(json.loads(line))
        if entry is not None:
            events.extend(e for e in parse_entry(entry, _linux_parse_ctx()) if keep(e))
    return events


# ── Kubernetes: the OTLP audit normaliser on captured audit records ──

AUDIT_FIXTURES = REPO / "tests" / "fixtures" / "kubernetes" / "audit"


def load_audit_record(filename: str) -> dict[str, Any]:
    record: dict[str, Any] = json.loads((AUDIT_FIXTURES / filename).read_text(encoding="utf-8"))
    return record


def k8s_audit_events(
    filename: str,
    *,
    received_at: datetime | None = None,
    mutate: Callable[[dict[str, Any]], None] | None = None,
) -> list[SecurityEvent]:
    """Normalise one captured kube-apiserver audit record with the real OTLP normaliser.

    Unmodified records are labelled ``derived-captured``; records reshaped by ``mutate``
    are labelled ``synthetic``.
    """
    from extorq.ingest.otlp_k8s import normalize_otlp_logs

    record = load_audit_record(filename)
    labels = DERIVED_LABELS
    if mutate is not None:
        mutate(record)
        labels = SYNTHETIC_LABELS
    when = received_at or datetime.fromisoformat(record["stageTimestamp"].replace("Z", "+00:00"))
    attrs = [
        {"key": "extorq.source", "value": {"stringValue": "audit"}},
        {"key": "k8s.cluster.name", "value": {"stringValue": "extorq-lab"}},
        {"key": "k8s.node.name", "value": {"stringValue": "extorq-lab-control-plane"}},
        {"key": "extorq.collector.version", "value": {"stringValue": "otelcol-contrib/0.165.0"}},
    ]
    log_record = {
        "observedTimeUnixNano": str(int(when.timestamp() * 1e9)),
        "body": {"stringValue": json.dumps(record)},
        "attributes": [
            {"key": "log.file.name", "value": {"stringValue": "kube-apiserver-audit.log"}}
        ],
    }
    payload = {
        "resourceLogs": [
            {
                "resource": {"attributes": attrs},
                "scopeLogs": [{"scope": {}, "logRecords": [log_record]}],
            }
        ]
    }
    events, failures = normalize_otlp_logs(
        payload, producer_id="k8s-otel-extorq-lab", received_at=when
    )
    if failures:
        raise ValueError(f"{filename}: normaliser rejected the record: {failures}")
    return labelled(events, labels)


def reshape_audit(
    *,
    audit_id_key: str,
    at: datetime | None = None,
    **object_ref: str | None,
) -> Callable[[dict[str, Any]], None]:
    """A ``mutate`` callback: new audit id (uuid5 of a key), optional time and objectRef edits.

    ``object_ref`` values of None remove the key (e.g. ``namespace=None`` for a
    cluster-wide request).
    """
    import uuid

    def mutate(record: dict[str, Any]) -> None:
        record["auditID"] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"extorq-fixture:{audit_id_key}"))
        ref = record.setdefault("objectRef", {})
        for key, value in object_ref.items():
            if value is None:
                ref.pop(key, None)
            else:
                ref[key] = value
        if at is not None:
            record["requestReceivedTimestamp"] = at.isoformat().replace("+00:00", "Z")
            stage = at + timedelta(milliseconds=3)
            record["stageTimestamp"] = stage.isoformat().replace("+00:00", "Z")

    return mutate


CAPTURES = Path(__file__).resolve().parent / "captures"


def captured_events(filename: str) -> list[SecurityEvent]:
    """Genuine normalised events exported from the live store (see captures/README.md)."""
    lines = (CAPTURES / filename).read_text(encoding="utf-8").splitlines()
    return [SecurityEvent.model_validate_json(line) for line in lines if line.strip()]


def k8s_risk_flags(filename: str) -> list[str]:
    """Risk flags the shared audit/inventory vocabulary assigns to a captured request object."""
    from extorq.ingest.otlp_k8s import risk_flags_for_summary, summarize_k8s_object

    record = load_audit_record(filename)
    resource = record.get("objectRef", {}).get("resource")
    return risk_flags_for_summary(
        summarize_k8s_object(record.get("requestObject"), resource=resource)
    )


def k8s_state(
    fx: FixtureWriter,
    t: datetime,
    kind: str,
    name: str,
    namespace: str | None,
    *,
    flags: list[str],
    baseline: bool = False,
    summary: str | None = None,
) -> None:
    """The Kubernetes inventory collector's view of an object (k8s.resource.created)."""
    attrs: dict[str, object] = {"risk_flags": flags}
    if baseline:
        attrs["baseline"] = True
    if summary is not None:
        attrs["object_summary"] = summary
    fx.add(
        "k8s.resource.created",
        t,
        asset=K8S,
        action="created",
        outcome="success",
        resource={"type": kind, "name": name, "namespace": namespace},
        kubernetes={"cluster": "extorq-lab", "namespace": namespace},
        message=f"{kind} {name} observed for the first time",
        attributes=attrs,
    )


# ── GitHub: the collector's workflow analyser ────────────────────────


def workflow_delta_attributes(
    path: str, before: str | None, after: str | None, *, repo_default: str | None
) -> dict[str, Any]:
    """Attributes exactly as the GitHub collector computes them for github.workflow.modified."""
    from extorq_collectors.github.workflow import analyse_workflow, compare_workflows

    before_a = analyse_workflow(path, before) if before is not None else None
    after_a = analyse_workflow(path, after) if after is not None else None
    change = "added" if before is None else ("removed" if after is None else "modified")
    delta = compare_workflows(
        path,
        before_a,
        after_a,
        repo_default=repo_default,  # type: ignore[arg-type]
        change_type=change,  # type: ignore[arg-type]
    )
    return {k: v for k, v in delta.to_attributes().items() if v is not None}


def _github(sha: str, *, path: str | None = None, actor: str = "octo-dev") -> dict[str, Any]:
    info: dict[str, Any] = {
        "repository": "example-org/extorq-lab",
        "ref": "refs/heads/main",
        "commit_sha": sha,
        "actor_login": actor,
    }
    if path is not None:
        info["workflow_path"] = path
        info["workflow_name"] = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    return info


def workflow_event(
    fx: FixtureWriter,
    t: datetime,
    sha: str,
    path: str,
    before: str | None,
    after: str | None,
    *,
    repo_default: str | None = "read",
    actor: str = "octo-dev",
) -> None:
    """github.workflow.modified with the analyser's attributes for ``before`` -> ``after``."""
    fx.add(
        "github.workflow.modified",
        t,
        asset=GITHUB_REPO,
        native_key=f"{sha}:{path}",
        action="workflow_modified",
        outcome="success",
        actor={"type": "github_user", "name": actor},
        resource={"type": "github_workflow", "name": path.rsplit("/", 1)[-1], "path": path},
        github=_github(sha, path=path, actor=actor),
        message=f"Workflow {path} modified (synthetic fixture)",
        attributes=workflow_delta_attributes(path, before, after, repo_default=repo_default),
    )


def commit_observed(fx: FixtureWriter, t: datetime, sha: str, files: list[str]) -> None:
    fx.add(
        "github.commit.observed",
        t,
        asset=GITHUB_REPO,
        native_key=f"commit:{sha}",
        action="commit",
        outcome="success",
        actor={"type": "github_user", "name": "octo-dev"},
        github=_github(sha),
        message=f"commit {sha[:12]} observed (synthetic fixture)",
        attributes={"files_changed": len(files), "workflow_files_changed": 0},
    )


def secret_exposed(
    fx: FixtureWriter,
    t: datetime,
    sha: str,
    path: str,
    line: int,
    pattern: str,
    redacted_match: str,
) -> None:
    """github.secret.exposed: pattern name, location and a redacted match, never the value."""
    fx.add(
        "github.secret.exposed",
        t,
        asset=GITHUB_REPO,
        native_key=f"secret:{sha}:{path}:{line}:{pattern}",
        action="secret_exposed",
        outcome="success",
        actor={"type": "github_user", "name": "octo-dev"},
        resource={"type": "file", "name": path.rsplit("/", 1)[-1], "path": path},
        github=_github(sha),
        message=f"credential-shaped string ({pattern}) added to {path}:{line}",
        attributes={"pattern": pattern, "line": line, "redacted_match": redacted_match},
    )


# ── macOS: the collector's own code on inputs written here ───────────


def _macos_ctx() -> Any:
    from extorq_collectors.macos.common import SourceContext

    return SourceContext(collector_id="macos-workstation-01", asset_id=MACOS[0])


def launchd_event(
    kind: str,
    path: str,
    plist: dict[str, Any] | bytes,
    at: datetime,
    *,
    scope: str = "user",
    item_kind: str = "agent",
    allowlisted: bool = False,
    previous_sha: str | None = None,
) -> SecurityEvent:
    """A launchd diff event built by the macOS collector's launchd code from a plist.

    ``kind`` is created / modified / deleted. ``plist`` is a plist dictionary (serialised
    as XML) or raw bytes (e.g. unparseable content). SYNTHETIC: the plist is written here.
    """
    from extorq_collectors.macos import launchd as ld

    data = plistlib.dumps(plist) if isinstance(plist, dict) else plist
    item = ld.LaunchItem(path=path, scope=scope, kind=item_kind)
    item.sha256 = hashlib.sha256(data).hexdigest()
    item.size = len(data)
    item.mode = "0644"
    item.owner_uid = 501
    item.world_writable = False
    ld.parse_plist_bytes(item, data)
    item.allowlisted = allowlisted
    previous = None
    if kind in ("modified", "deleted"):
        previous = {
            "fp": previous_sha or "0" * 64,
            "label": item.label,
            "scope": scope,
            "kind": item_kind,
            "program": item.program,
        }
    change = ld.Change(kind, path, None if kind == "deleted" else item, previous)
    event = ld.change_to_event(
        change, _macos_ctx(), observed_at=at, snapshot=f"fixture-{at:%H%M%S}"
    )
    return labelled([event], SYNTHETIC_LABELS)[0]


#: Wildcard bind addresses as the macOS collector reports them (fixture data, not a bind).
ANY_IPV4 = "0.0.0.0"  # noqa: S104 - an address value in a test record
ANY_IPV6 = "::"


def macos_listener(
    fx: FixtureWriter,
    t: datetime,
    kind: str,
    address: str,
    port: int,
    *,
    protocol: str = "tcp",
    executable: str | None,
    pid: int | None = 4242,
) -> None:
    """network.listener.opened/closed with the macOS collector's key fields and attributes."""
    name = executable.rsplit("/", 1)[-1] if executable else None
    process: dict[str, Any] | None = None
    if executable or pid is not None:
        process = {"name": name, "pid": pid, "executable": executable}
        process = {k: v for k, v in process.items() if v is not None}
    exposure = "loopback" if address in ("127.0.0.1", "::1") else "all_interfaces"
    attrs: dict[str, Any] = {
        "protocol": protocol,
        "bind_address": address,
        "port": port,
        "exposure": exposure,
        "family": "ipv6" if ":" in address else "ipv4",
    }
    if executable:
        attrs.update({"processes": [name], "executables": [executable], "pids": [pid]})
    fields: dict[str, Any] = {"process": process} if process else {}
    fx.add(
        f"network.listener.{kind}",
        t,
        asset=MACOS,
        source_type="macos.inventory",
        action=f"listener_{kind}",
        outcome="success",
        resource={"type": "listener", "name": f"{protocol}:{address}:{port}"},
        network={"dst_ip": address, "dst_port": port, "protocol": protocol},
        message=f"listening socket {kind}: {protocol}:{address}:{port}",
        attributes={k: v for k, v in attrs.items() if v is not None},
        **fields,
    )


def unified_log_events(
    records: list[dict[str, Any]], *, accounts: dict[str, str]
) -> list[SecurityEvent]:
    """Unified-log ndjson records classified and normalised by the macOS collector's code.

    ``accounts`` maps an opendirectoryd GeneratedUID to the account name, as the collector's
    dscl lookup would. SYNTHETIC: the records are written here in the shape of the
    collector's documented sudo records and the captured opendirectoryd record.
    """
    from extorq_collectors.macos import unified_log as ul

    # log show terminates every record with a newline (a last line without one is treated
    # as output cut at the byte limit and dropped).
    data = "".join(json.dumps(r) + "\n" for r in records).encode("utf-8")
    parsed, _ = ul.parse_ndjson(data, max_records=1000)
    events = []
    for record in parsed:
        classified = ul.classify(record)
        events.append(
            ul.to_event(
                record,
                classified,
                _macos_ctx(),
                observed_time=record.timestamp + timedelta(seconds=30),
                resolve_actor=accounts.get,
            )
        )
    return labelled(events, SYNTHETIC_LABELS)


def unified_log_record(
    t: datetime,
    process_path: str,
    message: str,
    *,
    pid: int,
    subsystem: str = "",
    category: str = "",
    message_type: str = "Error",
) -> dict[str, Any]:
    """One ``log show --style ndjson`` record (shape of the collector's test captures)."""
    return {
        "timezoneName": "",
        "eventType": "logEvent",
        "source": None,
        "formatString": "%{public}s",
        "activityIdentifier": 0,
        "parentActivityIdentifier": 0,
        "bootUUID": "00000000-0000-4000-8000-00000000B007",
        "userID": 0,
        "timestamp": t.strftime("%Y-%m-%d %H:%M:%S.%f+0000"),
        "processImagePath": process_path,
        "senderImagePath": process_path,
        "processID": pid,
        "subsystem": subsystem,
        "category": category,
        "messageType": message_type,
        "eventMessage": message,
        # Identity fields of the record (the collector's native key): unique per time+pid.
        "machTimestamp": int(t.timestamp() * 1_000_000),
        "threadID": 41000 + pid,
        "traceID": int(t.timestamp() * 1000),
    }


def software_installed(
    fx: FixtureWriter,
    t: datetime,
    path: str,
    *,
    bundle_id: str | None,
    version: str,
    signed: bool | str,
    signature_type: str | None,
    team_id: str | None = None,
    kind: str = "installed",
) -> None:
    """software.installed/removed with the macOS software source's attribute names."""
    name = path.rstrip("/").rsplit("/", 1)[-1].removesuffix(".app")
    attrs: dict[str, Any] = {
        "bundle_id": bundle_id,
        "version": version,
        "scope": "user" if path.startswith("/Users/") else "system",
        "app_dir": path.rsplit("/", 1)[0],
    }
    if kind == "installed":
        attrs.update(
            {
                "signed": signed,
                "signature_valid": signed is True,
                "signature_type": signature_type,
                "signature_team_id": team_id,
                "signature_error": "code object is not signed at all" if signed is False else None,
            }
        )
    fx.add(
        f"software.{kind}",
        t,
        asset=MACOS,
        source_type="macos.inventory",
        action=f"software_{kind}",
        outcome="success",
        resource={"type": "application_bundle", "name": name, "path": path},
        message=f"application {kind}: {path}",
        attributes={k: v for k, v in attrs.items() if v is not None},
    )
