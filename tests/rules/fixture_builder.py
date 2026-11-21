"""Builders for SYNTHETIC rule-test fixtures.

Everything produced here is synthetic test data, never telemetry:

* every event carries ``labels: {"extorq.fixture": "synthetic"}``
* ``source.collector_id`` and ``provenance.parser`` are ``fixture-synthetic``
* external addresses come from the RFC 5737 documentation ranges
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)

Field choices follow the event catalog key_fields and the producers' published
mappings (B1 lab-portal/sshd parsing, B2 kube-apiserver audit fixtures captured
from the real kind cluster, C1 workflow analysis), so a rule that passes these
fixtures relies only on fields producers genuinely populate. Event ids are
derived with ``identity.event_id`` from a deterministic synthetic native key.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from extorq.contracts.catalog import EVENT_CATALOG
from extorq.contracts.event import SecurityEvent
from extorq.contracts.identity import event_id

SYNTHETIC_LABELS = {"extorq.fixture": "synthetic"}
BASE = datetime(2026, 11, 20, 10, 0, 0, tzinfo=UTC)
LINUX = ("linux:lab-vm-01", "linux_host")
K8S = ("k8s:extorq-lab", "kubernetes_cluster")
MACOS = ("macos:workstation-01", "macos_host")
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
}


class FixtureWriter:
    """Accumulates events for one fixture file with deterministic ids."""

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

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            json.dumps(e.model_dump(mode="json", exclude_none=True), sort_keys=True)
            for e in sorted(self.events, key=lambda e: (e.event_time, e.event_id))
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── Linux sshd (journald) ────────────────────────────────────────────


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
    simulation: dict[str, str] | None = None,
) -> None:
    """One sshd connection that fails authentication (OpenSSH 9.6 line shapes)."""
    common: dict[str, Any] = {
        "outcome": "failure",
        "actor": {"type": "user", "name": user},
        "network": {"src_ip": ip, "src_port": port, "protocol": "tcp", "direction": "inbound"},
        "process": {"pid": pid, "name": "sshd"},
    }
    if simulation:
        common["simulation"] = simulation
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
    simulation: dict[str, str] | None = None,
) -> None:
    """One nginx JSON access line as B1's linux-nginx-json parser maps it (http.request)."""
    fields: dict[str, Any] = {"simulation": simulation} if simulation else {}
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
            "user_agent": "fixture-synthetic-scanner/1.0",
        },
        message=f"{method} {route} -> {status}",
        **fields,
    )


def http_probe(
    fx: FixtureWriter,
    t: datetime,
    ip: str,
    *,
    routes: tuple[str, ...] = PROBE_ROUTES,
    spacing_s: float = 4.0,
    status: int = 404,
    simulation: dict[str, str] | None = None,
) -> None:
    """A scanner requesting probe-like paths, each answered with a client error."""
    for i, route in enumerate(routes):
        nginx_request(
            fx, t + timedelta(seconds=i * spacing_s), ip, route, status, simulation=simulation
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


# ── Kubernetes audit: derived from REAL records captured by B2 ───────

REPO = Path(__file__).resolve().parents[2]
AUDIT_FIXTURES = REPO / "tests" / "fixtures" / "kubernetes" / "audit"
DERIVED_LABELS = {"extorq.fixture": "derived-captured"}


def k8s_audit_events(
    filename: str, *, rename: str | None = None, received_at: datetime | None = None
) -> list[SecurityEvent]:
    """Normalise one captured kube-apiserver audit record with B2's real normaliser.

    Unmodified records are labelled ``derived-captured``; records edited here (e.g. the
    object renamed to carry a simulation marker) are labelled ``synthetic``.
    """
    from extorq.ingest.otlp_k8s import normalize_otlp_logs

    record = json.loads((AUDIT_FIXTURES / filename).read_text(encoding="utf-8"))
    labels = DERIVED_LABELS
    if rename is not None:
        old = record["objectRef"]["name"]
        record["objectRef"]["name"] = rename
        body = json.dumps(record).replace(f'"{old}"', f'"{rename}"')
        record = json.loads(body)
        labels = SYNTHETIC_LABELS
    when = received_at or datetime.fromisoformat(record["stageTimestamp"].replace("Z", "+00:00"))
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "extorq.source", "value": {"stringValue": "audit"}},
                        {"key": "k8s.cluster.name", "value": {"stringValue": "extorq-lab"}},
                        {
                            "key": "k8s.node.name",
                            "value": {"stringValue": "extorq-lab-control-plane"},
                        },
                        {
                            "key": "extorq.collector.version",
                            "value": {"stringValue": "otelcol-contrib/0.165.0"},
                        },
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {},
                        "logRecords": [
                            {
                                "observedTimeUnixNano": str(int(when.timestamp() * 1e9)),
                                "body": {"stringValue": json.dumps(record)},
                                "attributes": [
                                    {
                                        "key": "log.file.name",
                                        "value": {"stringValue": "kube-apiserver-audit.log"},
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    events, failures = normalize_otlp_logs(
        payload, producer_id="k8s-otel-extorq-lab", received_at=when
    )
    if failures:
        raise ValueError(f"{filename}: normaliser rejected the record: {failures}")
    return [e.model_copy(update={"labels": dict(labels)}) for e in events]


def k8s_risk_flags(filename: str) -> list[str]:
    """Risk flags B2's shared vocabulary assigns to the captured request object."""
    from extorq.ingest.otlp_k8s import risk_flags_for_summary, summarize_k8s_object

    record = json.loads((AUDIT_FIXTURES / filename).read_text(encoding="utf-8"))
    resource = record.get("objectRef", {}).get("resource")
    return risk_flags_for_summary(
        summarize_k8s_object(record.get("requestObject"), resource=resource)
    )


# ── GitHub: attributes computed by C1's workflow analyser ────────────


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
        change_type=change,
    )  # type: ignore[arg-type]
    return {k: v for k, v in delta.to_attributes().items() if v is not None}
