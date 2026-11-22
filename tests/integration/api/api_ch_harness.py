"""Throwaway ClickHouse for validating the analyst API's SQL (owner: D1).

* Starts ``clickhouse/clickhouse-server:26.8.42.13`` as ``extorq-d1-apisql-<random>``,
  publishing 8123 on a random **loopback** port only, and removes it afterwards
  (``docker rm -f``). Never touches the shared compose stack.
* Applies the real migrations 0001 (core), the settings profiles, roles and grants of
  0002 (RBAC; user/password/quota statements skipped), 0003 (findings lifecycle views),
  0004 (service model, schema 1.1), 0005 (``v_findings_current.service_id``) and 0006
  (refreshed ``v_alerts``): the same schema the live stack runs.
* Creates users bound to the REAL roles and settings profiles of 0002:
  ``d1_api_ro`` (extorq_role_api_ro + extorq_api_readonly), ``d1_api_writer``
  (extorq_role_api_writer) and ``d1_grafana`` (extorq_role_grafana with its column-level
  grant on events + extorq_grafana_readonly). Tests query with exactly these identities.
* Seeds a SMALL SYNTHETIC dataset. Every row is synthetic (names/messages carry the
  word ``synthetic``), lives only in this container and is destroyed with it. Rows are
  built from contract models and mapped with the platform's own ``extorq.storage.rows``
  so they match what the writer produces.

Skipped when Docker or the pinned image is unavailable (nothing is pulled).
"""

from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import clickhouse_connect

from extorq.contracts import (
    Asset,
    CollectorHealth,
    PipelineHealth,
    PostureFinding,
    ScanRun,
    SecurityEvent,
    Service,
    ServiceInstance,
)
from extorq.contracts.identity import (
    canonical_json,
    event_id,
    finding_id,
    instance_id,
    scope_hash,
    service_id,
    stable_id,
)
from extorq.storage import rows
from extorq.storage.migrate import split_statements

REPO_ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = REPO_ROOT / "infra" / "clickhouse" / "migrations"
IMAGE = "clickhouse/clickhouse-server:26.8.42.13"
_TIMEOUT = 90


def _run(args: list[str], *, stdin: str | None = None, timeout: int = _TIMEOUT) -> str:
    proc = subprocess.run(
        args, input=stdin, capture_output=True, text=True, timeout=timeout, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(f"{args[:3]} failed ({proc.returncode}): {proc.stderr.strip()[:1500]}")
    return proc.stdout


def unavailable_reason() -> str | None:
    docker = shutil.which("docker")
    if docker is None:
        return "docker CLI not installed"
    try:
        subprocess.run(
            [docker, "image", "inspect", IMAGE], capture_output=True, timeout=20, check=True
        )
    except (subprocess.SubprocessError, OSError):
        return f"docker daemon or local image {IMAGE} not available"
    return None


class EphemeralClickHouse:
    def __init__(self) -> None:
        self.docker = shutil.which("docker") or "docker"
        self.name = f"extorq-d1-apisql-{uuid.uuid4().hex[:8]}"
        self.port: int | None = None

    def start(self) -> None:
        _run(
            [
                self.docker, "run", "-d", "--name", self.name,
                "--ulimit", "nofile=262144:262144",
                "-p", "127.0.0.1::8123",
                "-e", "CLICKHOUSE_SKIP_USER_SETUP=1",
                "-e", "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1",
                IMAGE,
            ]
        )  # fmt: skip
        mapping = _run([self.docker, "port", self.name, "8123/tcp"]).strip().splitlines()[0]
        host, _, port = mapping.rpartition(":")
        if host not in ("127.0.0.1", "[::1]", "::1"):
            raise RuntimeError(f"unexpected port binding {mapping!r}")
        self.port = int(port)
        deadline = time.monotonic() + 60
        while True:
            try:
                _run(
                    [self.docker, "exec", self.name, "clickhouse-client", "-q", "SELECT 1"],
                    timeout=10,
                )
                break
            except (RuntimeError, subprocess.TimeoutExpired):
                if time.monotonic() > deadline:
                    raise
                time.sleep(1)

    def sql(self, text: str) -> str:
        return _run(
            [self.docker, "exec", "-i", self.name, "clickhouse-client", "--multiquery"],
            stdin=text,
        )

    def migrate(self) -> None:
        self.sql((MIGRATIONS / "0001_core_tables.sql").read_text(encoding="utf-8"))
        rbac = [
            statement
            for statement in split_statements(
                (MIGRATIONS / "0002_rbac.sql").read_text(encoding="utf-8")
            )
            # Users need rendered password hashes and quotas target those users: the
            # harness creates its own passwordless users bound to the same roles below.
            if "{{" not in statement
            and not statement.lstrip().upper().startswith(("CREATE QUOTA", "GRANT EXTORQ_ROLE_"))
        ]
        self.sql(";\n".join(rbac) + ";")
        for name in (
            "0003_findings_views.sql",
            "0004_services.sql",
            "0005_findings_services.sql",
            "0006_refresh_views.sql",
        ):
            self.sql((MIGRATIONS / name).read_text(encoding="utf-8"))
        self.sql(
            """
            CREATE USER IF NOT EXISTS d1_api_ro IDENTIFIED WITH no_password
                SETTINGS PROFILE 'extorq_api_readonly';
            GRANT extorq_role_api_ro TO d1_api_ro;
            CREATE USER IF NOT EXISTS d1_api_writer IDENTIFIED WITH no_password
                SETTINGS PROFILE 'extorq_service';
            GRANT extorq_role_api_writer TO d1_api_writer;
            CREATE USER IF NOT EXISTS d1_grafana IDENTIFIED WITH no_password
                SETTINGS PROFILE 'extorq_grafana_readonly';
            GRANT extorq_role_grafana TO d1_grafana;
            """
        )

    def client(self, user: str) -> Any:
        assert self.port is not None
        return clickhouse_connect.get_client(
            host="127.0.0.1",
            port=self.port,
            username=user,
            password="",
            database="extorq",
            autogenerate_session_id=False,
            connect_timeout=5,
            send_receive_timeout=30,
        )

    def stop(self) -> None:
        subprocess.run(
            [self.docker, "rm", "-f", self.name], capture_output=True, timeout=60, check=False
        )


# ── synthetic dataset ─────────────────────────────────────────────────────────────

PRODUCER = "synthetic-producer"
BATCH = "0" * 32


@dataclass
class Dataset:
    now: datetime
    linux: str = "linux:lab-vm-01"
    github: str = "github:synthetic/extorq-lab"
    k8s: str = "k8s:extorq-lab"
    k8s_node: str = "k8s:extorq-lab/node/extorq-lab-control-plane"
    event_ids: dict[str, str] = field(default_factory=dict)
    service_ids: dict[str, str] = field(default_factory=dict)
    alert_ids: dict[str, str] = field(default_factory=dict)
    finding_ids: dict[str, str] = field(default_factory=dict)


def _ms(value: datetime) -> datetime:
    return value.replace(microsecond=(value.microsecond // 1000) * 1000)


def _insert(client: Any, table: str, data: list[dict[str, Any]]) -> None:
    columns = list(data[0])
    client.insert(table, [[row[c] for c in columns] for row in data], column_names=columns)


def _event(ds: Dataset, label: str, **kw: Any) -> SecurityEvent:
    base: dict[str, Any] = {
        "event_id": event_id("linux.journald", ds.linux, f"synthetic:{label}"),
        "event_type": "auth.ssh.login_failed",
        "category": "authentication",
        "asset_id": ds.linux,
        "asset_type": "linux_host",
        "source": {
            "source_type": "linux.journald",
            "collector_id": "synthetic-linux",
            "collector_version": "0.0.0",
            "collection_method": "ssh_pull",
        },
        "event_time": ds.now - timedelta(minutes=30),
        "outcome": "failure",
        "actor": {"type": "user", "name": "root"},
        "network": {"src_ip": "10.0.2.2", "src_port": 50000},
        "message": f"synthetic {label}",
        "attributes": {"auth_method": "password"},
        "provenance": {"parser": "synthetic-parser", "parser_version": "0"},
    }
    base.update(kw)
    return SecurityEvent(**base)


def seed(admin: Any, now: datetime) -> Dataset:
    ds = Dataset(now=_ms(now))
    n = ds.now

    # Assets: the linux asset twice (older + newer version) to prove FINAL dedup.
    assets = []
    for last_seen, criticality in ((n - timedelta(hours=2), "low"), (n, "high")):
        asset = Asset(
            asset_id=ds.linux,
            asset_type="linux_host",
            name="synthetic-vm",
            criticality=criticality,
            attributes={"os_name": "synthetic"},
            first_seen=n - timedelta(days=1),
            last_seen=last_seen,
            observed_by="synthetic-linux",
        )
        assets.append(rows.asset_to_row(asset, producer_id=PRODUCER, ingested_at=n))
    assets.append(
        rows.asset_to_row(
            Asset(
                asset_id=ds.github,
                asset_type="github_repository",
                name="synthetic-repo",
                first_seen=n - timedelta(days=1),
                last_seen=n,
                observed_by="synthetic-github",
            ),
            producer_id=PRODUCER,
            ingested_at=n,
        )
    )
    for asset_id, asset_type, parent in (
        (ds.k8s, "kubernetes_cluster", None),
        (ds.k8s_node, "kubernetes_node", ds.k8s),
    ):
        assets.append(
            rows.asset_to_row(
                Asset(
                    asset_id=asset_id,
                    asset_type=asset_type,
                    name=f"synthetic-{asset_type}",
                    parent_asset_id=parent,
                    first_seen=n - timedelta(days=1),
                    last_seen=n,
                    observed_by="synthetic-k8s",
                ),
                producer_id=PRODUCER,
                ingested_at=n,
            )
        )
    _insert(admin, "assets", assets)
    ds.service_ids = {
        "ssh": service_id(ds.linux, "host_service", "ssh.service"),
        "ftp": service_id(ds.linux, "host_service", "vsftpd.service"),
        "gone": service_id(ds.linux, "host_service", "gone.service"),
        "workload": service_id(ds.k8s, "k8s_workload", "extorq-apps/Deployment/lab-portal"),
        "k8s_service": service_id(ds.k8s, "k8s_service", "extorq-apps/lab-portal"),
    }
    ssh_ref = {"service_id": ds.service_ids["ssh"], "name": "ssh", "adapter_id": "ssh"}

    # Events (e1 inserted twice: duplicate delivery must not double-count).
    e1 = _event(ds, "e1", service=ssh_ref)
    e2 = _event(
        ds,
        "e2",
        event_type="auth.ssh.invalid_user",
        event_time=n - timedelta(minutes=29),
        actor={"type": "user", "name": "synthetic-admin"},
        service=ssh_ref,
    )
    e3 = _event(
        ds,
        "e3",
        event_id=event_id("github.api", ds.github, "synthetic:e3"),
        event_type="github.workflow.modified",
        category="ci_cd",
        asset_id=ds.github,
        asset_type="github_repository",
        source={
            "source_type": "github.api",
            "collector_id": "synthetic-github",
            "collector_version": "0.0.0",
            "collection_method": "api_poll",
        },
        actor=None,
        network=None,
        outcome="success",
        github={"repository": "synthetic/extorq-lab", "actor_login": "synthetic-dev"},
        attributes={"write_all_added": True},
    )
    e4 = _event(
        ds,
        "e4",
        event_id=event_id("k8s.audit", ds.k8s, "synthetic:e4"),
        event_type="k8s.api.request",
        category="kubernetes_api",
        asset_id=ds.k8s,
        asset_type="kubernetes_cluster",
        source={
            "source_type": "k8s.audit",
            "collector_id": "synthetic-otel",
            "collector_version": "0.0.0",
            "collection_method": "otel_filelog",
        },
        actor=None,
        network=None,
        outcome="denied",
        kubernetes={
            "verb": "create",
            "resource": "pods",
            "response_code": 403,
            "user": "synthetic-user",
            "source_ips": ["10.0.2.2"],
        },
        attributes={},
    )
    # F-19: another asset's producer tags its event with the VM's ssh service id. Three days
    # old, so it stays outside every default window; scoped queries must never show it.
    planted = _event(
        ds,
        "planted",
        event_id=event_id("macos.unified_log", "macos:synthetic-01", "synthetic:planted"),
        asset_id="macos:synthetic-01",
        asset_type="macos_host",
        source={
            "source_type": "macos.unified_log",
            "collector_id": "synthetic-macos",
            "collector_version": "0.0.0",
            "collection_method": "native_command",
        },
        event_time=n - timedelta(days=3),
        service=ssh_ref,
    )
    event_rows = [
        rows.event_to_row(e, producer_id=PRODUCER, batch_id=BATCH, ingested_at=n)
        for e in (e1, e1, e2, e3, e4, planted)
    ]
    _insert(admin, "events", event_rows)
    ds.event_ids = {
        "e1": e1.event_id,
        "e2": e2.event_id,
        "e3": e3.event_id,
        "e4": e4.event_id,
        "planted": planted.event_id,
    }

    # Alerts: a1 has two versions (late evidence bumped updated_at); a2 is closed later.
    def alert(
        label: str, *, severity: str, updated: datetime, count: int, services: list[str]
    ) -> dict[str, Any]:
        alert_id = stable_id("alert.v1", "VM-001", label, "synthetic")
        payload = {"synthetic": True}
        return {
            "alert_id": alert_id,
            "schema_version": "1.0",
            "rule_id": "VM-001",
            "rule_version": "1.0.0",
            "rule_title": "synthetic failed SSH burst",
            "severity": severity,
            "confidence": "high",
            "asset_id": ds.linux,
            "asset_type": "linux_host",
            "group_key": f"synthetic|{label}",
            "entities": {"src_ip": "10.0.2.2"},
            "service_ids": services,
            "summary": f"synthetic alert {label}",
            "first_seen": n - timedelta(minutes=31),
            "last_seen": n - timedelta(minutes=29),
            "window_start": n - timedelta(minutes=35),
            "window_end": n - timedelta(minutes=30),
            "event_count": count,
            "evidence_event_ids": [e1.event_id, e2.event_id],
            "evidence_truncated": 0,
            "features": canonical_json({"distinct_connections": count}),
            "mitre_techniques": ["T1110"],
            "simulation_run_ids": [],
            "created_at": n - timedelta(minutes=28),
            "updated_at": updated,
            "detector_version": "0.0.0-synthetic",
            "payload": canonical_json(payload),
        }

    ssh_only = [ds.service_ids["ssh"]]
    a1_v1 = alert("a1", severity="high", updated=n - timedelta(minutes=28), count=5, services=[])
    a1_v2 = alert(
        "a1", severity="high", updated=n - timedelta(minutes=20), count=7, services=ssh_only
    )
    a2 = alert("a2", severity="critical", updated=n - timedelta(minutes=27), count=6, services=[])
    _insert(admin, "alerts", [a1_v1, a1_v2, a2])
    ds.alert_ids = {"a1": a1_v1["alert_id"], "a2": a2["alert_id"]}

    missing_event = stable_id("event.v1", "synthetic", "missing")
    _insert(
        admin,
        "alert_evidence",
        [
            {"alert_id": a1_v1["alert_id"], "event_id": e2.event_id, "role": "supporting",
             "added_at": n - timedelta(minutes=28)},
            {"alert_id": a1_v1["alert_id"], "event_id": e1.event_id, "role": "trigger",
             "added_at": n - timedelta(minutes=28)},
            {"alert_id": a1_v1["alert_id"], "event_id": missing_event, "role": "supporting",
             "added_at": n - timedelta(minutes=27)},
        ],
    )  # fmt: skip
    ds.event_ids["missing"] = missing_event

    # Analyst state: a2 acknowledged then closed (latest wins).
    _insert(
        admin,
        "analyst_state",
        [
            {"alert_id": a2["alert_id"], "status": "acknowledged", "assignee": "bob",
             "note": None, "updated_by": "bob", "updated_at": n - timedelta(minutes=10)},
            {"alert_id": a2["alert_id"], "status": "closed_false_positive", "assignee": "bob",
             "note": "synthetic note", "updated_by": "bob", "updated_at": n - timedelta(minutes=5)},
        ],
    )  # fmt: skip

    # Rules: VM-001 v1.0.0 (older) and v1.1.0 (current); runs incl. a duplicate row.
    def rule(version: str, loaded: datetime) -> dict[str, Any]:
        return {
            "rule_id": "VM-001",
            "version": version,
            "title": "synthetic failed SSH burst",
            "description": "synthetic description",
            "severity": "high",
            "status": "stable",
            "mitre_techniques": ["T1110"],
            "asset_types": ["linux_host"],
            "requires": canonical_json([{"source_type": "linux.journald"}]),
            "schedule": canonical_json({"interval_seconds": 60, "lookback_seconds": 900}),
            "dedup": canonical_json({"strategy": "window_bucket", "bucket_seconds": 300}),
            "group_by": ["asset_id", "src_ip"],
            "params": "{}",
            "false_positives": ["synthetic fp"],
            "blind_spots": ["synthetic blind spot"],
            "reference_urls": [],
            "query_sha256": "a" * 64,
            "query_text": "SELECT 1",
            "enabled": 1,
            "loaded_at": loaded,
        }

    _insert(admin, "detection_rules", [rule("1.0.0", n - timedelta(days=1)), rule("1.1.0", n)])
    run = {
        "run_id": "1" * 32,
        "rule_id": "VM-001",
        "rule_version": "1.1.0",
        "started_at": n - timedelta(seconds=40),
        "finished_at": n - timedelta(seconds=39),
        "window_start": n - timedelta(minutes=15),
        "window_end": n - timedelta(seconds=40),
        "status": "succeeded",
        "rows_matched": 1,
        "alerts_created": 1,
        "alerts_updated": 0,
        "duration_ms": 9,
        "error": None,
        "missing_sources": ["linux.auditd"],
        "detector_instance": "synthetic-detector",
    }
    failed = dict(
        run,
        run_id="2" * 32,
        started_at=n - timedelta(minutes=3),
        finished_at=n - timedelta(minutes=3),
        status="failed",
        error="synthetic error",
    )
    _insert(admin, "rule_runs", [run, run, failed])

    # Collector health: linux ok (latest of two reports), github stale.
    def health(collector: str, asset: str, *, success_ago: timedelta, status: str,
               reported_ago: timedelta, interval: int) -> dict[str, Any]:  # fmt: skip
        model = CollectorHealth(
            collector_id=collector,
            collector_type="synthetic",
            asset_id=asset,
            source_types=["linux.journald"],
            status=status,
            reported_at=n - reported_ago,
            last_success_at=n - success_ago,
            collector_version="0.0.0",
            interval_seconds=interval,
        )
        return rows.collector_health_to_row(model, producer_id=PRODUCER, ingested_at=n)

    _insert(
        admin,
        "collector_health",
        [
            health("synthetic-linux", ds.linux, success_ago=timedelta(minutes=30), status="failed",
                   reported_ago=timedelta(minutes=30), interval=60),
            health("synthetic-linux", ds.linux, success_ago=timedelta(seconds=30), status="ok",
                   reported_ago=timedelta(seconds=30), interval=60),
            health("synthetic-github", ds.github, success_ago=timedelta(hours=2), status="ok",
                   reported_ago=timedelta(hours=2), interval=300),
        ],
    )  # fmt: skip

    _insert(
        admin,
        "pipeline_health",
        [
            rows.pipeline_health_to_row(
                PipelineHealth(component="writer", instance="synthetic-w1", reported_at=n,
                               status="ok", written_total=5)
            ),
            rows.pipeline_health_to_row(
                PipelineHealth(component="ingest", instance="synthetic-old",
                               reported_at=n - timedelta(hours=1), status="ok")
            ),
        ],
    )  # fmt: skip

    # Inventory (current + tombstone).
    _insert(
        admin,
        "inventory_items",
        [
            {"asset_id": ds.linux, "item_type": "package", "item_key": "openssh-server",
             "attributes": "{}", "snapshot_id": "s1", "observed_at": n, "present": 1,
             "collector_id": "synthetic-linux", "producer_id": PRODUCER, "ingested_at": n},
            {"asset_id": ds.linux, "item_type": "package", "item_key": "removed-pkg",
             "attributes": "{}", "snapshot_id": "s1", "observed_at": n, "present": 0,
             "collector_id": "synthetic-linux", "producer_id": PRODUCER, "ingested_at": n},
        ],
    )  # fmt: skip

    # Findings: one scan scope, two succeeded scans; f_old resolved, f_open open.
    scope = scope_hash(["/"], "synthetic")
    scans = []
    for idx, started in enumerate((n - timedelta(hours=2), n - timedelta(hours=1))):
        scans.append(
            ScanRun(
                scan_run_id=stable_id("scan.synthetic", idx),
                scanner="trivy",
                scanner_version="0.0.0",
                asset_id=ds.linux,
                scope={"targets": ["/"], "description": "synthetic", "scope_hash": scope},
                started_at=started,
                finished_at=started + timedelta(minutes=1),
                status="succeeded",
                producer_id="scanner-runner",
            )
        )
    _insert(
        admin,
        "scan_runs",
        [rows.scan_run_to_row(s, producer_id=PRODUCER, ingested_at=n) for s in scans],
    )

    # A second scanner/scope (two succeeded scans) carries the service-attribution cases.
    posture_scope = scope_hash(["/etc"], "synthetic posture")
    posture_scans = [
        ScanRun(
            scan_run_id=stable_id("scan.synthetic-posture", idx),
            scanner="synthetic-posture",
            scanner_version="0.0.0",
            asset_id=ds.linux,
            scope={"targets": ["/etc"], "description": "synthetic", "scope_hash": posture_scope},
            started_at=started,
            finished_at=started + timedelta(minutes=1),
            status="succeeded",
            producer_id="scanner-runner",
        )
        for idx, started in enumerate((n - timedelta(hours=2), n - timedelta(hours=1)))
    ]
    _insert(
        admin,
        "scan_runs",
        [rows.scan_run_to_row(s, producer_id=PRODUCER, ingested_at=n) for s in posture_scans],
    )

    def finding(
        check: str,
        scan: ScanRun,
        severity: str,
        service: str | None = None,
        scanner: str = "trivy",
    ) -> PostureFinding:
        return PostureFinding(
            finding_id=finding_id(ds.linux, scanner, check, "openssh-server"),
            scan_run_id=scan.scan_run_id,
            asset_id=ds.linux,
            scanner=scanner,
            check_id=check,
            category="vulnerability" if scanner == "trivy" else "misconfiguration",
            severity=severity,
            title=f"synthetic {check}",
            observed_at=scan.started_at + timedelta(seconds=30),
            cve_ids=[check] if scanner == "trivy" else [],
            service_id=service,
        )

    ssh, ftp = ds.service_ids["ssh"], ds.service_ids["ftp"]
    f_old = finding("CVE-0000-0001", scans[0], "medium")
    # "cleared": the first observation is attributed to ssh, the LATEST is not. Attribution
    # is evidence of the latest scan (v_findings_current.service_id): the link is cleared.
    f_open_1 = finding("CVE-0000-0002", scans[0], "critical", ssh)
    f_open_2 = finding("CVE-0000-0002", scans[1], "critical")
    posture = "synthetic-posture"
    gained, moved = "synthetic.check.gained", "synthetic.check.moved"
    # "gained": unattributed first, attributed to ssh by the latest scan.
    f_gained_1 = finding(gained, posture_scans[0], "low", None, posture)
    f_gained_2 = finding(gained, posture_scans[1], "low", ssh, posture)
    # "moved": attributed to ssh first, to ftp by the latest scan (latest wins).
    f_moved_1 = finding(moved, posture_scans[0], "low", ssh, posture)
    f_moved_2 = finding(moved, posture_scans[1], "low", ftp, posture)
    _insert(
        admin,
        "finding_observations",
        [
            rows.finding_to_row(f, producer_id=PRODUCER, ingested_at=n)
            for f in (f_old, f_open_1, f_open_2, f_gained_1, f_gained_2, f_moved_1, f_moved_2)
        ],
    )
    ds.finding_ids = {
        "resolved": f_old.finding_id,
        "open": f_open_1.finding_id,
        "gained": f_gained_1.finding_id,
        "moved": f_moved_1.finding_id,
    }

    # AI assessments (E's row format) and ingest boundary records.
    _insert(
        admin,
        "ai_assessments",
        [
            {"assessment_id": "3" * 32, "alert_id": a1_v1["alert_id"], "context_id": "4" * 32,
             "context_input_hash": "5" * 64, "provider": "google-gemini",
             "model": "synthetic-model", "task": "summary", "prompt_version": "summary-v1",
             "status": "timeout", "recommendation": None, "uncertain": None,
             "output": canonical_json({"requested_model": "synthetic-model", "triage": None,
                                       "summary": None, "validation": None}),
             "latency_ms": 30000, "input_tokens": None, "output_tokens": None,
             "provider_request_id": None, "error": "TimeoutError",
             "created_at": n - timedelta(minutes=15), "requested_by": "analyst:synthetic"},
        ],
    )  # fmt: skip
    _insert(
        admin,
        "ingest_quarantine",
        [
            rows.quarantine_row(
                quarantine_id="6" * 32, received_at=n, producer_id=PRODUCER, batch_id=BATCH,
                record_index=0, record_kind="event", reason="synthetic reason",
                payload_excerpt="{}", payload_sha256="7" * 64,
            )
        ],
    )  # fmt: skip
    _insert(
        admin,
        "ingest_audit",
        [
            rows.audit_row(
                audit_id="8" * 32, occurred_at=n, remote_addr="127.0.0.1",
                claimed_producer="synthetic", authenticated_producer=None,
                decision="denied", reason="synthetic bad token", path="/v1/ingest",
            )
        ],
    )  # fmt: skip
    _seed_services(admin, ds)
    return ds


def _service(ds: Dataset, key: str, **kw: Any) -> Service:
    n = ds.now
    base: dict[str, Any] = {
        "asset_id": ds.linux,
        "service_kind": "host_service",
        "service_key": key,
        "name": key.removesuffix(".service"),
        "category": "unknown",
        "discovered_via": ["systemd_unit"],
        "adapter_support": "none",
        "monitoring_status": "unmonitored",
        "first_seen": n - timedelta(days=1),
        "last_seen": n,
        "observed_by": "synthetic-linux",
    }
    base.update(kw)
    base["service_id"] = service_id(base["asset_id"], base["service_kind"], key)
    return Service(**base)


def _seed_services(admin: Any, ds: Dataset) -> None:
    n = ds.now
    ssh_endpoint = {
        "protocol": "tcp", "address": "0.0.0.0", "port": 22, "exposure": "any",  # noqa: S104
        "attribution": "confirmed", "attribution_basis": "synthetic socket owner",
    }  # fmt: skip
    ssh = {
        "category": "ssh", "product": "openssh", "adapter_id": "ssh",
        "adapter_support": "implemented", "telemetry_sources": ["linux.journald"],
        "discovered_via": ["listening_socket", "systemd_unit"], "endpoints": [ssh_endpoint],
        "config_refs": ["/etc/ssh/sshd_config"], "instance_count": 1,
        "attributes": {"origin": "synthetic"},
    }  # fmt: skip
    services = [
        # Older version (degraded) and newer version (monitored): FINAL keeps the newest.
        _service(ds, "ssh.service", monitoring_status="degraded",
                 last_seen=n - timedelta(hours=1), **ssh),
        _service(ds, "ssh.service", monitoring_status="monitored", **ssh),
        _service(ds, "vsftpd.service", category="ftp", adapter_id="ftp",
                 adapter_support="planned",
                 coverage_note="planned adapter 'ftp': discovered only, no telemetry collected"),
        _service(ds, "gone.service", present=False),
        _service(ds, "extorq-apps/Deployment/lab-portal", asset_id=ds.k8s,
                 service_kind="k8s_workload", name="lab-portal", category="web_application",
                 discovered_via=["k8s_api"], adapter_id="webapp-json",
                 adapter_support="implemented", monitoring_status="monitored",
                 telemetry_sources=["k8s.container_log"]),
        _service(ds, "extorq-apps/lab-portal", asset_id=ds.k8s, service_kind="k8s_service",
                 name="lab-portal", category="web_application", discovered_via=["k8s_api"],
                 endpoints=[{"protocol": "tcp", "address": "10.96.0.20", "port": 80,
                             "exposure": "private", "attribution": "confirmed"}]),
    ]  # fmt: skip
    _insert(
        admin,
        "services",
        [rows.service_to_row(s, producer_id=PRODUCER, ingested_at=n) for s in services],
    )
    ssh_id, workload_id = ds.service_ids["ssh"], ds.service_ids["workload"]

    def instance(service: str, kind: str, key: str, **kw: Any) -> ServiceInstance:
        base: dict[str, Any] = {
            "instance_id": instance_id(service, kind, key),
            "service_id": service,
            "instance_kind": kind,
            "instance_key": key,
            "observed_at": n,
            "observed_by": "synthetic-collector",
            "state": "running",
        }
        base.update(kw)
        return ServiceInstance(**base)

    instances = [
        instance(ssh_id, "process", "pid:100", asset_id=ds.linux, pid=100, process_name="sshd",
                 user="root", observed_at=n - timedelta(minutes=10)),
        instance(ssh_id, "process", "pid:100", asset_id=ds.linux, pid=100, process_name="sshd",
                 user="root"),
        instance(ssh_id, "process", "pid:7", asset_id=ds.linux, pid=7, present=False),
        # F-19: an instance on the GitHub asset naming the VM's ssh service (planted).
        instance(ssh_id, "process", "pid:666", asset_id=ds.github, pid=666, process_name="sshd"),
        instance(workload_id, "pod", "synthetic-pod-uid", asset_id=ds.k8s_node,
                 namespace="extorq-apps", pod_name="lab-portal-0", pod_uid="synthetic-pod-uid",
                 node_name="extorq-lab-control-plane", workload_kind="Deployment",
                 workload_name="lab-portal"),
    ]  # fmt: skip
    _insert(
        admin,
        "service_instances",
        [rows.service_instance_to_row(i, producer_id=PRODUCER, ingested_at=n) for i in instances],
    )
