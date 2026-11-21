"""Throwaway ClickHouse for validating the analyst API's SQL (owner: D1).

* Starts ``clickhouse/clickhouse-server:26.8.42.13`` as ``extorq-d1-apisql-<random>``,
  publishing 8123 on a random **loopback** port only, and removes it afterwards
  (``docker rm -f``). Never touches the shared compose stack.
* Applies the real migrations 0001 (core) and 0003 (findings lifecycle views).
* Creates two users that mirror PLAN 4.4 / 0002 for the API:
  ``d1_api_ro`` (SELECT on extorq.*, readonly=2, max_result_rows=100000,
  result_overflow_mode='throw') and ``d1_api_writer`` (INSERT only on the tables the
  API identity may write). The repository runs with exactly these identities.
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
)
from extorq.contracts.identity import canonical_json, event_id, finding_id, scope_hash, stable_id
from extorq.storage import rows

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
        for name in ("0001_core_tables.sql", "0003_findings_views.sql"):
            self.sql((MIGRATIONS / name).read_text(encoding="utf-8"))
        self.sql(
            """
            CREATE USER IF NOT EXISTS d1_api_ro IDENTIFIED WITH no_password
                SETTINGS readonly = 2, max_result_rows = 100000,
                         result_overflow_mode = 'throw', max_execution_time = 30;
            GRANT SELECT ON extorq.* TO d1_api_ro;
            CREATE USER IF NOT EXISTS d1_api_writer IDENTIFIED WITH no_password;
            GRANT INSERT ON extorq.analyst_state TO d1_api_writer;
            GRANT INSERT ON extorq.analyst_actions TO d1_api_writer;
            GRANT INSERT ON extorq.ai_assessments TO d1_api_writer;
            GRANT INSERT ON extorq.investigation_contexts TO d1_api_writer;
            GRANT INSERT ON extorq.context_relationships TO d1_api_writer;
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
    event_ids: dict[str, str] = field(default_factory=dict)
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
    _insert(admin, "assets", assets)

    # Events (e1 inserted twice: duplicate delivery must not double-count).
    e1 = _event(ds, "e1")
    e2 = _event(
        ds,
        "e2",
        event_type="auth.ssh.invalid_user",
        event_time=n - timedelta(minutes=29),
        actor={"type": "user", "name": "synthetic-admin"},
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
    event_rows = [
        rows.event_to_row(e, producer_id=PRODUCER, batch_id=BATCH, ingested_at=n)
        for e in (e1, e1, e2, e3, e4)
    ]
    _insert(admin, "events", event_rows)
    ds.event_ids = {"e1": e1.event_id, "e2": e2.event_id, "e3": e3.event_id, "e4": e4.event_id}

    # Alerts: a1 has two versions (late evidence bumped updated_at); a2 is closed later.
    def alert(label: str, *, severity: str, updated: datetime, count: int) -> dict[str, Any]:
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

    a1_v1 = alert("a1", severity="high", updated=n - timedelta(minutes=28), count=5)
    a1_v2 = alert("a1", severity="high", updated=n - timedelta(minutes=20), count=7)
    a2 = alert("a2", severity="critical", updated=n - timedelta(minutes=27), count=6)
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

    def finding(check: str, scan: ScanRun, severity: str) -> PostureFinding:
        return PostureFinding(
            finding_id=finding_id(ds.linux, "trivy", check, "openssh-server"),
            scan_run_id=scan.scan_run_id,
            asset_id=ds.linux,
            scanner="trivy",
            check_id=check,
            category="vulnerability",
            severity=severity,
            title=f"synthetic {check}",
            observed_at=scan.started_at + timedelta(seconds=30),
            cve_ids=[check],
        )

    f_old = finding("CVE-0000-0001", scans[0], "medium")
    f_open_1 = finding("CVE-0000-0002", scans[0], "critical")
    f_open_2 = finding("CVE-0000-0002", scans[1], "critical")
    _insert(
        admin,
        "finding_observations",
        [
            rows.finding_to_row(f, producer_id=PRODUCER, ingested_at=n)
            for f in (f_old, f_open_1, f_open_2)
        ],
    )
    ds.finding_ids = {"resolved": f_old.finding_id, "open": f_open_1.finding_id}

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
    return ds
