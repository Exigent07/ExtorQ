"""Ephemeral ClickHouse harness for the findings lifecycle view tests (owner: C3).

The tests talk to a throwaway ``clickhouse/clickhouse-server:26.8.42.13``
container through ``docker exec ... clickhouse-client``. The container runs with
``--network none`` and publishes no port, so nothing is exposed on the host.

* Two variants: ``0003`` (container ``extorq-c3-lifecycle-ch``, override with
  ``EXTORQ_C3_LIFECYCLE_CH``; migrations 0001 + 0003) and ``0005`` (container
  ``extorq-c3-services-ch``, override with ``EXTORQ_C3_SERVICES_CH``; 0001, the
  roles 0004 grants to, 0003, 0004, 0005), i.e. the view before and after the
  service-model migration.
* A container that is already running is reused and left running; otherwise it
  is started here and removed again when the test module finishes.
* Tests are skipped when Docker or the pinned image is not available locally;
  nothing is pulled from a registry during unit tests.

Rows are built from real contract models (``ScanRun`` / ``PostureFinding``) and
mapped to the 0001 columns exactly as documented in the schema comments
(``row_version`` = epoch_ms(coalesce(finished_at, started_at)) * 10 + status_rank).
All data written by these tests is synthetic and scoped to unique asset ids.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from extorq.contracts import PostureFinding, ScanRun, ScanStatus

REPO_ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = REPO_ROOT / "infra" / "clickhouse" / "migrations"
IMAGE = "clickhouse/clickhouse-server:26.8.42.13"
CONTAINER = os.environ.get("EXTORQ_C3_LIFECYCLE_CH", "extorq-c3-lifecycle-ch")
SERVICES_CONTAINER = os.environ.get("EXTORQ_C3_SERVICES_CH", "extorq-c3-services-ch")
#: Roles created by 0002 (whose users need rendered passwords, not applied here)
#: that 0004 grants to.
ROLES_0004 = (
    "extorq_role_ingest",
    "extorq_role_detect",
    "extorq_role_rules_ro",
    "extorq_role_api_ro",
    "extorq_role_grafana",
)
#: name -> (container, steps). A step is a migration file name or "roles".
VARIANTS: dict[str, tuple[str, tuple[str, ...]]] = {
    "0003": (CONTAINER, ("0001_core_tables.sql", "0003_findings_views.sql")),
    "0005": (
        SERVICES_CONTAINER,
        (
            "0001_core_tables.sql",
            "roles",
            "0003_findings_views.sql",
            "0004_services.sql",
            "0005_findings_services.sql",
        ),
    ),
}
_TIMEOUT = 60


def _docker() -> str | None:
    return shutil.which("docker")


def _run(args: list[str], *, stdin: str | None = None, timeout: int = _TIMEOUT) -> str:
    proc = subprocess.run(
        args, input=stdin, capture_output=True, text=True, timeout=timeout, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(f"{args[:4]} failed ({proc.returncode}): {proc.stderr.strip()[:2000]}")
    return proc.stdout


def docker_unavailable_reason() -> str | None:
    docker = _docker()
    if docker is None:
        return "docker CLI not installed"
    try:
        subprocess.run(
            [docker, "image", "inspect", IMAGE],
            capture_output=True,
            timeout=20,
            check=True,
        )
    except (subprocess.SubprocessError, OSError):
        return f"docker daemon or local image {IMAGE} not available"
    return None


def _ts(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.") + f"{value.microsecond // 1000:03d}"


def _epoch_ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def _jsonable(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in row.items():
        if isinstance(value, datetime):
            aware = value if value.tzinfo else value.replace(tzinfo=UTC)
            out[key] = _ts(aware)
        else:
            out[key] = value
    return out


def scan_run_row(run: ScanRun, *, ingested_at: datetime | None = None) -> dict[str, Any]:
    """``scan_runs`` row exactly as A's writer builds it (``extorq.storage.rows``)."""
    from extorq.storage.rows import scan_run_to_row

    row = scan_run_to_row(
        run, producer_id="scanner-runner", ingested_at=ingested_at or datetime.now(UTC)
    )
    expected = _epoch_ms(run.finished_at or run.started_at) * 10 + (
        0 if run.status is ScanStatus.RUNNING else 1
    )
    if row["row_version"] != expected:  # guard: DDL formula drift would break the view
        raise AssertionError("writer row_version differs from the 0001 DDL formula")
    return _jsonable(row)


def finding_row(finding: PostureFinding, *, ingested_at: datetime | None = None) -> dict[str, Any]:
    """``finding_observations`` row exactly as A's writer builds it."""
    from extorq.storage.rows import finding_to_row

    row = finding_to_row(
        finding, producer_id="scanner-runner", ingested_at=ingested_at or datetime.now(UTC)
    )
    return _jsonable(row)


class ClickHouse:
    """Minimal ``docker exec clickhouse-client`` wrapper (server-side parameters only)."""

    def __init__(self, container: str) -> None:
        self.container = container
        self.docker = _docker() or "docker"

    def _client(
        self,
        *,
        params: dict[str, str] | None = None,
        settings: dict[str, str] | None = None,
        user: str | None = None,
    ) -> list[str]:
        args = [self.docker, "exec", "-i", self.container, "clickhouse-client"]
        if user:
            args += ["--user", user]
        for key, value in (settings or {}).items():
            args.append(f"--{key}={value}")
        for key, value in (params or {}).items():
            args.append(f"--param_{key}={value}")
        return args

    def execute(self, query: str, **kwargs: Any) -> str:
        return _run([*self._client(**kwargs), "-q", query])

    def execute_script(self, sql: str) -> None:
        _run([*self._client(), "--multiquery"], stdin=sql)

    def insert(self, table: str, rows: Iterable[dict[str, Any]]) -> None:
        payload = "\n".join(json.dumps(row) for row in rows)
        if not payload:
            return
        if table not in {"extorq.scan_runs", "extorq.finding_observations"}:
            raise ValueError(f"unexpected table {table}")
        _run([*self._client(), "-q", f"INSERT INTO {table} FORMAT JSONEachRow"], stdin=payload)

    def select(self, query: str, **kwargs: Any) -> list[dict[str, Any]]:
        out = self.execute(f"{query} FORMAT JSONEachRow", **kwargs)
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    def apply_migrations(self, steps: tuple[str, ...] = VARIANTS["0003"][1]) -> None:
        for step in steps:
            if step == "roles":
                for role in ROLES_0004:
                    self.execute(f"CREATE ROLE IF NOT EXISTS {role}")
            else:
                self.execute_script((MIGRATIONS / step).read_text(encoding="utf-8"))


def _container_running(name: str) -> bool:
    docker = _docker()
    if docker is None:
        return False
    proc = subprocess.run(
        [docker, "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def clickhouse_session(variant: str = "0003") -> Iterator[ClickHouse]:
    """Yield a ready ClickHouse with the variant's migrations applied; clean up what we started."""
    container, steps = VARIANTS[variant]
    docker = _docker() or "docker"
    started = False
    if not _container_running(container):
        _run(
            [
                docker,
                "run",
                "-d",
                "--rm",
                "--name",
                container,
                "--network",
                "none",
                "--memory",
                "1536m",
                "--ulimit",
                "nofile=262144:262144",
                IMAGE,
            ],
            timeout=120,
        )
        started = True
    ch = ClickHouse(container)
    try:
        deadline = time.monotonic() + 90
        while True:
            try:
                ch.execute("SELECT 1")
                break
            except RuntimeError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(1)
        ch.apply_migrations(steps)
        yield ch
    finally:
        if started:
            subprocess.run([docker, "rm", "-f", container], capture_output=True, timeout=60)


def unique_asset(prefix: str = "linux:c3-test") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"
