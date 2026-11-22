"""AI storage path against a real, throwaway ClickHouse (Docker; skipped without it).

Starts ``clickhouse/clickhouse-server:26.8.42.13`` as container ``extorq-ai-store-ch``
(label ``extorq.owner=ai``) on a random 127.0.0.1 port, applies migrations 0001 and 0004,
and exercises, with a fake Jev client (no network beyond the local container):

* C2's ``extorq.correlation.store`` (save + hash-verified load) via ``extorq.ai.context_source``;
* ``extorq.ai.store`` SQL (insert, list, reuse lookup, attempt counting, pending queue, health);
* ``AIService.request_triage`` and ``TriageWorker.run_cycle`` end to end.

All rows are SYNTHETIC (dataset contexts) and live only in the throwaway container,
which is removed afterwards. The admin password is random, passed through a 0600
env-file that is deleted right after start, and never printed.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from ai_fakes import answering_client, enabled_settings, jev_key, load_dataset_records

from extorq.ai import store
from extorq.ai.budget import BudgetGuard
from extorq.ai.context_source import load_latest_context
from extorq.ai.jev import TRIAGE_PROMPT_VERSION, JevTriageProvider
from extorq.ai.service import AIService
from extorq.ai.worker import TriageWorker
from extorq.contracts.ai import AIProvider, AIStatus, AITask
from extorq.contracts.common import HealthStatus
from extorq.contracts.context import InvestigationContext
from extorq.contracts.health import PipelineHealth
from extorq.contracts.identity import context_id as make_context_id

REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGE = "clickhouse/clickhouse-server:26.8.42.13"
CONTAINER = "extorq-ai-store-ch"
OWNER = "ai"
OWNER_LABEL = f"extorq.owner={OWNER}"
MIGRATIONS = ("0001_core_tables.sql", "0004_services.sql")
ROLE_RE = re.compile(r"\bTO\s+(extorq_role_[a-z_]+)")


def _docker() -> str | None:
    path = shutil.which("docker")
    if path is None:
        return None
    probe = subprocess.run(
        [path, "info", "--format", "{{.ServerVersion}}"],
        capture_output=True,
        timeout=20,
        check=False,
    )
    return path if probe.returncode == 0 else None


def _run(args: list[str], *, stdin: bytes | None = None, timeout: int = 120) -> str:
    proc = subprocess.run(args, input=stdin, capture_output=True, timeout=timeout, check=False)
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-1:]
        raise RuntimeError(f"{args[1]} failed: {tail}")
    return proc.stdout.decode("utf-8", "replace")


def _remove_own_stale(docker: str) -> None:
    out = _run(
        [docker, "ps", "-a", "--filter", f"name=^{CONTAINER}$", "--format",
         '{{.Names}} {{.Label "extorq.owner"}}']
    )  # fmt: skip
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0] == CONTAINER:
            if parts[1:] != [OWNER]:
                raise RuntimeError(f"{CONTAINER} exists but is not owned by agent {OWNER}")
            _run([docker, "rm", "-f", CONTAINER])


@pytest.fixture(scope="module")
def clickhouse() -> Iterator[Any]:
    docker = _docker()
    if docker is None:
        pytest.skip("Docker is not available")
    import clickhouse_connect

    _remove_own_stale(docker)
    password = secrets.token_urlsafe(24)
    with tempfile.TemporaryDirectory(prefix="extorq-ai-") as tmp:
        env_file = Path(tmp) / "ch.env"
        fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write("CLICKHOUSE_USER=aiadmin\n")
            handle.write(f"CLICKHOUSE_PASSWORD={password}\n")
            handle.write("CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1\n")
        _run(
            [docker, "run", "-d", "--name", CONTAINER, "--label", OWNER_LABEL,
             "--env-file", str(env_file), "-p", "127.0.0.1::8123",
             "--ulimit", "nofile=262144:262144", IMAGE],
            timeout=180,
        )  # fmt: skip
    try:
        port = int(
            _run([docker, "port", CONTAINER, "8123/tcp"]).strip().splitlines()[0].rsplit(":", 1)[1]
        )
        deadline = time.monotonic() + 90
        while True:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/ping", timeout=2) as r:
                    if r.read().strip() == b"Ok.":
                        break
            except (urllib.error.URLError, OSError, TimeoutError):
                pass
            if time.monotonic() > deadline:
                raise RuntimeError("throwaway ClickHouse did not become ready")
            time.sleep(0.5)
        migrations = [REPO_ROOT / "infra" / "clickhouse" / "migrations" / m for m in MIGRATIONS]
        roles = sorted({role for m in migrations for role in ROLE_RE.findall(m.read_text())})
        ddl = "".join(f"CREATE ROLE IF NOT EXISTS {role};\n" for role in roles)
        client_cmd = [docker, "exec", "-i", CONTAINER, "clickhouse-client", "--multiquery"]
        _run(client_cmd, stdin=ddl.encode("ascii"))
        for path in migrations:
            _run(client_cmd, stdin=path.read_bytes())
        client = clickhouse_connect.get_client(
            host="127.0.0.1",
            port=port,
            username="aiadmin",
            password=password,
            database="extorq",
            connect_timeout=10,
            send_receive_timeout=60,
            autogenerate_session_id=False,
        )
        yield client
        client.close()
    finally:
        subprocess.run(
            [docker, "rm", "-f", CONTAINER], capture_output=True, timeout=60, check=False
        )


def _store_ready(case_id: str) -> InvestigationContext:
    """A dataset context re-hashed with the correlation store's input-hash definition."""
    from extorq.correlation.builder import context_input_hash

    record = next(r for r in load_dataset_records() if r["case_id"] == case_id)
    ctx = InvestigationContext.model_validate(record["context"])
    digest = context_input_hash(ctx)
    return ctx.model_copy(
        update={"input_hash": digest, "context_id": make_context_id(ctx.alert_id, digest)}
    )


def _truncate(client: Any) -> None:
    for table in (
        "investigation_contexts",
        "context_relationships",
        "ai_assessments",
        "pipeline_health",
    ):
        client.command("TRUNCATE TABLE IF EXISTS {table:Identifier}", parameters={"table": table})


def test_context_round_trip_through_the_correlation_store(clickhouse: Any) -> None:
    from extorq.correlation.store import save_context

    _truncate(clickhouse)
    ctx = _store_ready("SSH-S1")
    save_context(clickhouse, ctx)
    loaded = load_latest_context(clickhouse, ctx.alert_id)
    assert loaded == ctx
    assert loaded is not None and loaded.services, "1.1 service summaries survive storage"
    assert load_latest_context(clickhouse, "f" * 32) is None


def test_assessment_sql_round_trip(clickhouse: Any) -> None:
    _truncate(clickhouse)
    ctx = _store_ready("K8S-B2")
    now = datetime.now(UTC).replace(microsecond=0)
    provider = JevTriageProvider(
        enabled_settings(),
        key=jev_key(),
        client_factory=lambda k, s: answering_client(),
        clock=lambda: now,
    )
    first = provider.assess(ctx, "system:ai-worker")
    store.save_assessment(clickhouse, first, requested_model="jev-1.14.0")
    store.save_assessment(clickhouse, first, requested_model="jev-1.14.0")  # duplicate insert
    listed = store.list_assessments(clickhouse, ctx.alert_id)
    assert listed == [first], "FINAL collapses the duplicate; rows round-trip exactly"
    assert store.count_attempts_since(clickhouse, AIProvider.JEV, now - timedelta(hours=1)) == 1
    assert store.count_attempts_since(clickhouse, AIProvider.JEV, now + timedelta(seconds=1)) == 0
    reuse = dict(
        alert_id=ctx.alert_id, provider=AIProvider.JEV, task=AITask.TRIAGE,
        prompt_version=TRIAGE_PROMPT_VERSION, context_input_hash=ctx.input_hash,
    )  # fmt: skip
    assert store.find_reusable(clickhouse, model="jev-1.14.0", **reuse) == first
    assert store.find_reusable(clickhouse, model="jev-9.9.9", **reuse) is None


def test_pending_queue_semantics(clickhouse: Any) -> None:
    from extorq.correlation.store import save_context

    _truncate(clickhouse)
    a, b = _store_ready("SSH-S1"), _store_ready("GH-B1")
    for ctx in (a, b):
        save_context(clickhouse, ctx.model_copy(update={"created_at": datetime.now(UTC)}))
    args: dict[str, Any] = dict(
        prompt_version=TRIAGE_PROMPT_VERSION, max_failed=2, backoff_seconds=0, max_age_hours=1
    )
    pending = store.pending_triage(clickhouse, limit=10, **args)
    assert {p.alert_id for p in pending} == {a.alert_id, b.alert_id}
    assert store.count_pending_triage(clickhouse, **args) == 2
    skip_a = [store.pending_key(a.alert_id, a.input_hash)]
    only_b = store.pending_triage(clickhouse, limit=10, exclude=skip_a, **args)
    assert [p.alert_id for p in only_b] == [b.alert_id]
    assert store.count_pending_triage(clickhouse, **args) == 2, "exclusion only pages the queue"

    now = datetime.now(UTC)
    ok = JevTriageProvider(
        enabled_settings(),
        key=jev_key(),
        client_factory=lambda k, s: answering_client(),
        clock=lambda: now,
    )
    store.save_assessment(clickhouse, ok.assess(a))  # success for a's current hash
    failing = JevTriageProvider(
        enabled_settings(),
        key=jev_key(),
        client_factory=lambda k, s: answering_client(sc=float("nan")),
        clock=lambda: now,
    )
    failed = failing.assess(b)
    assert failed.status is AIStatus.INVALID_OUTPUT
    store.save_assessment(clickhouse, failed)
    assert [p.alert_id for p in store.pending_triage(clickhouse, limit=10, **args)] == [b.alert_id]
    store.save_assessment(clickhouse, failing.assess(b))  # second failure hits max_failed=2
    assert store.pending_triage(clickhouse, limit=10, **args) == []
    # With a backoff, a recent failure is not retried yet.
    backoff = {**args, "max_failed": 5, "backoff_seconds": 3600}
    assert store.pending_triage(clickhouse, limit=10, **backoff) == []


def test_pipeline_health_insert(clickhouse: Any) -> None:
    _truncate(clickhouse)
    health = PipelineHealth(
        component="ai_worker",
        instance="test:1",
        reported_at=datetime.now(UTC),
        status=HealthStatus.OK,
        queue_depth=3,
        last_write_at=None,
        details={"provider": "typesafe-jev", "cycle_processed": 1},
    )
    store.save_pipeline_health(clickhouse, health)
    rows = clickhouse.query(
        "SELECT component, status, queue_depth, details FROM pipeline_health "
        "WHERE instance = {i:String}",
        parameters={"i": "test:1"},
    ).result_rows
    assert rows[0][:3] == ("ai_worker", "ok", 3)
    assert json.loads(rows[0][3])["cycle_processed"] == 1


def test_triage_service_end_to_end(clickhouse: Any) -> None:
    """``extorq ai triage``: one paid call, stored, then reused from storage."""
    from extorq.correlation.store import save_context

    _truncate(clickhouse)
    ctx = _store_ready("SSH-S3")
    save_context(clickhouse, ctx)
    client = answering_client()
    settings = enabled_settings()
    service = AIService(
        settings,
        read_client=clickhouse,
        write_client=clickhouse,
        jev=JevTriageProvider(settings, key=jev_key(), client_factory=lambda k, s: client),
    )
    first = service.request_triage(ctx.alert_id, "analyst:alice")
    assert first.status is AIStatus.OK and first.triage is not None
    second = service.request_triage(ctx.alert_id, "analyst:bob")
    assert second.assessment_id == first.assessment_id, "reused from storage"
    assert len(client.calls) == 1
    assert store.list_assessments(clickhouse, ctx.alert_id) == [first]


def test_worker_cycle_end_to_end(clickhouse: Any) -> None:
    from extorq.correlation.store import save_context

    _truncate(clickhouse)
    contexts = [_store_ready(cid) for cid in ("SSH-S2", "K8S-S1", "GH-S1")]
    for ctx in contexts:
        save_context(clickhouse, ctx.model_copy(update={"created_at": datetime.now(UTC)}))
    settings = enabled_settings(ai_worker_batch_size=2)
    worker = TriageWorker(
        read_client=clickhouse,
        write_client=clickhouse,
        settings=settings,
        provider=JevTriageProvider(
            settings, key=jev_key(), client_factory=lambda k, s: answering_client()
        ),
        guard=BudgetGuard(AIProvider.JEV, settings.jev_daily_cap),
        instance="test:worker",
    )
    first = worker.run_cycle()
    assert (first.queue_depth, first.processed, first.saved) == (3, 2, 2)
    second = worker.run_cycle()
    assert (second.queue_depth, second.processed, second.saved) == (1, 1, 1)
    third = worker.run_cycle()
    assert (third.queue_depth, third.processed) == (0, 0)
    worker.report(third)
    stored = {
        a.alert_id for ctx in contexts for a in store.list_assessments(clickhouse, ctx.alert_id)
    }
    assert stored == {ctx.alert_id for ctx in contexts}
    health = clickhouse.query(
        "SELECT status, written_total FROM pipeline_health WHERE instance = {i:String}",
        parameters={"i": "test:worker"},
    ).result_rows
    assert health == [("ok", 3)]


def test_worker_pages_past_a_tampered_context_at_the_head(clickhouse: Any) -> None:
    """A context failing C2's hash check (newest, so first in the queue) never stalls it."""
    from extorq.correlation.store import context_to_row, save_context

    _truncate(clickhouse)
    good = _store_ready("SSH-S2")
    save_context(
        clickhouse, good.model_copy(update={"created_at": datetime.now(UTC) - timedelta(minutes=1)})
    )
    bad = _store_ready("K8S-S1")
    row = context_to_row(bad.model_copy(update={"created_at": datetime.now(UTC)}))
    body = json.loads(row["body"])
    body["alert"]["summary"] = "tampered after hashing"
    row["body"] = json.dumps(body, sort_keys=True, separators=(",", ":"))
    clickhouse.insert("investigation_contexts", [list(row.values())], column_names=list(row))

    loads: list[str] = []

    def loader(client: Any, alert_id: str) -> InvestigationContext | None:
        loads.append(alert_id)
        return load_latest_context(client, alert_id)

    settings = enabled_settings(ai_worker_batch_size=1)
    worker = TriageWorker(
        read_client=clickhouse,
        write_client=clickhouse,
        settings=settings,
        provider=JevTriageProvider(
            settings, key=jev_key(), client_factory=lambda k, s: answering_client()
        ),
        guard=BudgetGuard(AIProvider.JEV, settings.jev_daily_cap),
        context_loader=loader,
        instance="test:poison",
    )
    first = worker.run_cycle()
    assert loads == [bad.alert_id, good.alert_id]
    assert (first.invalid, first.processed, first.saved) == (1, 1, 1)
    assert first.status is HealthStatus.DEGRADED
    second = worker.run_cycle()
    assert loads == [bad.alert_id, good.alert_id], "the tampered context is not loaded again"
    assert (second.queue_depth, second.processed, second.invalid) == (1, 0, 0)
    assert [a.alert_id for a in store.list_assessments(clickhouse, good.alert_id)] == [
        good.alert_id
    ]
    assert store.list_assessments(clickhouse, bad.alert_id) == []
