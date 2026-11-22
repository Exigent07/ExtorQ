"""Asset lifecycle, the response cache and migration 0007 on a real, throwaway ClickHouse 26.8.

Runs with ``-m integration``. Own container (api_ch_harness: real migrations 0001-0006 and
the real 0002 roles/profiles), the shared SYNTHETIC dataset plus a SYNTHETIC "mechanics
test" repository that stopped reporting three days ago, so the lifecycle SQL inputs
(``asset_last_events`` with the asset type, ``finding_severity_counts`` exclusions) and
the endpoints run against real rows. The quota test applies 0002's quota and 0007 to a
user created only inside this container. Nothing touches the shared stack.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from api_ch_harness import (
    BATCH,
    MIGRATIONS,
    PRODUCER,
    Dataset,
    EphemeralClickHouse,
    seed,
    unavailable_reason,
)
from fastapi.testclient import TestClient

from extorq.api.app import create_app
from extorq.api.integrations import PlatformIntegrations
from extorq.api.repository import ClickHouseRepository, ClientProvider
from extorq.api.settings import ApiSettings
from extorq.contracts import Asset, CollectorHealth, PostureFinding, ScanRun, SecurityEvent
from extorq.contracts.identity import event_id, finding_id, scope_hash, stable_id
from extorq.storage import rows
from extorq.storage.migrate import split_statements

pytestmark = pytest.mark.integration

RETIRED = "github:synthetic-octo/hello-world"


def _insert(client: Any, table: str, data: list[dict[str, Any]]) -> None:
    columns = list(data[0])
    client.insert(table, [[row[c] for c in columns] for row in data], column_names=columns)


def seed_retired(admin: Any, ds: Dataset) -> str:
    """A repository whose one-off collector last reported 3 days ago (SYNTHETIC)."""
    n = ds.now
    gone = n - timedelta(days=3)
    asset = Asset(
        asset_id=RETIRED,
        asset_type="github_repository",
        name="synthetic-octo/hello-world",
        first_seen=n - timedelta(days=5),
        last_seen=gone,
        observed_by="synthetic-mechanics",
    )
    _insert(admin, "assets", [rows.asset_to_row(asset, producer_id=PRODUCER, ingested_at=n)])
    health = CollectorHealth(
        collector_id="synthetic-mechanics",
        collector_type="synthetic",
        asset_id=RETIRED,
        source_types=["github.api"],
        status="ok",
        reported_at=gone,
        last_success_at=gone,
        collector_version="0.0.0",
        interval_seconds=120,
    )
    _insert(
        admin,
        "collector_health",
        [rows.collector_health_to_row(health, producer_id=PRODUCER, ingested_at=n)],
    )
    event = SecurityEvent(
        event_id=event_id("github.api", RETIRED, "synthetic:retired"),
        event_type="github.workflow.modified",
        category="ci_cd",
        asset_id=RETIRED,
        asset_type="github_repository",
        source={
            "source_type": "github.api",
            "collector_id": "synthetic-mechanics",
            "collector_version": "0.0.0",
            "collection_method": "api_poll",
        },
        event_time=gone,
        outcome="success",
        message="synthetic retired",
        provenance={"parser": "synthetic-parser", "parser_version": "0"},
    )
    _insert(
        admin,
        "events",
        [rows.event_to_row(event, producer_id=PRODUCER, batch_id=BATCH, ingested_at=gone)],
    )
    scope = scope_hash(["/"], "synthetic retired")
    scan = ScanRun(
        scan_run_id=stable_id("scan.synthetic-retired", 0),
        scanner="synthetic-posture",
        scanner_version="0.0.0",
        asset_id=RETIRED,
        scope={"targets": ["/"], "description": "synthetic", "scope_hash": scope},
        started_at=gone,
        finished_at=gone + timedelta(minutes=1),
        status="succeeded",
        producer_id="scanner-runner",
    )
    _insert(admin, "scan_runs", [rows.scan_run_to_row(scan, producer_id=PRODUCER, ingested_at=n)])
    finding = PostureFinding(
        finding_id=finding_id(RETIRED, "synthetic-posture", "synthetic.check.retired", "repo"),
        scan_run_id=scan.scan_run_id,
        asset_id=RETIRED,
        scanner="synthetic-posture",
        check_id="synthetic.check.retired",
        category="misconfiguration",
        severity="high",
        title="synthetic retired finding",
        observed_at=gone + timedelta(seconds=30),
    )
    _insert(
        admin,
        "finding_observations",
        [rows.finding_to_row(finding, producer_id=PRODUCER, ingested_at=n)],
    )
    return finding.finding_id


@pytest.fixture(scope="module")
def clickhouse() -> Iterator[EphemeralClickHouse]:
    reason = unavailable_reason()
    if reason:
        pytest.skip(reason)
    ch = EphemeralClickHouse()
    try:
        ch.start()
        ch.migrate()
        yield ch
    finally:
        ch.stop()


@pytest.fixture(scope="module")
def dataset(clickhouse: EphemeralClickHouse) -> Dataset:
    admin = clickhouse.client("default")
    ds = seed(admin, datetime.now(UTC))
    seed_retired(admin, ds)
    return ds


@pytest.fixture(scope="module")
def repo(clickhouse: EphemeralClickHouse, dataset: Dataset) -> ClickHouseRepository:
    reader = clickhouse.client("d1_api_ro")
    writer = clickhouse.client("d1_api_writer")
    return ClickHouseRepository(
        ClientProvider("api_ro", lambda _role: reader),
        ClientProvider("api_writer", lambda _role: writer),
        lifecycle_cache_seconds=0,
    )


@pytest.fixture(scope="module")
def client(repo: ClickHouseRepository, tmp_path_factory: pytest.TempPathFactory) -> TestClient:
    token = secrets.token_urlsafe(32)
    path: Path = tmp_path_factory.mktemp("api-data") / "token"
    path.write_text(token, encoding="utf-8")
    app = create_app(
        settings=ApiSettings(service_token_file=path),  # production defaults (cache on)
        repository=repo,
        integrations=PlatformIntegrations(),
    )
    test_client = TestClient(app)
    test_client.headers.update(
        {"Authorization": f"Bearer {token}", "X-ExtorQ-User": "viewer", "X-ExtorQ-Role": "viewer"}
    )
    return test_client


def test_lifecycle_inputs_from_real_sql(repo: ClickHouseRepository, dataset: Dataset) -> None:
    activity = {r["asset_id"]: r for r in repo.asset_last_events([])}
    assert activity[RETIRED]["asset_type"] == "github_repository"
    assert activity[RETIRED]["last_event_at"] == dataset.now - timedelta(days=3)
    assert activity[dataset.linux]["asset_type"] == "linux_host"
    assert [r["asset_id"] for r in repo.asset_last_events([RETIRED])] == [RETIRED]

    everything, lifecycle = repo.finding_severity_counts("")
    without, lifecycle_without = repo.finding_severity_counts("", [RETIRED])
    assert lifecycle is True and lifecycle_without is True

    def high_open(counts: list[dict[str, Any]]) -> int:
        return sum(
            int(c["findings"]) for c in counts if c["severity"] == "high" and c["state"] == "open"
        )

    assert high_open(everything) == high_open(without) + 1
    assert repo.finding_severity_counts("", [dataset.linux, RETIRED])[0] == []


def test_asset_endpoints_leave_the_retired_repository_out(
    client: TestClient, dataset: Dataset
) -> None:
    listed = client.get("/api/v1/assets").json()
    assert RETIRED not in {i["asset_id"] for i in listed["items"]}
    assert listed["retired_excluded"] == 1
    full = client.get("/api/v1/assets", params={"include_retired": "true"}).json()
    retired = next(i for i in full["items"] if i["asset_id"] == RETIRED)
    assert retired["lifecycle_state"] == "retired"
    assert retired["lifecycle_reason"].startswith("no collector covering it has reported")
    assert {i["lifecycle_state"] for i in full["items"] if i["asset_id"] != RETIRED} == {"active"}
    detail = client.get(f"/api/v1/assets/{quote(RETIRED, safe='')}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["asset"]["lifecycle_state"] == "retired"
    assert [(c["collector_id"], c["lifecycle_state"]) for c in body["collectors"]] == [
        ("synthetic-mechanics", "retired")
    ]


def test_overview_and_health_rollups_on_real_rows(client: TestClient, dataset: Dataset) -> None:
    overview = client.get("/api/v1/overview").json()
    assert overview["lifecycle"]["retired_asset_ids"] == [RETIRED]
    github = next(c for c in overview["asset_coverage"] if c["asset_type"] == "github_repository")
    assert (github["assets_total"], github["assets_retired"], github["status"]) == (1, 1, "stale")
    assert overview["collection_health"]["collectors_retired"] == 1
    assert overview["collection_health"]["collectors_total"] == 2
    full = client.get("/api/v1/overview", params={"include_retired": "true"}).json()
    high = overview["open_findings"]["counts"]["high"]
    assert full["open_findings"]["counts"]["high"] == high + 1
    assert full["collection_health"]["collectors_total"] == 3

    health = client.get("/api/v1/health").json()
    assert {c["collector_id"] for c in health["collectors"]} == {
        "synthetic-linux",
        "synthetic-github",
    }
    assert health["collectors_retired"] == 1
    listed = client.get("/api/v1/health", params={"include_retired": "true"}).json()
    states = {c["collector_id"]: c["lifecycle_state"] for c in listed["collectors"]}
    assert states["synthetic-mechanics"] == "retired"


def test_second_read_within_the_ttl_is_a_cache_hit(client: TestClient) -> None:
    first = client.get("/api/v1/rules")
    second = client.get("/api/v1/rules")
    assert first.headers["X-ExtorQ-Cache"] == "miss"
    assert second.headers["X-ExtorQ-Cache"] == "hit"
    assert first.json() == second.json()


# ── migration 0007 ────────────────────────────────────────────────────────────────


def _quota(clickhouse: EphemeralClickHouse) -> tuple[list[str], str]:
    limits = clickhouse.sql(
        "SELECT duration, max_queries, max_errors, max_result_rows, max_read_rows, "
        "max_execution_time FROM system.quota_limits WHERE quota_name = 'extorq_api_quota' "
        "FORMAT TSV"
    )
    owner = clickhouse.sql(
        "SELECT keys, apply_to_list FROM system.quotas WHERE name = 'extorq_api_quota' FORMAT TSV"
    )
    return limits.strip().split("\t"), owner.strip()


def test_0007_raises_only_the_query_limit_and_is_idempotent(
    clickhouse: EphemeralClickHouse,
) -> None:
    rbac = split_statements((MIGRATIONS / "0002_rbac.sql").read_text(encoding="utf-8"))
    (create_quota,) = [st for st in rbac if "CREATE QUOTA IF NOT EXISTS extorq_api_quota" in st]
    clickhouse.sql(
        "CREATE USER IF NOT EXISTS extorq_api_ro IDENTIFIED WITH no_password;\n"
        + create_quota
        + ";"
    )
    before, owner = _quota(clickhouse)
    assert before == ["60", "1200", "300", "50000000", "5000000000", "600"]
    assert owner == "['user_name']\t['extorq_api_ro']"

    migration = (MIGRATIONS / "0007_api_quota.sql").read_text(encoding="utf-8")
    assert len(split_statements(migration)) == 1
    for _ in range(2):  # idempotent
        clickhouse.sql(migration)
        after, owner_after = _quota(clickhouse)
        assert after == ["60", "6000", "300", "50000000", "5000000000", "600"]
        assert owner_after == owner
