"""Findings lifecycle view tests (infra/clickhouse/migrations/0003_findings_views.sql).

Runs crafted scan histories against a real, ephemeral ClickHouse 26.8.42.13
(see scanners_ch_testlib). All rows are synthetic and isolated per test by a
unique asset id. Required semantics (PLAN / C3 task):

* success -> success without the finding           => resolved
* success -> failed                                 => unverified
* success -> partial without the finding            => unverified (never resolved)
* only partial                                      => unverified
* a different scope_hash never resolves
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from scanners_ch_testlib import (
    ClickHouse,
    clickhouse_session,
    docker_unavailable_reason,
    finding_row,
    scan_run_row,
    unique_asset,
)

from extorq.contracts import (
    FindingCategory,
    PackageRef,
    PostureFinding,
    Resource,
    ScanCoverage,
    ScanRun,
    ScanScope,
    ScanStatus,
    Severity,
)
from extorq.contracts.identity import finding_id, scope_hash

_SKIP = docker_unavailable_reason()
pytestmark = pytest.mark.skipif(_SKIP is not None, reason=_SKIP or "")

EXPECTED_COLUMNS = [
    "finding_id",
    "asset_id",
    "scanner",
    "scope_hash",
    "check_id",
    "category",
    "severity",
    "title",
    "resource_type",
    "resource_name",
    "resource_namespace",
    "resource_path",
    "package_name",
    "installed_version",
    "fixed_version",
    "cve_ids",
    "accepted_risk_reason",
    "first_observed_at",
    "last_observed_at",
    "last_scan_run_id",
    "last_success_at",
    "latest_scan_status",
    "latest_scan_at",
    "state",
]


@pytest.fixture(scope="module", params=["0003", "0005"])
def ch(request: pytest.FixtureRequest) -> Iterator[ClickHouse]:
    """Every scenario runs against the 0003 view and the 0005 (service-aware) view."""
    session = clickhouse_session(request.param)
    client = next(session)
    client.variant = request.param  # type: ignore[attr-defined]
    yield client
    session.close()  # runs the generator's cleanup


def _ch_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.") + f"{value.microsecond // 1000:03d}"


class History:
    """Builds a scan history for one asset and writes it like the pipeline would."""

    def __init__(
        self,
        ch: ClickHouse,
        *,
        scanner: str = "trivy",
        asset_id: str | None = None,
        base: datetime | None = None,
    ) -> None:
        self.ch = ch
        self.scanner = scanner
        self.asset_id = asset_id or unique_asset()
        now = datetime.now(UTC).replace(microsecond=0)
        self.base = base or (now - timedelta(hours=5))
        self.scans: dict[str, ScanRun] = {}

    @staticmethod
    def scope(name: str = "default") -> ScanScope:
        targets = [f"synthetic-target-{name}"]
        description = f"synthetic lifecycle test scope {name}"
        return ScanScope(
            targets=targets,
            description=description,
            scope_hash=scope_hash(targets, description),
        )

    def fid(self, key: str) -> str:
        return finding_id(self.asset_id, self.scanner, f"CVE-2099-{key}", f"pkg-{key}@1.0")

    def finding(
        self,
        key: str,
        run: ScanRun,
        *,
        severity: Severity = Severity.HIGH,
        fixed_version: str | None = "1.1",
        accepted_risk: str | None = None,
        service_id: str | None = None,
    ) -> PostureFinding:
        from extorq.contracts import AcceptedRisk

        observed = run.finished_at or (run.started_at + timedelta(seconds=30))
        return PostureFinding(
            finding_id=self.fid(key),
            scan_run_id=run.scan_run_id,
            asset_id=self.asset_id,
            scanner=self.scanner,
            check_id=f"CVE-2099-{key}",
            category=FindingCategory.VULNERABILITY,
            severity=severity,
            title=f"synthetic vulnerability {key}",
            resource=Resource(type="package", name=f"pkg-{key}", path="requirements.txt"),
            package=PackageRef(
                name=f"pkg-{key}", installed_version="1.0", fixed_version=fixed_version
            ),
            cve_ids=[f"CVE-2099-{key}"],
            service_id=service_id,
            observed_at=observed,
            accepted_risk=(
                AcceptedRisk(reason=accepted_risk, source="config:test") if accepted_risk else None
            ),
        )

    def scan(
        self,
        status: ScanStatus,
        minute: int,
        observed: Sequence[str] = (),
        *,
        scope: str = "default",
        started_at: datetime | None = None,
        duration_minutes: int = 2,
        overrides: dict[str, dict[str, Any]] | None = None,
        write_running_row: bool = True,
    ) -> ScanRun:
        started = started_at or (self.base + timedelta(minutes=minute))
        finished = (
            None if status is ScanStatus.RUNNING else started + timedelta(minutes=duration_minutes)
        )
        run_id = uuid.uuid4().hex
        common = {
            "scan_run_id": run_id,
            "scanner": self.scanner,
            "scanner_version": "0.0.0-synthetic",
            "asset_id": self.asset_id,
            "scope": self.scope(scope),
            "started_at": started,
            "producer_id": "scanner-runner",
        }
        running = ScanRun(**common, status=ScanStatus.RUNNING)
        rows = [scan_run_row(running)] if write_running_row else []
        final = running
        if status is not ScanStatus.RUNNING:
            final = ScanRun(
                **common,
                status=status,
                finished_at=finished,
                findings_count=len(observed),
                coverage=ScanCoverage(checks_total=1, checks_run=1),
                error=None if status is ScanStatus.SUCCEEDED else "synthetic failure",
            )
            rows.append(scan_run_row(final))
        findings = [self.finding(k, final, **(overrides or {}).get(k, {})) for k in observed]
        self.ch.insert("extorq.finding_observations", [finding_row(f) for f in findings])
        self.ch.insert("extorq.scan_runs", rows)
        self.scans[run_id] = final
        return final

    def rows(self, **kwargs: Any) -> list[dict[str, Any]]:
        return self.ch.select(
            "SELECT * FROM extorq.v_findings_current WHERE asset_id = {asset:String} "
            "ORDER BY scope_hash, finding_id",
            params={"asset": self.asset_id},
            **kwargs,
        )

    def by_key(self, *keys: str, scope: str = "default", **kwargs: Any) -> dict[str, dict]:
        wanted = {self.fid(k): k for k in keys}
        result: dict[str, dict] = {}
        sh = self.scope(scope).scope_hash
        for row in self.rows(**kwargs):
            if row["finding_id"] in wanted and row["scope_hash"] == sh:
                result[wanted[row["finding_id"]]] = row
        return result

    def state(self, key: str, scope: str = "default") -> str:
        return self.by_key(key, scope=scope)[key]["state"]


S, P, F, R = ScanStatus.SUCCEEDED, ScanStatus.PARTIAL, ScanStatus.FAILED, ScanStatus.RUNNING


def test_view_has_exactly_the_contract_columns(ch: ClickHouse) -> None:
    described = ch.select("DESCRIBE TABLE extorq.v_findings_current")
    expected = EXPECTED_COLUMNS + (["service_id"] if ch.variant == "0005" else [])  # type: ignore[attr-defined]
    assert [c["name"] for c in described] == expected
    types = {c["name"]: c["type"] for c in described}
    assert types["last_success_at"].startswith("Nullable(DateTime64(3")
    assert types["latest_scan_at"].startswith("Nullable(DateTime64(3")
    assert types["latest_scan_status"] == "Nullable(String)"
    assert types["cve_ids"] == "Array(String)"


# ── Required scenarios ──────────────────────────────────────────────────────────


def test_success_then_success_without_finding_resolves(ch: ClickHouse) -> None:
    h = History(ch)
    s1 = h.scan(S, 0, ["A", "B"])
    s2 = h.scan(S, 10, ["A"])
    rows = h.by_key("A", "B")
    assert rows["A"]["state"] == "open"
    assert rows["B"]["state"] == "resolved"
    assert rows["B"]["last_scan_run_id"] == s1.scan_run_id
    assert rows["A"]["last_scan_run_id"] == s2.scan_run_id
    for row in rows.values():
        assert row["latest_scan_status"] == "succeeded"
        assert row["last_success_at"] == _ch_time(s2.finished_at)  # type: ignore[arg-type]
        assert row["latest_scan_at"] == _ch_time(s2.finished_at)  # type: ignore[arg-type]


def test_success_then_failed_is_unverified(ch: ClickHouse) -> None:
    h = History(ch)
    s1 = h.scan(S, 0, ["A"])
    f2 = h.scan(F, 10, [])
    row = h.by_key("A")["A"]
    assert row["state"] == "unverified"
    assert row["latest_scan_status"] == "failed"
    assert row["latest_scan_at"] == _ch_time(f2.finished_at)  # type: ignore[arg-type]
    assert row["last_success_at"] == _ch_time(s1.finished_at)  # type: ignore[arg-type]


def test_success_then_partial_without_finding_is_never_resolved(ch: ClickHouse) -> None:
    h = History(ch)
    h.scan(S, 0, ["A", "B"])
    h.scan(P, 10, ["A"])
    rows = h.by_key("A", "B")
    assert rows["B"]["state"] == "unverified"
    assert rows["A"]["state"] == "unverified"
    assert {r["latest_scan_status"] for r in rows.values()} == {"partial"}


def test_only_partial_scans_are_unverified(ch: ClickHouse) -> None:
    h = History(ch)
    h.scan(P, 0, ["A"])
    h.scan(P, 10, [])
    row = h.by_key("A")["A"]
    assert row["state"] == "unverified"
    assert row["last_success_at"] is None
    assert row["latest_scan_status"] == "partial"


def test_only_failed_scan_with_observation_is_unverified(ch: ClickHouse) -> None:
    h = History(ch)
    h.scan(F, 0, ["A"])
    assert h.state("A") == "unverified"


def test_different_scope_hash_never_resolves(ch: ClickHouse) -> None:
    h = History(ch)
    h.scan(S, 0, ["A"], scope="x")
    h.scan(S, 10, [], scope="y")
    assert h.state("A", scope="x") == "open"
    assert h.by_key("A", scope="y") == {}
    # Observed under scope y too, then resolved there: scope x is unaffected.
    h.scan(S, 20, ["A"], scope="y")
    h.scan(S, 30, [], scope="y")
    assert h.state("A", scope="y") == "resolved"
    assert h.state("A", scope="x") == "open"


def test_other_scanner_or_asset_with_same_scope_never_resolves(ch: ClickHouse) -> None:
    h = History(ch, scanner="trivy")
    h.scan(S, 0, ["A"])
    other_scanner = History(ch, scanner="semgrep", asset_id=h.asset_id, base=h.base)
    other_scanner.scan(S, 10, [])
    other_asset = History(ch, scanner="trivy", base=h.base)
    other_asset.scan(S, 10, [])
    assert h.state("A") == "open"


# ── Further transitions ─────────────────────────────────────────────────────────


def test_single_success_is_open_with_latest_details(ch: ClickHouse) -> None:
    h = History(ch)
    s1 = h.scan(S, 0, ["A"])
    row = h.by_key("A")["A"]
    assert row["state"] == "open"
    assert row["check_id"] == "CVE-2099-A"
    assert row["category"] == "vulnerability"
    assert row["severity"] == "high"
    assert row["package_name"] == "pkg-A"
    assert row["installed_version"] == "1.0"
    assert row["fixed_version"] == "1.1"
    assert row["resource_type"] == "package"
    assert row["resource_path"] == "requirements.txt"
    assert row["resource_namespace"] is None
    assert row["cve_ids"] == ["CVE-2099-A"]
    assert row["accepted_risk_reason"] is None
    assert row["first_observed_at"] == row["last_observed_at"] == _ch_time(s1.finished_at)  # type: ignore[arg-type]
    assert row["scope_hash"] == h.scope().scope_hash
    assert row["scanner"] == "trivy"


def test_running_attempt_does_not_change_state(ch: ClickHouse) -> None:
    h = History(ch)
    h.scan(S, 0, ["A"])
    fresh = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)
    h.scan(R, 0, [], started_at=fresh)
    row = h.by_key("A")["A"]
    assert row["state"] == "open"
    assert row["latest_scan_status"] == "running"
    assert row["latest_scan_at"] == _ch_time(fresh)


def test_abandoned_running_scan_counts_as_failed(ch: ClickHouse) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    h = History(ch, base=now - timedelta(hours=8))
    h.scan(S, 0, ["A"])
    h.scan(R, 0, [], started_at=now - timedelta(hours=7))
    row = h.by_key("A")["A"]
    assert row["state"] == "unverified"
    assert row["latest_scan_status"] == "failed"
    current = ch.select(
        "SELECT status, effective_status FROM extorq.v_scan_runs_current "
        "WHERE asset_id = {asset:String} ORDER BY started_at",
        params={"asset": h.asset_id},
    )
    assert [(r["status"], r["effective_status"]) for r in current] == [
        ("succeeded", "succeeded"),
        ("running", "failed"),
    ]


def test_finding_reopens_after_resolution(ch: ClickHouse) -> None:
    h = History(ch)
    s1 = h.scan(S, 0, ["A"])
    h.scan(S, 10, [])
    assert h.state("A") == "resolved"
    s3 = h.scan(S, 20, ["A"])
    row = h.by_key("A")["A"]
    assert row["state"] == "open"
    assert row["first_observed_at"] == _ch_time(s1.finished_at)  # type: ignore[arg-type]
    assert row["last_observed_at"] == _ch_time(s3.finished_at)  # type: ignore[arg-type]


def test_resolved_stays_resolved_after_failed_attempt(ch: ClickHouse) -> None:
    h = History(ch)
    h.scan(S, 0, ["A"])
    h.scan(S, 10, [])
    h.scan(F, 20, [])
    row = h.by_key("A")["A"]
    assert row["state"] == "resolved"
    assert row["latest_scan_status"] == "failed"


def test_partial_observation_after_resolution_is_unverified(ch: ClickHouse) -> None:
    h = History(ch)
    h.scan(S, 0, ["A"])
    h.scan(S, 10, [])
    h.scan(P, 20, ["A"])
    assert h.state("A") == "unverified"


def test_success_failed_success_is_open(ch: ClickHouse) -> None:
    h = History(ch)
    h.scan(S, 0, ["A"])
    h.scan(F, 10, [])
    h.scan(S, 20, ["A"])
    assert h.state("A") == "open"


def test_failed_then_success_without_finding_resolves(ch: ClickHouse) -> None:
    h = History(ch)
    h.scan(S, 0, ["A"])
    h.scan(F, 10, [])
    h.scan(S, 20, [])
    assert h.state("A") == "resolved"


def test_partial_reobservation_after_success_is_unverified(ch: ClickHouse) -> None:
    h = History(ch)
    h.scan(S, 0, ["A"])
    h.scan(P, 10, ["A"])
    assert h.state("A") == "unverified"


def test_observation_without_known_scan_run_is_unverified(ch: ClickHouse) -> None:
    h = History(ch)
    s1 = h.scan(S, 0, ["A"])
    orphan_run = s1.model_copy(update={"scan_run_id": uuid.uuid4().hex})
    ch.insert("extorq.finding_observations", [finding_row(h.finding("B", orphan_run))])
    rows = {r["finding_id"]: r for r in h.rows()}
    orphan = rows[h.fid("B")]
    assert orphan["state"] == "unverified"
    assert orphan["scope_hash"] == ""
    assert orphan["latest_scan_status"] is None
    assert orphan["latest_scan_at"] is None
    assert orphan["last_success_at"] is None
    assert rows[h.fid("A")]["state"] == "open"


def test_duplicate_rows_collapse(ch: ClickHouse) -> None:
    h = History(ch)
    s1 = h.scan(S, 0, ["A", "B"])
    s2 = h.scan(S, 10, ["A"])
    # Re-deliver everything (at-least-once pipeline): same logical rows again.
    for run in (s1, s2):
        ch.insert("extorq.scan_runs", [scan_run_row(run)])
    ch.insert(
        "extorq.finding_observations",
        [
            finding_row(h.finding("A", s1)),
            finding_row(h.finding("B", s1)),
            finding_row(h.finding("A", s2)),
        ],
    )
    rows = h.rows()
    assert len(rows) == 2
    states = {r["finding_id"]: r["state"] for r in rows}
    assert states == {h.fid("A"): "open", h.fid("B"): "resolved"}


def test_latest_observation_wins_even_when_null(ch: ClickHouse) -> None:
    h = History(ch)
    h.scan(S, 0, ["A"], overrides={"A": {"severity": Severity.HIGH, "fixed_version": "1.1"}})
    h.scan(
        S,
        10,
        ["A"],
        overrides={
            "A": {
                "severity": Severity.CRITICAL,
                "fixed_version": None,
                "accepted_risk": "synthetic accepted risk",
            }
        },
    )
    row = h.by_key("A")["A"]
    assert row["severity"] == "critical"
    assert row["fixed_version"] is None
    assert row["accepted_risk_reason"] == "synthetic accepted risk"


def test_join_use_nulls_does_not_change_results(ch: ClickHouse) -> None:
    h = History(ch)
    s1 = h.scan(S, 0, ["A", "B"])
    h.scan(S, 10, ["A"])
    h.scan(F, 20, [])
    orphan_run = s1.model_copy(update={"scan_run_id": uuid.uuid4().hex})
    ch.insert("extorq.finding_observations", [finding_row(h.finding("C", orphan_run))])
    default = h.rows()
    with_nulls = h.rows(settings={"join_use_nulls": "1"})
    assert default == with_nulls
    assert {r["state"] for r in default} == {"unverified", "resolved"}


def test_readonly_session_can_query_views(ch: ClickHouse) -> None:
    h = History(ch)
    h.scan(S, 0, ["A"])
    rows = h.rows(settings={"readonly": "1"})
    assert [r["state"] for r in rows] == ["open"]
    count = ch.execute("SELECT count() FROM extorq.v_scan_runs_current", settings={"readonly": "1"})
    assert int(count.strip()) >= 1


def test_scan_runs_current_collapses_running_and_terminal_rows(ch: ClickHouse) -> None:
    h = History(ch)
    s1 = h.scan(S, 0, ["A"])
    rows = ch.select(
        "SELECT scan_run_id, status, effective_status, findings_count, finished_at "
        "FROM extorq.v_scan_runs_current WHERE asset_id = {asset:String}",
        params={"asset": h.asset_id},
    )
    assert rows == [
        {
            "scan_run_id": s1.scan_run_id,
            "status": "succeeded",
            "effective_status": "succeeded",
            "findings_count": 1,
            "finished_at": _ch_time(s1.finished_at),  # type: ignore[arg-type]
        }
    ]


def test_views_use_invoker_security(ch: ClickHouse) -> None:
    """A user granted only the view cannot read through it (no privilege widening)."""
    user = f"c3_view_probe_{uuid.uuid4().hex[:8]}"
    ch.execute(f"CREATE USER {user} IDENTIFIED WITH no_password")
    try:
        ch.execute(f"GRANT SELECT ON extorq.v_findings_current TO {user}")
        with pytest.raises(RuntimeError, match=r"ACCESS_DENIED|Not enough privileges"):
            ch.execute("SELECT count() FROM extorq.v_findings_current", user=user)
        ch.execute(f"GRANT SELECT ON extorq.scan_runs TO {user}")
        ch.execute(f"GRANT SELECT ON extorq.finding_observations TO {user}")
        out = ch.execute("SELECT count() FROM extorq.v_findings_current", user=user)
        assert int(out.strip()) >= 0
    finally:
        ch.execute(f"DROP USER IF EXISTS {user}")


# ── 0005: service attribution (contract 1.1) ────────────────────────────────────


def _only_0005(ch: ClickHouse) -> None:
    if ch.variant != "0005":  # type: ignore[attr-defined]
        pytest.skip("service_id exists from migration 0005 on")


SVC = "8ae2e115bc4a7a7c2cf3ed07ee5cb827"  # synthetic: identity.service_id(...) shape


def test_service_id_column_type(ch: ClickHouse) -> None:
    _only_0005(ch)
    described = {
        c["name"]: c["type"] for c in ch.select("DESCRIBE TABLE extorq.v_findings_current")
    }
    assert described["service_id"] == "Nullable(String)"


def test_service_id_follows_latest_observation(ch: ClickHouse) -> None:
    _only_0005(ch)
    h = History(ch)
    h.scan(S, 0, ["A", "B"], overrides={"A": {"service_id": SVC}})
    rows = h.by_key("A", "B")
    assert rows["A"]["service_id"] == SVC
    assert rows["B"]["service_id"] is None
    # next scan without attribution evidence: the latest observation (NULL) wins
    h.scan(S, 10, ["A", "B"])
    assert h.by_key("A")["A"]["service_id"] is None
    h.scan(S, 20, ["A"], overrides={"A": {"service_id": SVC}})
    rows = h.by_key("A", "B")
    assert rows["A"]["service_id"] == SVC and rows["A"]["state"] == "open"
    assert rows["B"]["state"] == "resolved"


def test_service_findings_query(ch: ClickHouse) -> None:
    _only_0005(ch)
    h = History(ch)
    h.scan(S, 0, ["A", "B"], overrides={"A": {"service_id": SVC}})
    rows = ch.select(
        "SELECT finding_id, state FROM extorq.v_findings_current "
        "WHERE asset_id = {asset:String} AND service_id = {svc:String}",
        params={"asset": h.asset_id, "svc": SVC},
        settings={"readonly": "1"},
    )
    assert rows == [{"finding_id": h.fid("A"), "state": "open"}]


def test_grants_survive_create_or_replace_and_reapply_is_idempotent(ch: ClickHouse) -> None:
    _only_0005(ch)
    from scanners_ch_testlib import MIGRATIONS

    ch.execute("GRANT SELECT ON extorq.v_findings_current TO extorq_role_api_ro")
    before = ch.execute("SHOW GRANTS FOR extorq_role_api_ro")
    ch.execute_script((MIGRATIONS / "0005_findings_services.sql").read_text(encoding="utf-8"))
    ch.execute_script((MIGRATIONS / "0005_findings_services.sql").read_text(encoding="utf-8"))
    after = ch.execute("SHOW GRANTS FOR extorq_role_api_ro")
    assert "v_findings_current" in before
    assert "GRANT SELECT ON extorq.v_findings_current TO extorq_role_api_ro" in after
    described = [c["name"] for c in ch.select("DESCRIBE TABLE extorq.v_findings_current")]
    assert described[-1] == "service_id"


def test_migration_runner_splits_0005_statements() -> None:
    from scanners_ch_testlib import MIGRATIONS

    from extorq.storage.migrate import split_statements

    text = (MIGRATIONS / "0005_findings_services.sql").read_text(encoding="utf-8")
    statements = split_statements(text)
    assert len(statements) == 4
    assert statements[0].startswith("CREATE OR REPLACE VIEW extorq.v_findings_current")
    assert all(
        s.startswith("GRANT SELECT ON extorq.v_scan_runs_current TO ") for s in statements[1:]
    )


def test_scan_runs_view_grant_does_not_widen_privileges(ch: ClickHouse) -> None:
    _only_0005(ch)
    user = f"c3_grafana_probe_{uuid.uuid4().hex[:8]}"
    ch.execute(f"CREATE USER {user} IDENTIFIED WITH no_password")
    try:
        ch.execute(f"GRANT extorq_role_grafana TO {user}")
        ch.execute(f"SET DEFAULT ROLE extorq_role_grafana TO {user}")
        # 0004/0005 grant the view, but the base table grant (from 0002) is missing here
        with pytest.raises(RuntimeError, match=r"ACCESS_DENIED|Not enough privileges"):
            ch.execute("SELECT count() FROM extorq.v_scan_runs_current", user=user)
        ch.execute("GRANT SELECT ON extorq.scan_runs TO extorq_role_grafana")  # as 0002 does
        assert int(ch.execute("SELECT count() FROM extorq.v_scan_runs_current", user=user)) >= 0
    finally:
        ch.execute(f"DROP USER IF EXISTS {user}")
