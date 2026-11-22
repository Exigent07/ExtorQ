"""Clean-slate reset of ExtorQ's ClickHouse data (``extorq data counts | reset``).

The operator entry point is ``make reset-data`` (``scripts/reset_data.py``): it stops the
collectors and the pipeline services first and then runs ``extorq data reset --yes`` in a
one-off ``migrate`` container, the only service that holds the ``extorq_admin`` password.
This module never decides *when* a reset is safe; it only does the ClickHouse part.

Rules:

* Only the tables in :data:`DATA_TABLES` (plus :data:`LEGACY_TABLES` while they still
  exist) are truncated. The list is explicit on purpose: a table this module does not know
  is reported as ``unknown`` and left alone, never truncated by pattern.
  ``tests/unit/platform/test_platform_reset.py`` replays the migrations and fails when a
  table is created that is neither listed here nor protected.
* ``schema_migrations`` (the migration ledger) is protected. Users, roles, quotas, settings
  profiles and grants are access entities, not tables, and are never touched.
* Row counts are ``system.tables.total_rows``: physical rows in active parts. For
  ReplacingMergeTree tables this includes duplicates that are not merged yet, i.e. exactly
  what TRUNCATE removes. Only counts are reported, never row contents.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

DATABASE = "extorq"

#: Every table that holds collected, derived or analyst data (schema 2.0). Order is the
#: order of truncation and of the printed report: raw telemetry, detection output,
#: inventory and posture, investigation and AI, analyst state, then pipeline bookkeeping.
DATA_TABLES: tuple[str, ...] = (
    "events",
    "alerts",
    "alert_evidence",
    "rule_runs",
    "detection_rules",
    "assets",
    "inventory_items",
    "services",
    "service_instances",
    "scan_runs",
    "finding_observations",
    "investigation_contexts",
    "context_relationships",
    "ai_assessments",
    "analyst_state",
    "analyst_actions",
    "collector_health",
    "pipeline_health",
    "ingest_quarantine",
    "ingest_audit",
)

#: Tables of removed features, truncated only while they still exist. ``simulation_runs``
#: is dropped by migration 0008 (schema 2.0 has no simulation category); a database where
#: 0008 is not applied yet still has it and must not keep its rows across a clean slate.
LEGACY_TABLES: tuple[str, ...] = ("simulation_runs",)

#: Never truncated: without the ledger the migration runner would re-apply every migration.
PROTECTED_TABLES: frozenset[str] = frozenset({"schema_migrations"})

#: Table identifiers are interpolated into TRUNCATE (DDL cannot take parameters), so they
#: must also match this pattern in addition to the allow-lists above.
_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")

#: Engines that hold no rows of their own (views); they are never counted or truncated.
_VIEW_ENGINES = ("View", "MaterializedView", "LiveView", "WindowView")

EXIT_OK = 0
EXIT_ROWS_REMAIN = 1
EXIT_NOT_CONFIRMED = 2


class ResetError(RuntimeError):
    """A reset precondition failed (message never contains row data or secrets)."""


@dataclass(frozen=True)
class ResetPlan:
    """Which tables a reset truncates, given the tables that exist in the database."""

    #: Listed data tables (and legacy tables) that exist: truncated, in this order.
    truncate: tuple[str, ...]
    #: Listed data tables that do not exist (migrations not applied?): nothing to do.
    missing: tuple[str, ...]
    #: Tables in the database this module does not know: reported and left alone.
    unknown: tuple[str, ...]
    #: Protected tables that exist: never truncated.
    protected: tuple[str, ...]


def plan_reset(existing: Iterable[str]) -> ResetPlan:
    """Pure: decide what to truncate from the names of the existing tables."""
    present = set(existing)
    known = {*DATA_TABLES, *LEGACY_TABLES, *PROTECTED_TABLES}
    return ResetPlan(
        truncate=tuple(t for t in (*DATA_TABLES, *LEGACY_TABLES) if t in present),
        missing=tuple(t for t in DATA_TABLES if t not in present),
        unknown=tuple(sorted(present - known)),
        protected=tuple(sorted(present & PROTECTED_TABLES)),
    )


def _checked_identifier(table: str) -> str:
    """Defence in depth before interpolation: allow-listed AND a plain identifier."""
    if table not in DATA_TABLES and table not in LEGACY_TABLES:
        raise ResetError(f"refusing to truncate a table outside the allow-list: {table!r}")
    if not _IDENTIFIER.match(table):
        raise ResetError(f"refusing to truncate a table with an unexpected name: {table!r}")
    return table


def table_rows(client: Any) -> dict[str, int]:
    """``{table: physical rows}`` for every table (not view) in :data:`DATABASE`."""
    result = client.query(
        "SELECT name, total_rows FROM system.tables "
        "WHERE database = {database:String} AND NOT is_temporary "
        "AND engine NOT IN {views:Array(String)} ORDER BY name",
        parameters={"database": DATABASE, "views": list(_VIEW_ENGINES)},
    )
    return {str(name): int(total or 0) for name, total in result.result_rows}


def truncate_tables(client: Any, plan: ResetPlan) -> None:
    """TRUNCATE every table of ``plan.truncate`` (synchronous for MergeTree tables)."""
    for table in plan.truncate:
        statement = f"TRUNCATE TABLE IF EXISTS {DATABASE}.{_checked_identifier(table)}"
        client.command(statement)  # extorq: sql-reviewed allow-listed table identifier, no values


@dataclass(frozen=True)
class ResetReport:
    """Counts-only outcome of :func:`reset` (serialised as one JSON line by the CLI)."""

    database: str
    before: dict[str, int]
    after: dict[str, int]
    truncated: tuple[str, ...]
    missing: tuple[str, ...]
    unknown: tuple[str, ...]
    protected: tuple[str, ...]

    @property
    def rows_remaining(self) -> dict[str, int]:
        """Truncated tables that hold rows again (a writer was still running)."""
        return {t: self.after.get(t, 0) for t in self.truncated if self.after.get(t, 0)}

    def to_json(self) -> str:
        data = asdict(self)
        data["rows_remaining"] = self.rows_remaining
        return json.dumps(data, sort_keys=True, separators=(",", ":"))


def reset(client: Any) -> ResetReport:
    """Count, truncate the planned tables, count again. The caller stops writers first."""
    before = table_rows(client)
    plan = plan_reset(before)
    truncate_tables(client, plan)
    after = table_rows(client)
    return ResetReport(
        database=DATABASE,
        before=before,
        after=after,
        truncated=plan.truncate,
        missing=plan.missing,
        unknown=plan.unknown,
        protected=plan.protected,
    )


def counts_json(counts: Mapping[str, int]) -> str:
    """One JSON line ``{"database": ..., "tables": {table: rows}}`` (counts only)."""
    return json.dumps(
        {"database": DATABASE, "tables": dict(counts)}, sort_keys=True, separators=(",", ":")
    )


def main(*, confirm: bool, counts_only: bool = False) -> int:
    """``extorq data counts`` / ``extorq data reset --yes`` (admin identity).

    Prints exactly one JSON line on stdout (counts only), so callers can parse it.
    Exit codes: 0 done, 1 rows remain in a truncated table after the reset (a writer was
    still running), 2 ``reset`` without ``--yes``.
    """
    from extorq.storage.clickhouse import get_client

    if not counts_only and not confirm:
        print(
            json.dumps({"error": "refusing to truncate without --yes (destructive)"}),
            flush=True,
        )
        return EXIT_NOT_CONFIRMED
    client = get_client("admin", database=DATABASE)
    try:
        if counts_only:
            print(counts_json(table_rows(client)), flush=True)
            return EXIT_OK
        report = reset(client)
    finally:
        client.close()
    print(report.to_json(), flush=True)
    return EXIT_ROWS_REMAIN if report.rows_remaining else EXIT_OK
