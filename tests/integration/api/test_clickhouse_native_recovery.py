"""Exercise native archival on one disposable, isolated ClickHouse server."""

from __future__ import annotations

import uuid
from contextlib import closing

import pytest
from api_ch_harness import REPO_ROOT, EphemeralClickHouse, unavailable_reason

from extorq.storage.migrate import SCHEMA_MIGRATIONS_DDL
from extorq.storage.recovery import native_archive

pytestmark = pytest.mark.integration


def test_native_recovery_keeps_evidence_and_migration_ledger() -> None:
    reason = unavailable_reason()
    if reason:
        pytest.skip(reason)
    server = EphemeralClickHouse(
        server_config=REPO_ROOT / "infra/clickhouse/config.d/10-extorq-server.xml"
    )
    archive = f"extorq-{uuid.uuid4().hex}.zip"
    schema = (
        """
    CREATE DATABASE extorq;
    CREATE TABLE extorq.events (event_id String) ENGINE MergeTree ORDER BY event_id;
    CREATE TABLE extorq.alert_evidence (alert_id String, event_id String)
    ENGINE MergeTree ORDER BY (alert_id, event_id);
    """
        + SCHEMA_MIGRATIONS_DDL
        + """;
    INSERT INTO extorq.schema_migrations VALUES
      ('0009', 'synthetic', 'synthetic-checksum', now64(3), 0, 'recovery-test');
    """
    )
    try:
        server.start()
        server.sql(schema)
        server.sql(
            """
            INSERT INTO extorq.events VALUES ('synthetic-event');
            INSERT INTO extorq.alert_evidence VALUES ('synthetic-alert', 'synthetic-event');
            """
        )
        with closing(server.client("default", database="default")) as admin:
            backup = native_archive(admin, archive, restore=False)
            # Only the randomly named, throwaway server created above is mutated.
            server.sql("DROP DATABASE extorq SYNC")
            server.sql(schema)
            restored = native_archive(
                admin, archive, restore=True, expected_schema=backup["schema_sha256"]
            )
            assert restored["tables"] == backup["tables"]
            assert restored["migrations"] == backup["migrations"]
            evidence = admin.query(
                """
                SELECT ae.alert_id, ev.event_id FROM extorq.alert_evidence AS ae
                INNER JOIN extorq.events AS ev ON ev.event_id = ae.event_id
                """
            )
            assert evidence.result_rows == [("synthetic-alert", "synthetic-event")]
    finally:
        server.stop()
