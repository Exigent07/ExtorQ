"""Shared fixtures for the rule test harness (ephemeral ClickHouse in Docker).

The container ``extorq-c2-rules-ch`` is started once per session and always
removed afterwards. Tests are skipped (not failed) when Docker is unavailable.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from extorq.detection import harness


@pytest.fixture(scope="session")
def clickhouse() -> Iterator[harness.EphemeralClickHouse]:
    if not harness.docker_available():
        pytest.skip("Docker is not available: rule harness tests need an ephemeral ClickHouse")
    with harness.EphemeralClickHouse() as ch:
        yield ch


@pytest.fixture(scope="session")
def to_row() -> harness.ToRow:
    resolved = harness.resolve_to_row()
    if resolved is None:  # pragma: no cover - A's extorq.storage.rows is present since 2026-11-21
        pytest.fail("extorq.storage.rows.to_row is not available")
    return resolved
