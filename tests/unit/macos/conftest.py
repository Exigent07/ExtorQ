"""pytest fixtures for the macOS collector unit tests (helpers: macos_helpers.py)."""

from __future__ import annotations

import pytest
from macos_helpers import ASSET, COLLECTOR, FakeRunner

from extorq_collectors.macos.common import SourceContext


@pytest.fixture
def src() -> SourceContext:
    return SourceContext(collector_id=COLLECTOR, asset_id=ASSET, collector_version="0.1.0")


@pytest.fixture
def fake_runner() -> FakeRunner:
    return FakeRunner()
