"""Pytest fixtures for the Linux collector tests (helpers live in linux_testlib.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
from linux_testlib import write_ssh_files


@pytest.fixture
def ssh_files(tmp_path: Path) -> tuple[Path, Path]:
    return write_ssh_files(tmp_path)
