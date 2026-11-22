"""Make the top-level ``detection_tests`` package importable from its unit tests.

The package lives at the repository root (``python -m detection_tests`` is run from there)
and is not an installed workspace member, so the root is put on ``sys.path`` here.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
