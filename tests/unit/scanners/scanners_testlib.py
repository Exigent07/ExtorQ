"""Helpers for scanner unit tests (owner: C3): fixture loading and contexts."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from extorq_scanners.k8s_index import K8sIndex, K8sObjectRef
from extorq_scanners.models import NormalizeContext

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "scanners"
OBSERVED_AT = datetime(2026, 11, 21, 14, 45, tzinfo=UTC)
RUN_ID = "0123456789abcdef0123456789abcdef"


def load_json(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def load_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def load_k8s_index(name: str = "trivy-config-kind.k8s-index.json") -> K8sIndex:
    raw = load_json(name)
    return {path: [K8sObjectRef(**ref) for ref in refs] for path, refs in raw.items()}


def ctx(asset_id: str, scanner: str, mode: str, **kwargs: Any) -> NormalizeContext:
    return NormalizeContext(
        asset_id=asset_id,
        scanner=scanner,
        scan_run_id=RUN_ID,
        observed_at=OBSERVED_AT,
        mode=mode,
        **kwargs,
    )


def all_text(finding: Any) -> str:
    """Every stored free-text value of a finding (for leak assertions)."""
    return json.dumps(finding.model_dump(mode="json"), sort_keys=True)
