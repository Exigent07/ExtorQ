"""The detection-test matrix (``docs/team/PLAN.md`` section 12): suites per asset and selection.

``--asset all`` runs the suites in the PLAN's order (Linux, Kubernetes, GitHub, macOS); the
order of the tests inside a suite is fixed by each asset module because some tests depend
on what ran before them (see ``detection_tests.linux``).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

from detection_tests import github, kubernetes, linux, macos
from detection_tests.model import RULE_ID_RE
from detection_tests.runner import AssetSuite

BUILDERS: dict[str, Callable[[Path], AssetSuite]] = {
    "linux": linux.build_suite,
    "kubernetes": kubernetes.build_suite,
    "github": github.build_suite,
    "macos": macos.build_suite,
}
ASSET_KEYS: tuple[str, ...] = tuple(BUILDERS)


def build_suites(root: Path, asset: str) -> list[AssetSuite]:
    """Suites for one asset key or ``all``."""
    if asset == "all":
        return [BUILDERS[key](root) for key in ASSET_KEYS]
    if asset not in BUILDERS:
        raise ValueError(f"unknown asset {asset!r} (expected one of {', '.join(ASSET_KEYS)}, all)")
    return [BUILDERS[asset](root)]


def parse_only(values: Sequence[str]) -> list[str]:
    """``--only VM-001 --only k8s-003,GH-001`` -> upper-case, validated rule ids."""
    rules: list[str] = []
    for value in values:
        for item in value.split(","):
            rule = item.strip().upper()
            if not rule:
                continue
            if not RULE_ID_RE.fullmatch(rule):
                raise ValueError(f"invalid rule id {item.strip()!r} (expected e.g. VM-001)")
            if rule not in rules:
                rules.append(rule)
    return rules


def select(suites: Sequence[AssetSuite], only: Sequence[str]) -> list[AssetSuite]:
    """Keep only tests of the given rules (all tests when ``only`` is empty).

    Raises ``ValueError`` when a requested rule has no test in the selected assets, so a
    typo never turns into a silently empty run.
    """
    if not only:
        return list(suites)
    wanted = set(only)
    found: set[str] = set()
    selected: list[AssetSuite] = []
    for suite in suites:
        tests = [t for t in suite.tests if t.spec.rule_id in wanted]
        found.update(t.spec.rule_id for t in tests)
        if tests:
            selected.append(
                AssetSuite(
                    asset=suite.asset,
                    tests=tests,
                    check=suite.check,
                    sweep=suite.sweep,
                    collector_ids=suite.collector_ids,
                    telemetry_check=suite.telemetry_check,
                )
            )
    missing = sorted(wanted - found)
    if missing:
        raise ValueError(f"no test for {', '.join(missing)} in the selected asset(s)")
    return selected
