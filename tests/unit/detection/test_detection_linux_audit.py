"""Shared auditd semantics: Python helper == rule params; create/modify vs removal (SYNTHETIC)."""

from __future__ import annotations

from pathlib import Path

import pytest

from extorq.detection import linux_audit
from extorq.detection.registry import load_rules_report

ROOT = Path(__file__).resolve().parents[3] / "rules"
RULES = {r.rule_id: r for r in load_rules_report(ROOT)[0]}


@pytest.mark.parametrize("rule_id", ["VM-002", "CORR-002"])
def test_rule_allowlists_match_the_shared_definition(rule_id: str) -> None:
    params = RULES[rule_id].metadata.params
    assert set(params["change_syscalls"]) == linux_audit.CHANGE_SYSCALLS
    if "deletion_syscalls" in params:
        assert set(params["deletion_syscalls"]) == linux_audit.DELETION_SYSCALLS
    assert not linux_audit.CHANGE_SYSCALLS & linux_audit.DELETION_SYSCALLS


UNIT = "/etc/systemd/system/x.service"


@pytest.mark.parametrize(
    ("attributes", "resource_path", "change", "removal", "written"),
    [
        ({"syscall": "openat", "success": True, "nametype": "CREATE"}, UNIT, True, False, UNIT),
        ({"syscall": "openat", "success": True, "nametype": "NORMAL"}, UNIT, True, False, UNIT),
        ({"syscall": "fchmodat", "success": True, "nametype": "NORMAL"}, UNIT, True, False, UNIT),
        ({"syscall": "unlinkat", "success": True, "nametype": "DELETE"}, UNIT, False, True, None),
        ({"syscall": "openat", "success": False, "nametype": "NORMAL"}, UNIT, False, False, UNIT),
        ({"syscall": "fsetxattr", "success": True, "nametype": "NORMAL"}, None, False, False, None),
        ({"syscall": "56", "success": True, "nametype": "CREATE"}, UNIT, False, False, UNIT),
        ({"syscall": "openat", "nametype": "CREATE"}, UNIT, False, False, UNIT),
        (
            {
                "syscall": "renameat",
                "success": True,
                "nametype": "DELETE",
                "paths": [
                    "PARENT:/tmp/",
                    "PARENT:/etc/systemd/system/",
                    "DELETE:/tmp/x",
                    f"CREATE:{UNIT}",
                ],
            },
            "/tmp/x",
            True,
            True,
            UNIT,
        ),
    ],
)
def test_change_and_removal_classification(attributes, resource_path, change, removal, written):
    assert linux_audit.is_change(attributes, resource_path) is change
    assert linux_audit.is_removal(attributes) is removal
    assert linux_audit.written_path(attributes, resource_path) == written
