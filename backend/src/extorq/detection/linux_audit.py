"""What an auditd file-watch hit on a systemd unit path proves (shared by rules and context).

B1's auditd parser (``extorq_collectors.linux.auditd``) emits ``file.audit.watch`` events
with ``attributes.syscall`` (enriched name, or the number when the log is not enriched),
``success``, ``nametype`` of the primary PATH item (first non-PARENT item, mapped to
``resource.path``) and ``paths`` (every PATH item as ``NAMETYPE:/abs/path``).

A hit is **creation/modification evidence** only when it succeeded, its syscall is in
:data:`CHANGE_SYSCALLS` (an allowlist: unknown or numeric values fail closed) and it has a
written path: the primary item when it is CREATE/NORMAL, otherwise the CREATE item of a
rename/link whose primary item is the source name. Deletions (nametype DELETE,
:data:`DELETION_SYSCALLS`) are **context only**. The VM-002 / CORR-002 SQL implements the
same definition (``params.change_syscalls``); ``tests/unit/detection`` checks they agree.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#: Syscalls that create or modify a file: open for write/create, truncate, rename/link/
#: symlink/mknod into the directory, permission and ownership changes.
CHANGE_SYSCALLS: frozenset[str] = frozenset(
    {
        "open",
        "openat",
        "openat2",
        "creat",
        "truncate",
        "ftruncate",
        "rename",
        "renameat",
        "renameat2",
        "link",
        "linkat",
        "symlink",
        "symlinkat",
        "mknod",
        "mknodat",
        "chmod",
        "fchmod",
        "fchmodat",
        "fchmodat2",
        "chown",
        "fchown",
        "fchownat",
        "lchown",
    }
)
DELETION_SYSCALLS: frozenset[str] = frozenset({"unlink", "unlinkat", "rmdir"})


def written_path(attributes: Mapping[str, Any], resource_path: str | None) -> str | None:
    """Path the hit created or modified (``None`` when it wrote no name)."""
    nametype = attributes.get("nametype")
    if nametype in ("CREATE", "NORMAL") and resource_path:
        return resource_path
    paths = attributes.get("paths")
    if isinstance(paths, list):
        for item in paths:
            if isinstance(item, str) and item.startswith("CREATE:/"):
                return item[len("CREATE:") :]
    return None


def is_change(attributes: Mapping[str, Any], resource_path: str | None) -> bool:
    """Successful create/modify syscall with a written path (creation/modification evidence)."""
    return (
        attributes.get("success") is True
        and attributes.get("syscall") in CHANGE_SYSCALLS
        and written_path(attributes, resource_path) is not None
    )


def is_removal(attributes: Mapping[str, Any]) -> bool:
    """Successful deletion of the primary path item (context, never persistence evidence)."""
    return attributes.get("success") is True and (
        attributes.get("nametype") == "DELETE" or attributes.get("syscall") in DELETION_SYSCALLS
    )
