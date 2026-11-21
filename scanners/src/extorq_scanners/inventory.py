"""Linux VM package inventory through B1's restricted SSH dispatch (``packages``).

Reuses ``extorq_collectors.linux.ssh.SSHDispatchClient`` (host-key pinning,
BatchMode, forced-command allow-list, bounded output, timeouts and jittered
retries live there) and B1's ``ssh:`` block in ``config/collectors/linux.yaml``
(defaults apply when that file or block is absent). The SSH private key is
only ever passed to ``ssh`` by path; this module never reads it.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from extorq_scanners.config import InventoryConfig, resolve_in_root

MAX_INVENTORY_BYTES = 32 * 1024 * 1024


class InventoryUnavailable(RuntimeError):
    """The package inventory could not be obtained (message is sanitized)."""


def _ssh_block(root: Path, cfg: InventoryConfig) -> dict[str, Any]:
    path = resolve_in_root(root, cfg.linux_collector_config)
    if not path.is_file():
        return {}
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise InventoryUnavailable(f"cannot read {path.name}: {type(exc).__name__}") from None
    block = doc.get("ssh") if isinstance(doc, dict) else None
    return dict(block) if isinstance(block, dict) else {}


def _dispatch_json(root: Path, cfg: InventoryConfig, command: str) -> Any:
    """Run one allow-listed dispatch command on the VM and parse its JSON output."""
    try:
        from extorq_collectors.linux.ssh import SSHDispatchClient, SSHDispatchError, SSHTarget
    except ImportError:
        raise InventoryUnavailable(
            "B1 SSH dispatch helper (extorq_collectors.linux.ssh) not installed"
        ) from None
    try:
        target = SSHTarget.from_mapping(_ssh_block(root, cfg), base_dir=root)
    except (TypeError, ValueError) as exc:
        raise InventoryUnavailable(f"invalid ssh configuration: {exc}") from None
    client = SSHDispatchClient(target)
    try:
        text = client.run(
            command, timeout=float(cfg.timeout_seconds), max_output=MAX_INVENTORY_BYTES
        )
    except SSHDispatchError as exc:
        raise InventoryUnavailable(f"{type(exc).__name__}: {str(exc)[:300]}") from None
    finally:
        client.close()
    try:
        return json.loads(text)
    except ValueError:
        raise InventoryUnavailable(f"{command} output is not valid JSON") from None


def fetch_packages(root: Path, cfg: InventoryConfig) -> Any:
    """Return the parsed ``packages`` JSON document (dpkg inventory) from the VM."""
    return _dispatch_json(root, cfg, "packages")


def fetch_inventory(root: Path, cfg: InventoryConfig) -> Any:
    """Return the parsed ``inventory`` JSON document (systemd units etc.) from the VM."""
    return _dispatch_json(root, cfg, "inventory")


InventoryFetcher = Callable[[Path, InventoryConfig], Any]
