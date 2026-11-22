"""Read collector intervals and rule schedules from the repository's YAML files.

The bounded waits follow the configuration that is actually deployed: collector intervals
come from ``config/collectors/*.yaml`` (the files the collectors load) and rule intervals
from the detector's registered rule (``GET /api/v1/rules/{id}``, see the runner). The local
``rules/**/<ID>.yaml`` is only a fallback for ``python -m detection_tests list``, which
runs without the stack.

YAML is parsed with ``yaml.safe_load`` and size-capped; a missing file or key falls back
to the documented default of the :class:`~detection_tests.model.LatencySource`, and the
report says which value was used.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from detection_tests.model import LatencySource

MAX_YAML_BYTES = 1024 * 1024


def load_yaml(path: Path) -> Any:
    """``yaml.safe_load`` of a small repository file (``None`` when absent or invalid)."""
    try:
        if path.stat().st_size > MAX_YAML_BYTES:
            return None
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError, UnicodeDecodeError):
        return None


def collector_entry(root: Path, config_file: str, collector_id: str) -> Mapping[str, Any] | None:
    """The ``collectors:`` entry with ``collector_id`` from one collector config file."""
    document = load_yaml(root / config_file)
    if not isinstance(document, Mapping):
        return None
    entries = document.get("collectors")
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if isinstance(entry, Mapping) and entry.get("collector_id") == collector_id:
            return entry
    return None


def evidence_producer(root: Path, source_type: str) -> str | None:
    if source_type in {"k8s.audit", "k8s.container_log"}:
        return "k8s-otel-extorq-lab"
    source = {
        "linux": ("linux", "linux-ssh-lab-vm-01"),
        "macos": ("macos", "macos-workstation-01"),
        "github": ("github", "github-repos"),
        "k8s": ("kubernetes", "k8s-inventory"),
    }.get(source_type.partition(".")[0])
    if source is None:
        return None
    platform, collector = source
    entry = collector_entry(root, f"config/collectors/{platform}.yaml", collector)
    value = entry.get("producer_id") if entry else None
    return value if isinstance(value, str) and value else None


def _positive_int(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


@dataclass(frozen=True)
class SourceInterval:
    """Resolved interval of an evidence source and where the value came from."""

    source_seconds: int
    loop_seconds: int
    origin: str


def source_interval(root: Path, source: LatencySource) -> SourceInterval:
    """Resolve ``source``'s interval (and its collector loop tick) from the config file."""
    if source.config_file is None or source.collector_id is None:
        return SourceInterval(source.default_seconds, 0, "default (push source)")
    entry = collector_entry(root, source.config_file, source.collector_id)
    if entry is None:
        loop = source.default_seconds if source.loop_tick else 0
        return SourceInterval(
            source.default_seconds, loop, f"default ({source.config_file} entry not found)"
        )
    loop_seconds = _positive_int(entry.get("interval_seconds")) or 0
    if not source.interval_keys:
        # The source IS the collector loop: no extra tick on top of its own interval.
        own = loop_seconds or source.default_seconds
        return SourceInterval(own, 0, f"{source.config_file}: interval_seconds")
    node: Any = entry
    for key in source.interval_keys:
        node = node.get(key) if isinstance(node, Mapping) else None
    configured = _positive_int(node)
    origin = f"{source.config_file}: {'.'.join(source.interval_keys)}"
    if configured is None:
        configured = source.default_seconds
        origin = f"default ({origin} not set)"
    return SourceInterval(configured, loop_seconds if source.loop_tick else 0, origin)


def local_rule(root: Path, rule_id: str) -> Mapping[str, Any] | None:
    """The rule's YAML metadata from ``rules/**/<rule_id>.yaml`` (for offline listing)."""
    for path in sorted((root / "rules").glob(f"*/{rule_id}.yaml")):
        document = load_yaml(path)
        if isinstance(document, Mapping) and document.get("rule_id") == rule_id:
            return document
    return None
