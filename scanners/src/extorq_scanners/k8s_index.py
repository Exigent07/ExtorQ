"""Line index of Kubernetes objects in scanned manifest files.

Trivy reports Kubernetes misconfigurations with a file path and line range but
without a structured object reference (its messages are inconsistent). The
index maps line ranges back to ``kind``/``metadata.name``/``metadata.namespace``
taken from the manifest itself. YAML is *composed* (node tree with marks), never
constructed, so no objects are instantiated from untrusted input.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml

MAX_FILE_BYTES = 1_000_000
MAX_DOCUMENTS = 500
MAX_FILES = 2_000
_SUFFIXES = (".yaml", ".yml")


@dataclass(frozen=True)
class K8sObjectRef:
    kind: str
    name: str | None
    namespace: str | None
    start_line: int
    end_line: int


#: relative file path -> objects in that file (1-based inclusive line ranges)
K8sIndex = dict[str, list[K8sObjectRef]]


def _scalar(node: yaml.Node | None) -> str | None:
    if isinstance(node, yaml.ScalarNode) and isinstance(node.value, str):
        value = node.value.strip()
        return value[:253] or None
    return None


def _get(node: yaml.MappingNode, key: str) -> yaml.Node | None:
    for key_node, value_node in node.value:
        if isinstance(key_node, yaml.ScalarNode) and key_node.value == key:
            return value_node
    return None


def index_text(text: str) -> list[K8sObjectRef]:
    """Objects (with ``kind``) found in a possibly multi-document YAML text."""
    refs: list[K8sObjectRef] = []
    for count, doc in enumerate(yaml.compose_all(text, Loader=yaml.SafeLoader)):
        if count >= MAX_DOCUMENTS:
            break
        if not isinstance(doc, yaml.MappingNode):
            continue
        kind = _scalar(_get(doc, "kind"))
        if not kind:
            continue
        name = namespace = None
        metadata = _get(doc, "metadata")
        if isinstance(metadata, yaml.MappingNode):
            name = _scalar(_get(metadata, "name"))
            namespace = _scalar(_get(metadata, "namespace"))
        start = doc.start_mark.line + 1
        end = max(start, doc.end_mark.line + (1 if doc.end_mark.column else 0))
        refs.append(K8sObjectRef(kind, name, namespace, start, end))
    return refs


def _iter_files(root: Path, rel_paths: Iterable[str]) -> Iterable[tuple[str, Path]]:
    seen = 0
    for rel in rel_paths:
        base = root / rel
        if base.is_symlink():
            continue
        if base.is_file():
            candidates: Iterable[Path] = [base]
        elif base.is_dir():
            candidates = sorted(
                Path(dirpath) / name
                for dirpath, _dirs, files in os.walk(base, followlinks=False)
                for name in files
            )
        else:
            continue
        for path in candidates:
            if path.suffix.lower() not in _SUFFIXES or path.is_symlink():
                continue
            seen += 1
            if seen > MAX_FILES:
                return
            yield path.relative_to(root).as_posix(), path


def index_paths(
    root: Path, rel_paths: Iterable[str], mount_rel: dict[str, str] | None = None
) -> K8sIndex:
    """Index YAML files below ``rel_paths`` (relative to ``root``).

    ``mount_rel`` optionally maps a repository-relative path prefix to the path
    the scanner reports (when targets are mounted under a different name).
    Unreadable/invalid files are skipped: the index is an enrichment only.
    """
    index: K8sIndex = {}
    for rel, path in _iter_files(root, rel_paths):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            refs = index_text(text)
        except (OSError, yaml.YAMLError):
            continue
        if refs:
            key = rel
            for prefix, reported in (mount_rel or {}).items():
                base = prefix.rstrip("/")
                if rel == base or rel.startswith(base + "/"):
                    rest = rel[len(base) :].lstrip("/")
                    key = "/".join(part for part in (reported.strip("/"), rest) if part)
                    break
            index[key] = refs
    return index


def lookup(index: K8sIndex | None, path: str | None, line: int | None) -> K8sObjectRef | None:
    """Innermost object whose line range contains ``line`` in ``path``."""
    if not index or not path or line is None:
        return None
    best: K8sObjectRef | None = None
    for ref in index.get(path, ()):
        if ref.start_line <= line <= ref.end_line and (
            best is None or (ref.end_line - ref.start_line) < (best.end_line - best.start_line)
        ):
            best = ref
    return best


#: Kinds that carry a Pod template (pod-level checks apply to them).
WORKLOAD_KINDS = frozenset(
    {
        "Pod",
        "Deployment",
        "DaemonSet",
        "StatefulSet",
        "ReplicaSet",
        "ReplicationController",
        "Job",
        "CronJob",
    }
)


def sole_workload(index: K8sIndex | None, path: str | None) -> K8sObjectRef | None:
    """The only workload object in ``path``, if exactly one exists (else ``None``)."""
    if not index or not path:
        return None
    refs = [ref for ref in index.get(path, ()) if ref.kind in WORKLOAD_KINDS]
    return refs[0] if len(refs) == 1 else None
