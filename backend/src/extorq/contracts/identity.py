"""Deterministic identities shared by collectors, the gateway and the backend.

ClickHouse sorting keys do NOT enforce uniqueness. ExtorQ therefore derives
stable identifiers from source-native identity (journald cursor, audit ID,
commit SHA, ...) or from canonical content, so that re-sent records collapse to
the same logical identity (``ReplacingMergeTree`` + duplicate-safe queries).

Changing any function in this module is a breaking contract change: identities
would no longer match previously stored rows. Bump the namespace suffix (``.v1``)
instead of editing behaviour in place.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from datetime import UTC, date, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel

_SEP = "\x1f"  # ASCII unit separator: cannot appear in normal identifiers.


def iso_utc(value: datetime) -> str:
    """Canonical UTC ISO-8601 rendering with millisecond precision and ``Z`` suffix."""
    if value.tzinfo is None:
        raise ValueError("naive datetime cannot be rendered canonically")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def stable_id(namespace: str, *parts: object) -> str:
    """Deterministic 128-bit identifier: first 32 hex chars of SHA-256 over the parts."""
    rendered = [namespace]
    for part in parts:
        if part is None:
            rendered.append("")
        elif isinstance(part, datetime):
            rendered.append(iso_utc(part))
        else:
            rendered.append(str(part))
    material = _SEP.join(rendered)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def sha256_hex(data: str | bytes) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return iso_utc(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, set | frozenset):
        return sorted(value, key=str)
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=False)
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    raise TypeError(f"not canonically serialisable: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Canonical JSON: sorted keys, compact separators, UTF-8, ISO-8601 UTC times."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
        allow_nan=False,
    )


def input_hash(value: Any) -> str:
    """SHA-256 of the canonical JSON form; used for context/AI input hashes."""
    return sha256_hex(canonical_json(value))


# ── Domain identities ─────────────────────────────────────────────────


def event_id(source_type: str, asset_id: str, native_key: str) -> str:
    """Identity of a SecurityEvent.

    ``native_key`` must be the most stable source-native identity available:

    * journald: the entry ``__CURSOR``
    * auditd: ``<node>:<audit serial>:<audit timestamp>`` plus record type
    * Kubernetes audit: ``<auditID>:<stage>``
    * Kubernetes inventory diff: ``<kind>/<namespace>/<name>:<uid>:<resourceVersion>:<change>``
    * GitHub: commit SHA / ``<run_id>:<run_attempt>:<status>`` / workflow path + commit SHA
    * container logs: ``<pod_uid>:<container>:<stream>:<timestamp_ns>:<sha256(line)>``
    * snapshot diffs: ``<item key>:<change>:<content sha256>``

    When no native identity exists use :func:`content_key` over the canonical
    normalised content (never over collection time).
    """
    return stable_id("event.v1", source_type, asset_id, native_key)


def content_key(*parts: object) -> str:
    """Full SHA-256 over parts, for sources lacking a native unique identifier."""
    return sha256_hex(_SEP.join("" if p is None else str(p) for p in parts))


def finding_id(
    asset_id: str, scanner: str, check_id: str, resource_key: str, qualifier: str = ""
) -> str:
    """Fingerprint of a finding, stable across scans of the same asset and scope."""
    return stable_id("finding.v1", asset_id, scanner, check_id, resource_key, qualifier)


def alert_id(rule_id: str, group_key: str, bucket: datetime | str) -> str:
    """Identity of a DetectionAlert.

    ``bucket`` is the dedup bucket start (threshold rules) or the triggering
    event id / signature (single-event rules). Rule *version* is deliberately not
    part of the identity so a rule upgrade does not duplicate open alerts.
    """
    return stable_id("alert.v1", rule_id, group_key, bucket)


def context_id(alert_id_value: str, context_input_hash: str) -> str:
    return stable_id("context.v1", alert_id_value, context_input_hash)


def assessment_id(
    provider: str, model: str, task: str, prompt_version: str, context_input_hash: str, nonce: str = ""
) -> str:
    return stable_id("assessment.v1", provider, model, task, prompt_version, context_input_hash, nonce)


def scope_hash(targets: list[str], description: str = "") -> str:
    """Hash identifying the scope of a scan; lifecycle comparisons require equal scope."""
    return stable_id("scope.v1", canonical_json(sorted(targets)), description)
