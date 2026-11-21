"""Parsing of dispatch-boundary responses (protocol version 1).

The VM is untrusted: every response is validated structurally and bounded
before any field is used. Formats (docs/telemetry/linux.md):

* ``journal``: NDJSON, one filtered journald entry per line, terminated by a
  trailer ``{"_extorq": {"type": "journal_end", ...}}``. A response without the
  trailer is incomplete (connection lost): complete lines are still usable
  because every entry carries its own cursor.
* ``audit``: one JSON header line ``{"_extorq": {"type": "audit", ...}}``
  followed by raw audit.log bytes (complete lines only).
* ``inventory`` / ``packages`` / ``posture`` / ``version``: one JSON object.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

PROTOCOL_VERSION = 1
MAX_JOURNAL_LINE = 256 * 1024


class ProtocolError(Exception):
    """The VM returned something that does not match the dispatch protocol."""


@dataclass
class JournalBatch:
    entries: list[dict[str, Any]] = field(default_factory=list)
    trailer: dict[str, Any] | None = None
    malformed_lines: int = 0

    @property
    def complete(self) -> bool:
        return self.trailer is not None

    @property
    def cursor_exact(self) -> bool | None:
        value = (self.trailer or {}).get("cursor_exact")
        return value if isinstance(value, bool) else None

    @property
    def truncated(self) -> bool:
        return bool((self.trailer or {}).get("truncated"))

    @property
    def error(self) -> str | None:
        value = (self.trailer or {}).get("error")
        return str(value)[:300] if value else None


def parse_journal_response(data: bytes) -> JournalBatch:
    batch = JournalBatch()
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    elif lines:
        lines.pop()  # trailing partial line (no newline): connection cut mid-line
        batch.malformed_lines += 1
    for raw in lines:
        if not raw or len(raw) > MAX_JOURNAL_LINE:
            batch.malformed_lines += 1
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            batch.malformed_lines += 1
            continue
        if not isinstance(obj, dict):
            batch.malformed_lines += 1
            continue
        meta = obj.get("_extorq")
        if isinstance(meta, dict):
            if meta.get("type") == "journal_end" and meta.get("protocol") == PROTOCOL_VERSION:
                batch.trailer = meta
            else:
                batch.malformed_lines += 1
            continue
        if batch.trailer is not None:
            batch.malformed_lines += 1  # nothing may follow the trailer
            continue
        batch.entries.append(obj)
    return batch


@dataclass(frozen=True)
class AuditChunk:
    header: dict[str, Any]
    payload: bytes

    def _int(self, key: str) -> int:
        value = self.header.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ProtocolError(f"audit header field {key!r} missing or invalid")
        return value

    @property
    def inode(self) -> int:
        return self._int("inode")

    @property
    def start_offset(self) -> int:
        return self._int("start_offset")

    @property
    def next_offset(self) -> int:
        return self._int("next_offset")

    @property
    def gap(self) -> bool:
        return self.header.get("gap") is True

    @property
    def gap_reason(self) -> str | None:
        value = self.header.get("gap_reason")
        return str(value)[:64] if value else None

    @property
    def more(self) -> bool:
        return self.header.get("more") is True


def parse_audit_response(data: bytes) -> AuditChunk:
    newline = data.find(b"\n")
    if newline < 0:
        raise ProtocolError("audit response has no header line")
    try:
        header_obj = json.loads(data[:newline])
    except ValueError as exc:
        raise ProtocolError("audit header is not JSON") from exc
    meta = header_obj.get("_extorq") if isinstance(header_obj, dict) else None
    if not isinstance(meta, dict) or meta.get("type") != "audit" \
            or meta.get("protocol") != PROTOCOL_VERSION:
        raise ProtocolError("unexpected audit header")
    chunk = AuditChunk(header=meta, payload=data[newline + 1:])
    if chunk.next_offset < chunk.start_offset:
        raise ProtocolError("audit next_offset precedes start_offset")
    if chunk.next_offset - chunk.start_offset < len(chunk.payload):
        raise ProtocolError("audit payload larger than the advertised byte range")
    if chunk.payload and not chunk.payload.endswith(b"\n"):
        raise ProtocolError("audit payload does not end on a line boundary")
    return chunk


def parse_json_document(data: bytes, expected_type: str) -> dict[str, Any]:
    try:
        obj = json.loads(data)
    except ValueError as exc:
        raise ProtocolError(f"{expected_type} response is not JSON") from exc
    if not isinstance(obj, dict) or obj.get("type") != expected_type:
        raise ProtocolError(f"unexpected {expected_type} response type")
    if obj.get("protocol") != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported {expected_type} protocol {obj.get('protocol')!r}")
    return obj
