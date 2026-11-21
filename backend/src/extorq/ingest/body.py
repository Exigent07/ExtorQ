"""Request body limits: streaming size enforcement and bounded gzip decompression.

* ``Content-Length`` above the limit is rejected before reading anything.
* Otherwise the body is read chunk by chunk and rejected as soon as the running
  total exceeds the limit, so an oversized (or endless chunked) upload never
  reaches the JSON parser and never sits fully in memory.
* gzip bodies are inflated incrementally with an output cap (decompression-bomb
  guard); truncated streams, trailing garbage and multi-member streams are
  rejected.
"""

from __future__ import annotations

import zlib
from collections.abc import AsyncIterator


class BodyError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def check_content_length(header: str | None, max_bytes: int) -> None:
    if header is None:
        return
    try:
        length = int(header)
    except ValueError:
        raise BodyError(400, "invalid Content-Length") from None
    if length < 0:
        raise BodyError(400, "invalid Content-Length")
    if length > max_bytes:
        raise BodyError(413, f"request body exceeds {max_bytes} bytes")


async def read_limited(stream: AsyncIterator[bytes], max_bytes: int) -> bytes:
    """Read an ASGI body stream, failing with 413 once more than ``max_bytes`` arrive."""
    chunks: list[bytes] = []
    total = 0
    async for chunk in stream:
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise BodyError(413, f"request body exceeds {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def content_encoding(header: str | None) -> str:
    """Return ``identity`` or ``gzip``; anything else is unsupported (415)."""
    value = (header or "identity").strip().lower()
    if value in ("", "identity"):
        return "identity"
    if value in ("gzip", "x-gzip"):
        return "gzip"
    raise BodyError(415, "unsupported Content-Encoding (use gzip or identity)")


def gunzip_limited(data: bytes, max_output: int) -> bytes:
    """Inflate a single gzip member, refusing more than ``max_output`` bytes of output."""
    inflater = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    out = bytearray()
    pending = data
    for _ in range(1_000_000):  # hard bound; each pass consumes input or produces output
        try:
            chunk = inflater.decompress(pending, max_output + 1 - len(out))
        except zlib.error:
            raise BodyError(400, "invalid gzip body") from None
        out += chunk
        if len(out) > max_output:
            raise BodyError(413, f"decompressed body exceeds {max_output} bytes")
        if inflater.eof:
            break
        pending = inflater.unconsumed_tail
        if not pending and not chunk:
            break
    if not inflater.eof:
        raise BodyError(400, "truncated gzip body")
    if inflater.unused_data:
        raise BodyError(400, "unexpected data after gzip stream")
    return bytes(out)


def check_json_content_type(header: str | None) -> None:
    media_type = (header or "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise BodyError(415, "Content-Type must be application/json")
