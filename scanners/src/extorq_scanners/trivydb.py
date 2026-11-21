"""Trivy vulnerability DB cache (``var/cache/trivy``): freshness and updates.

Scans mount the cache read-only with ``--network none --skip-db-update``.
Updating is a separate container with network access that mounts *only* the
cache directory (no scan target), runs ``--download-db-only`` with telemetry
and version checks disabled, and uses an on-disk temp dir inside the cache.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from extorq_scanners.docker import ContainerSpec, DockerRunner, Mount


@dataclass(frozen=True)
class DbMetadata:
    updated_at: datetime | None
    next_update: datetime | None
    downloaded_at: datetime | None

    def age(self, now: datetime) -> timedelta | None:
        ref = self.downloaded_at or self.updated_at
        return None if ref is None else now - ref


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.replace("Z", "+00:00")
    # Trivy writes nanoseconds; Python accepts at most microseconds.
    if "." in text:
        head, _, tail = text.partition(".")
        frac = "".join(ch for ch in tail if ch.isdigit())[:6]
        zone = tail[len("".join(ch for ch in tail if ch.isdigit())) :]
        text = f"{head}.{frac}{zone}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def read_metadata(cache_dir: Path) -> DbMetadata | None:
    """Metadata of the cached DB, or None when no usable DB is present."""
    meta_path = cache_dir / "db" / "metadata.json"
    db_path = cache_dir / "db" / "trivy.db"
    try:
        if db_path.stat().st_size == 0:
            return None
        data = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return DbMetadata(
        updated_at=_parse_time(data.get("UpdatedAt")),
        next_update=_parse_time(data.get("NextUpdate")),
        downloaded_at=_parse_time(data.get("DownloadedAt")),
    )


def is_stale(meta: DbMetadata | None, max_age_hours: int, now: datetime | None = None) -> bool:
    if meta is None:
        return True
    age = meta.age(now or datetime.now(UTC))
    return age is None or age > timedelta(hours=max_age_hours)


def update_spec(image: str, cache_dir: Path) -> ContainerSpec:
    (cache_dir / ".tmp").mkdir(parents=True, exist_ok=True)
    return ContainerSpec(
        image=image,
        args=[
            "--cache-dir",
            "/cache",
            "image",
            "--download-db-only",
            "--disable-telemetry",
            "--skip-version-check",
            "--no-progress",
        ],
        mounts=[Mount(cache_dir, "/cache", read_only=False)],
        env={"TMPDIR": "/cache/.tmp"},
        network="bridge",
        purpose="trivy-db",
    )


def update_db(runner: DockerRunner, image: str, cache_dir: Path, timeout: float) -> str | None:
    """Download/refresh the DB. Returns None on success, else a sanitized error."""
    result = runner.run(update_spec(image, cache_dir), timeout=timeout, max_stdout_bytes=1_000_000)
    out = result.outcome
    if out.start_error:
        return f"trivy DB update could not start: {out.start_error}"
    if out.timed_out:
        return "trivy DB update timed out"
    if out.exit_code != 0:
        fatal = [ln for ln in result.stderr.splitlines() if "FATAL" in ln or "ERROR" in ln]
        detail = fatal[-1][-300:] if fatal else f"exit code {out.exit_code}"
        return f"trivy DB update failed: {detail}"
    if read_metadata(cache_dir) is None:
        return "trivy DB update finished but no DB metadata was found"
    return None
