"""Semgrep rulesets: registry packs cached host-side, local (vendored) rule files.

Registry packs (e.g. ``p/python``) are fetched by this process over HTTPS with
a timeout and bounded, jittered retries, validated (JSON/YAML with a non-empty
``rules`` list, size-capped) and written atomically to ``var/cache/semgrep``
together with a metadata sidecar (source URL, SHA-256, fetch time, rule count).
The Semgrep container itself then runs with ``--network none`` and never talks
to the registry; ``--metrics=off`` is always passed as well. Registry rules are
cached locally only and are not redistributed in this repository.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import yaml

from extorq.contracts.identity import iso_utc
from extorq_scanners import __version__
from extorq_scanners.config import RulesetConfig, SemgrepConfig, resolve_in_root

MAX_RULESET_BYTES = 8 * 1024 * 1024
_RETRIES = 3


class RulesetError(RuntimeError):
    """A ruleset is unavailable or invalid."""


@dataclass(frozen=True)
class ResolvedRuleset:
    name: str
    path: Path
    sha256: str
    rules: int
    source: str
    fetched_at: str | None = None
    stale: bool = False


def count_rules(data: bytes) -> int:
    """Validate a Semgrep config document and return its rule count."""
    try:
        doc: Any = json.loads(data)
    except ValueError:
        try:
            doc = yaml.safe_load(data)
        except yaml.YAMLError as exc:
            raise RulesetError(f"ruleset is neither JSON nor YAML: {type(exc).__name__}") from None
    rules = doc.get("rules") if isinstance(doc, dict) else None
    if not isinstance(rules, list) or not rules:
        raise RulesetError("ruleset has no 'rules' list")
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            raise RulesetError("ruleset contains a rule without an id")
    return len(rules)


def _safe_name(name: str) -> str:
    return name.replace("/", "-")


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def fetch_registry(cfg: SemgrepConfig, ruleset: RulesetConfig, cache_dir: Path) -> ResolvedRuleset:
    """Download a registry pack into the cache (network). Raises RulesetError."""
    assert ruleset.registry_id is not None  # noqa: S101 - validated by config
    url = cfg.registry_url.rstrip("/") + "/" + ruleset.registry_id
    if not url.startswith("https://"):
        raise RulesetError("registry URL must use https")
    cache_dir.mkdir(parents=True, exist_ok=True)
    last_error = "unknown error"
    for attempt in range(1, _RETRIES + 1):
        try:
            with httpx.Client(
                timeout=cfg.fetch_timeout_seconds,
                follow_redirects=False,
                headers={"User-Agent": f"extorq-scanners/{__version__}"},
            ) as client:
                resp = client.get(url)
            if resp.status_code != 200:
                last_error = f"HTTP {resp.status_code}"
                if resp.status_code < 500 and resp.status_code != 429:
                    break
            elif len(resp.content) > MAX_RULESET_BYTES:
                raise RulesetError(f"ruleset larger than {MAX_RULESET_BYTES} bytes")
            else:
                data = resp.content
                rules = count_rules(data)
                digest = hashlib.sha256(data).hexdigest()
                path = cache_dir / f"{_safe_name(ruleset.name)}.json"
                _write_atomic(path, data)
                fetched = iso_utc(datetime.now(UTC))
                meta = {"source": url, "sha256": digest, "fetched_at": fetched, "rules": rules}
                _write_atomic(path.with_suffix(".meta.json"), json.dumps(meta).encode())
                return ResolvedRuleset(ruleset.name, path, digest, rules, url, fetched)
        except httpx.HTTPError as exc:
            last_error = type(exc).__name__
        if attempt < _RETRIES:
            time.sleep(min(10.0, 1.0 * 2 ** (attempt - 1)) + random.uniform(0, 0.5))  # noqa: S311
    raise RulesetError(f"cannot fetch {ruleset.registry_id}: {last_error}")


def _cached(ruleset: RulesetConfig, cache_dir: Path, now: datetime) -> ResolvedRuleset | None:
    path = cache_dir / f"{_safe_name(ruleset.name)}.json"
    meta_path = path.with_suffix(".meta.json")
    try:
        data = path.read_bytes()
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    digest = hashlib.sha256(data).hexdigest()
    if not isinstance(meta, dict) or meta.get("sha256") != digest:
        return None  # tampered or partially written cache: refetch
    try:
        rules = count_rules(data)
        fetched = datetime.fromisoformat(str(meta.get("fetched_at")).replace("Z", "+00:00"))
    except (RulesetError, ValueError):
        return None
    stale = now - fetched > timedelta(hours=ruleset.max_age_hours)
    return ResolvedRuleset(
        ruleset.name, path, digest, rules, str(meta.get("source")), iso_utc(fetched), stale
    )


def resolve(
    cfg: SemgrepConfig,
    ruleset: RulesetConfig,
    *,
    root: Path,
    allow_network: bool,
    now: datetime | None = None,
) -> tuple[ResolvedRuleset, str | None]:
    """Return (ruleset, note). Refreshes stale registry packs when network is allowed."""
    now = now or datetime.now(UTC)
    if ruleset.source == "local":
        assert ruleset.path is not None  # noqa: S101 - validated by config
        path = resolve_in_root(root, ruleset.path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise RulesetError(
                f"local ruleset {ruleset.name} unreadable: {type(exc).__name__}"
            ) from None
        rules = count_rules(data)
        return ResolvedRuleset(
            ruleset.name, path, hashlib.sha256(data).hexdigest(), rules, "local"
        ), None
    cache_dir = resolve_in_root(root, cfg.cache_dir)
    cached = _cached(ruleset, cache_dir, now)
    if cached is not None and not cached.stale:
        return cached, None
    if allow_network:
        try:
            return fetch_registry(cfg, ruleset, cache_dir), None
        except RulesetError as exc:
            if cached is None:
                raise
            return (
                cached,
                f"ruleset {ruleset.name}: refresh failed ({exc}); "
                f"using cache from {cached.fetched_at}",
            )
    if cached is None:
        raise RulesetError(f"ruleset {ruleset.name} not cached (run 'extorq-scan update')")
    return (
        cached,
        f"ruleset {ruleset.name}: cache from {cached.fetched_at} "
        f"is older than {ruleset.max_age_hours}h",
    )
