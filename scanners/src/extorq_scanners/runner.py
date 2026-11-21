"""Scan orchestration: one ScanRun lifecycle per configured target.

For every target: submit ``running`` -> run the pinned tool in a hardened
container -> normalise -> decide the status (``extorq_scanners.status``) ->
submit findings and the terminal ScanRun (last) and a CollectorHealth record.
Any unexpected exception still closes the ScanRun as ``failed``; a crash of the
runner itself is reported as ``failed`` by the next run (``state.interrupted``).
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from extorq.common.logging import get_logger
from extorq.contracts import (
    CollectorHealth,
    HealthStatus,
    ScanCoverage,
    ScanRun,
    ScanStatus,
    SkippedCheck,
    utc_now,
)
from extorq.contracts.identity import sha256_hex
from extorq.contracts.ingest import CollectorHealthRecord, FindingRecord, ScanRunRecord
from extorq_scanners import __version__, rulesets, trivydb
from extorq_scanners.config import ConfigError, ScannersConfig, TargetConfig, resolve_in_root
from extorq_scanners.docker import ContainerResult, ContainerSpec, DockerRunner, Mount
from extorq_scanners.inventory import (
    InventoryFetcher,
    InventoryUnavailable,
    fetch_inventory,
    fetch_packages,
)
from extorq_scanners.k8s_index import K8sIndex, index_paths
from extorq_scanners.models import NormalizeContext, NormalizedScan, ReportFormatError
from extorq_scanners.normalize.common import bounded_attributes
from extorq_scanners.normalize.gitleaks import normalize_gitleaks
from extorq_scanners.normalize.semgrep import normalize_semgrep
from extorq_scanners.normalize.trivy import normalize_trivy
from extorq_scanners.sanitize import MEDIUM, clean
from extorq_scanners.sbom import InventoryError, build_cyclonedx, parse_inventory
from extorq_scanners.scope import scope_for
from extorq_scanners.services import UnitInventoryError, package_service_map, unit_states
from extorq_scanners.sink import RecordSink
from extorq_scanners.state import StateStore
from extorq_scanners.status import ProcessOutcome, Verdict, decide

log = get_logger("extorq.scanners")

GITLEAKS_LEAKS_EXIT = 42
_TRIVY_COMMON = [
    "--format",
    "json",
    "--cache-backend",
    "memory",
    "--disable-telemetry",
    "--skip-version-check",
]
_TRIVY_DB_FLAGS = [
    "--skip-db-update",
    "--skip-java-db-update",
    "--skip-vex-repo-update",
    "--offline-scan",
]
#: Trivy log lines at ERROR level that are expected and harmless.
_TRIVY_BENIGN = ("Falling back to embedded checks",)
_TRIVY_LOG = re.compile(r"\t(ERROR|FATAL)\t(.*)$")
_VERSION = {
    "trivy": re.compile(r"Version:\s*v?([0-9][0-9A-Za-z.+-]*)"),
    "gitleaks": re.compile(r"v?([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]*)"),
    "semgrep": re.compile(r"([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]*)"),
}
#: Semgrep runs as a non-root uid with a read-only root fs: HOME on the container tmpfs.
_SEMGREP_ENV = {"SEMGREP_ENABLE_VERSION_CHECK": "0", "HOME": "/tmp"}  # noqa: S108 - container path
_HEALTH = {
    ScanStatus.SUCCEEDED: HealthStatus.OK,
    ScanStatus.PARTIAL: HealthStatus.DEGRADED,
    ScanStatus.FAILED: HealthStatus.FAILED,
}
Normalizer = Callable[[object, str, NormalizeContext], NormalizedScan]


@dataclass
class Plan:
    """Mode-specific execution plan for one scan."""

    spec: ContainerSpec | None = None
    timeout: float = 600
    max_stdout: int = 64 * 1024 * 1024
    success_codes: frozenset[int] = frozenset({0})
    normalize: Normalizer | None = None
    ctx: dict[str, Any] = field(default_factory=dict)
    skipped: list[SkippedCheck] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    tool_errors: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    preflight_error: str | None = None
    cleanup: list[Path] = field(default_factory=list)


@dataclass
class TargetOutcome:
    target: str
    kind: str
    asset_id: str
    status: ScanStatus | None
    scan_run_id: str | None = None
    findings: int = 0
    severities: dict[str, int] = field(default_factory=dict)
    error: str | None = None
    skipped_reason: str | None = None
    duration_seconds: float = 0.0


def trivy_log_errors(stderr: str) -> list[str]:
    errors: list[str] = []
    for line in stderr.splitlines():
        match = _TRIVY_LOG.search(line)
        if match and not any(b in match.group(2) for b in _TRIVY_BENIGN):
            text = clean(match.group(2), 300)
            if text and len(errors) < 20:
                errors.append(text)
    return errors


def _tag_version(image: str) -> str:
    name = image.split("@", 1)[0]
    tag = name.rsplit(":", 1)[1] if ":" in name.rsplit("/", 1)[-1] else "unknown"
    return f"{tag.lstrip('v')} (image tag)"


class ScanRunner:
    def __init__(
        self,
        cfg: ScannersConfig,
        root: Path,
        sink: RecordSink,
        *,
        docker: DockerRunner | None = None,
        state: StateStore | None = None,
        inventory_fetcher: InventoryFetcher = fetch_packages,
        unit_fetcher: InventoryFetcher = fetch_inventory,
        allow_network: bool = True,
        clock: Callable[[], datetime] = utc_now,
        raw_dir: Path | None = None,
    ) -> None:
        self.cfg = cfg
        self.root = root.resolve()
        self.sink = sink
        self.work_dir = resolve_in_root(self.root, cfg.work_dir)
        self.trivy_cache = resolve_in_root(self.root, cfg.trivy.cache_dir)
        self.state = state or StateStore(resolve_in_root(self.root, cfg.state_dir))
        self.docker = docker or DockerRunner(
            docker_bin=cfg.docker.binary,
            name_prefix=cfg.docker.container_prefix,
            memory=cfg.docker.memory,
            cpus=cfg.docker.cpus,
            pids_limit=cfg.docker.pids_limit,
            tmpfs_mb=cfg.docker.tmpfs_mb,
            allowed_images=[cfg.images.trivy, cfg.images.gitleaks, cfg.images.semgrep],
            allowed_roots=[self.root],
        )
        self.inventory_fetcher = inventory_fetcher
        self.unit_fetcher = unit_fetcher
        #: Debug only: keep raw tool output (0600, may contain scanned content; never commit).
        self.raw_dir = raw_dir
        self.allow_network = allow_network
        self.clock = clock
        self._versions: dict[str, str] = {}

    # ── public API ────────────────────────────────────────────────────
    def run(self, targets: list[TargetConfig]) -> list[TargetOutcome]:
        with self.state.lock():
            self.recover_interrupted()
            return [self.run_target(t) for t in targets]

    def recover_interrupted(self) -> int:
        """Report scans left ``running`` by a crashed runner as ``failed``."""
        runs = self.state.interrupted()
        for run in runs:
            data = run.model_dump()
            data.update(
                status=ScanStatus.FAILED,
                finished_at=max(self.clock(), run.started_at),
                findings_count=0,
                error="scanner runner was interrupted before the scan completed",
            )
            final = ScanRun.model_validate(data)
            self.sink.submit([ScanRunRecord(data=final)])
            self.state.clear_inflight(run.scan_run_id)
            log.warning("scan_marked_failed_after_interruption", scan_run_id=run.scan_run_id)
        return len(runs)

    def tool_version(self, tool: str) -> str:
        if tool in self._versions:
            return self._versions[tool]
        image = getattr(self.cfg.images, tool)
        args = {
            "trivy": ["--version"],
            "gitleaks": ["version"],
            "semgrep": ["semgrep", "--version"],
        }[tool]
        spec = ContainerSpec(
            image=image,
            args=args,
            env=_SEMGREP_ENV if tool == "semgrep" else {},
            platform=self.cfg.docker.semgrep_platform if tool == "semgrep" else None,
            purpose=f"{tool}-version",
        )
        version = _tag_version(image)
        result = self.docker.run(spec, timeout=120, max_stdout_bytes=65536)
        if result.outcome.exit_code == 0:
            match = _VERSION[tool].search(result.stdout.decode("utf-8", "replace"))
            if match:
                version = match.group(1)[:64]
        self._versions[tool] = version
        return version

    # ── one target ────────────────────────────────────────────────────
    def resolve_image(self, target: TargetConfig) -> str | None:
        """Local image reference to scan (``newest``: latest created tag of the repository)."""
        if target.image is None:
            return None
        if target.image_select == "exact":
            return target.image if self.docker.image_present(target.image) else None
        return self.docker.newest_image(target.image)

    def missing_reason(self, target: TargetConfig) -> str | None:
        if target.mode == "image":
            if self.resolve_image(target) is None:
                return f"image {target.image} is not present locally"
            return None
        if target.mode == "sbom":
            return None
        for rel in target.paths:
            try:
                path = resolve_in_root(self.root, rel)
            except ConfigError as exc:
                return str(exc)
            if not path.exists():
                return f"target path {rel} does not exist"
        return None

    def run_target(self, target: TargetConfig) -> TargetOutcome:
        tool = target.tool
        missing = self.missing_reason(target)
        if missing and target.when_missing == "skip":
            log.info("scan_target_skipped", target=target.name, reason=missing)
            return TargetOutcome(
                target.name, target.kind, target.asset_id, None, skipped_reason=missing
            )
        scope = scope_for(target)
        version = self.tool_version(tool)
        scan_run_id = uuid.uuid4().hex
        started = self.clock()
        running = ScanRun(
            scan_run_id=scan_run_id,
            scanner=tool,
            scanner_version=version,
            asset_id=target.asset_id,
            scope=scope,
            started_at=started,
            status=ScanStatus.RUNNING,
            producer_id=self.cfg.producer_id,
            attributes=bounded_attributes({"target": target.name, "mode": target.mode}),
        )
        self.sink.submit([ScanRunRecord(data=running)])
        self.state.mark_inflight(running)
        log.info("scan_started", target=target.name, scan_run_id=scan_run_id, scanner=tool)

        plan = Plan()
        normalized = NormalizedScan()
        result: ContainerResult | None = None
        try:
            plan = Plan(preflight_error=missing) if missing else self.prepare(target, scan_run_id)
            if plan.preflight_error is None and plan.spec is not None:
                result = self.docker.run(
                    plan.spec, timeout=plan.timeout, max_stdout_bytes=plan.max_stdout
                )
                process = result.outcome
                self._save_raw(target, scan_run_id, result)
            else:
                process = ProcessOutcome(
                    None, start_error=plan.preflight_error or "no execution plan"
                )
            finished = self.clock()
            normalized, parse_error = self._parse(target, scan_run_id, plan, result, finished)
            if tool == "trivy" and result is not None:
                plan.tool_errors.extend(trivy_log_errors(result.stderr))
                if "Falling back to embedded checks" in result.stderr:
                    plan.notes.append(
                        "misconfiguration checks: trivy's embedded check bundle "
                        "(check bundle downloads disabled)"
                    )
            tool_errors = plan.tool_errors + normalized.tool_errors
            skipped = plan.skipped + normalized.skipped
            verdict = decide(
                process,
                success_exit_codes=plan.success_codes,
                parse_error=parse_error,
                tool_errors=tool_errors,
                skipped=[s.check for s in skipped],
                dropped_findings=normalized.dropped,
                nothing_scanned=normalized.nothing_scanned,
                timeout_seconds=plan.timeout,
            )
        except Exception as exc:
            log.exception("scan_internal_error", target=target.name, scan_run_id=scan_run_id)
            finished = self.clock()
            process = ProcessOutcome(None, start_error="internal error")
            verdict = Verdict(
                ScanStatus.FAILED, f"internal error in scanner runner: {type(exc).__name__}"
            )
            normalized, skipped, tool_errors = NormalizedScan(), [], []
        finally:
            for path in plan.cleanup:
                with contextlib.suppress(OSError):
                    if path.is_dir():
                        shutil.rmtree(path)
                    else:
                        path.unlink()

        findings = normalized.findings if verdict.status is not ScanStatus.FAILED else []
        notes = plan.notes + normalized.notes + [f"tool error: {e}" for e in tool_errors[:10]]
        coverage = ScanCoverage(
            checks_total=normalized.checks_total,
            checks_run=normalized.checks_run,
            skipped=skipped[:256],
            notes=[n for n in (clean(x, MEDIUM) for x in notes) if n][:32],
        )
        attributes = {
            **plan.attributes,
            **normalized.attributes,
            "target": target.name,
            "mode": target.mode,
            "tool_image": getattr(self.cfg.images, tool),
            "exit_code": process.exit_code,
            "duration_seconds": process.duration_seconds,
            "redactions": normalized.redactions,
            "dropped_findings": normalized.dropped,
            "duplicate_findings": normalized.duplicates,
            "runner_version": __version__,
        }
        final = ScanRun(
            scan_run_id=scan_run_id,
            scanner=tool,
            scanner_version=normalized.scanner_version or version,
            asset_id=target.asset_id,
            scope=scope,
            started_at=started,
            finished_at=max(finished, started),
            status=verdict.status,
            coverage=coverage,
            findings_count=len(findings),
            error=clean(verdict.error, MEDIUM),
            producer_id=self.cfg.producer_id,
            attributes=bounded_attributes(attributes),
        )
        records: list[Any] = [FindingRecord(data=f) for f in findings]
        records.append(ScanRunRecord(data=final))
        if self.cfg.emit_health:
            records.append(CollectorHealthRecord(data=self._health(target, final, len(findings))))
        self.sink.submit(records)
        self.state.clear_inflight(scan_run_id)
        self.state.record(target.name, final)
        severities = Counter(f.severity.value for f in findings)
        log.info(
            "scan_finished",
            target=target.name,
            scan_run_id=scan_run_id,
            status=final.status.value,
            findings=len(findings),
            duration_seconds=process.duration_seconds,
        )
        return TargetOutcome(
            target.name,
            target.kind,
            target.asset_id,
            final.status,
            scan_run_id,
            len(findings),
            dict(severities),
            final.error,
            duration_seconds=process.duration_seconds,
        )

    def _save_raw(self, target: TargetConfig, scan_run_id: str, result: ContainerResult) -> None:
        if self.raw_dir is None:
            return
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.raw_dir, 0o700)
        for suffix, data in (("stdout", result.stdout), ("stderr", result.stderr.encode())):
            path = self.raw_dir / f"{target.name}.{scan_run_id}.{suffix}"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)

    def _health(self, target: TargetConfig, run: ScanRun, findings: int) -> CollectorHealth:
        last_success = (
            run.finished_at
            if run.status is ScanStatus.SUCCEEDED
            else self.state.last_success(target.name)
        )
        return CollectorHealth(
            collector_id=f"scanner.{target.name}",
            collector_type="scanner",
            asset_id=target.asset_id,
            source_types=[f"scanner.{target.tool}"],
            status=_HEALTH[run.status],
            reported_at=self.clock(),
            last_attempt_at=run.started_at,
            last_success_at=last_success,
            last_error=run.error,
            events_collected=findings,
            collector_version=f"extorq-scanners {__version__}; {run.scanner} {run.scanner_version}"[
                :256
            ],
            interval_seconds=target.interval_seconds,
            details=bounded_attributes(
                {
                    "scan_run_id": run.scan_run_id,
                    "scan_status": run.status.value,
                    "scope_hash": run.scope.scope_hash,
                }
            ),
        )

    def _parse(
        self,
        target: TargetConfig,
        scan_run_id: str,
        plan: Plan,
        result: ContainerResult | None,
        finished: datetime,
    ) -> tuple[NormalizedScan, str | None]:
        if result is None or plan.normalize is None:
            return NormalizedScan(), None
        out = result.outcome
        if out.start_error or out.timed_out or out.output_truncated:
            return NormalizedScan(), None
        text = result.stdout.strip()
        if not text:
            return NormalizedScan(), "empty output"
        try:
            doc = json.loads(text)
        except ValueError as exc:
            pos = getattr(exc, "pos", "?")
            return NormalizedScan(), f"malformed JSON (parse error at byte {pos})"
        ctx = NormalizeContext(
            asset_id=target.asset_id,
            scanner=target.tool,
            scan_run_id=scan_run_id,
            observed_at=finished,
            mode=target.mode,
            severity_overrides=self.cfg.gitleaks.severity_overrides,
            default_secret_severity=self.cfg.gitleaks.default_severity,
            **plan.ctx,
        )
        try:
            return plan.normalize(doc, result.stderr, ctx), None
        except ReportFormatError as exc:
            return NormalizedScan(), str(exc)

    # ── mode-specific plans ───────────────────────────────────────────
    def prepare(self, target: TargetConfig, scan_run_id: str) -> Plan:
        if target.kind == "trivy" or target.kind == "linux-packages":
            return self._prepare_trivy(target, scan_run_id)
        if target.kind == "gitleaks":
            return self._prepare_gitleaks(target)
        return self._prepare_semgrep(target, scan_run_id)

    def _trivy_db(self, plan: Plan) -> bool:
        meta = trivydb.read_metadata(self.trivy_cache)
        if trivydb.is_stale(meta, self.cfg.trivy.db_max_age_hours) and self.allow_network:
            error = trivydb.update_db(
                self.docker,
                self.cfg.images.trivy,
                self.trivy_cache,
                self.cfg.trivy.db_update_timeout_seconds,
            )
            if error:
                plan.notes.append(error)
            meta = trivydb.read_metadata(self.trivy_cache)
        if meta is None:
            plan.preflight_error = "trivy vulnerability DB not available (run 'extorq-scan update')"
            return False
        if trivydb.is_stale(meta, self.cfg.trivy.db_max_age_hours):
            plan.notes.append(f"trivy DB older than {self.cfg.trivy.db_max_age_hours}h")
        if meta.updated_at:
            plan.attributes["trivy_db_updated_at"] = meta.updated_at.isoformat()
        return True

    def _prepare_trivy(self, target: TargetConfig, scan_run_id: str) -> Plan:
        cfg = self.cfg.trivy
        plan = Plan(
            timeout=cfg.timeout_seconds,
            max_stdout=cfg.max_output_mb * 1024 * 1024,
            normalize=lambda doc, _stderr, ctx: normalize_trivy(doc, ctx),
        )
        mounts = [Mount(self.trivy_cache, "/cache")]
        self.trivy_cache.mkdir(parents=True, exist_ok=True)
        timeout_flag = ["--timeout", f"{cfg.timeout_seconds}s"]
        needs_db = target.mode == "sbom" or (
            target.mode in {"fs", "image"} and "vuln" in target.scanners
        )
        if needs_db and not self._trivy_db(plan):
            return plan
        if target.mode == "fs":
            src = resolve_in_root(self.root, target.paths[0])
            mounts.append(Mount(src, "/src"))
            args = [
                "--cache-dir",
                "/cache",
                "fs",
                "--scanners",
                ",".join(sorted(set(target.scanners))),
                *_TRIVY_COMMON,
                *_TRIVY_DB_FLAGS,
                "--skip-check-update",
                "--no-progress",
                *timeout_flag,
                "/src",
            ]
            if "misconfig" in target.scanners:
                plan.ctx["k8s_index"] = self._k8s_index(target.paths, {target.paths[0]: ""})
        elif target.mode == "config":
            for rel in target.paths:
                mounts.append(Mount(resolve_in_root(self.root, rel), f"/src/{rel}"))
            args = [
                "--cache-dir",
                "/cache",
                "config",
                *_TRIVY_COMMON,
                "--skip-check-update",
                *timeout_flag,
                "/src",
            ]
            plan.ctx["k8s_index"] = self._k8s_index(target.paths, None)
        elif target.mode == "image":
            tar_dir = self.work_dir / "images" / scan_run_id
            error = self._save_image(target, tar_dir, plan)
            if error:
                plan.preflight_error = error
                return plan
            mounts.append(Mount(tar_dir, "/images"))
            plan.ctx["identity_qualifier"] = f"image:{target.image_repository}"
            plan.ctx["artifact"] = target.image_repository
            args = [
                "--cache-dir",
                "/cache",
                "image",
                "--input",
                "/images/image.tar",
                "--scanners",
                ",".join(sorted(set(target.scanners))),
                *_TRIVY_COMMON,
                *_TRIVY_DB_FLAGS,
                "--skip-check-update",
                "--no-progress",
                *timeout_flag,
            ]
        else:  # sbom
            sbom_dir = self.work_dir / "sbom" / scan_run_id
            error = self._write_sbom(target, sbom_dir, plan)
            if error:
                plan.preflight_error = error
                return plan
            mounts.append(Mount(sbom_dir, "/sbom"))
            args = [
                "--cache-dir",
                "/cache",
                "sbom",
                *_TRIVY_COMMON,
                *_TRIVY_DB_FLAGS,
                "--no-progress",
                *timeout_flag,
                "/sbom/inventory.cdx.json",
            ]
        plan.spec = ContainerSpec(
            image=self.cfg.images.trivy, args=args, mounts=mounts, purpose=f"trivy-{target.mode}"
        )
        return plan

    def _k8s_index(self, paths: list[str], mount_rel: dict[str, str] | None) -> K8sIndex:
        try:
            return index_paths(self.root, paths, mount_rel)
        except OSError:
            return {}

    def _save_image(self, target: TargetConfig, tar_dir: Path, plan: Plan) -> str | None:
        ref = self.resolve_image(target)
        if ref is None:
            return f"image {target.image} is not present locally"
        tar_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(tar_dir, 0o700)
        plan.cleanup.append(tar_dir)
        tar = tar_dir / "image.tar"
        docker = self.docker.docker
        fmt = "{{.Id}}|{{.Os}}/{{.Architecture}}|{{json .RepoDigests}}"
        try:
            inspect = subprocess.run(
                [docker, "image", "inspect", "--format", fmt, ref],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if inspect.returncode != 0:
                return f"image {ref} is not present locally"
            image_id, platform, digests = [*inspect.stdout.strip().split("|", 2), "", ""][:3]
            plan.attributes["image_ref"] = ref
            plan.attributes["image_id"] = image_id[:128]
            plan.attributes["image_platform"] = platform[:64]
            with contextlib.suppress(ValueError):
                plan.attributes["repo_digests"] = [
                    str(d)[:256] for d in json.loads(digests or "[]")
                ][:8]
            save_cmd = [docker, "image", "save", "--output", str(tar)]
            if re.fullmatch(r"[a-z0-9]+/[a-z0-9]+", platform):
                save_cmd += ["--platform", platform]
            saved = subprocess.run(
                [*save_cmd, ref], capture_output=True, text=True, timeout=900, check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return f"docker image save failed: {type(exc).__name__}"
        plan.notes.append(f"scanned image {ref} ({image_id[:19]})")
        if saved.returncode != 0 or not tar.is_file():
            return f"docker image save failed: {clean(saved.stderr, 300) or saved.returncode}"
        os.chmod(tar, 0o600)
        return None

    def _write_sbom(self, target: TargetConfig, sbom_dir: Path, plan: Plan) -> str | None:
        try:
            doc = self.inventory_fetcher(self.root, self.cfg.inventory)
            inventory = parse_inventory(doc)
        except (InventoryUnavailable, InventoryError) as exc:
            return f"package inventory unavailable: {exc}"
        if inventory.truncated:
            plan.skipped.append(
                SkippedCheck(check="inventory", reason="package inventory truncated by the VM")
            )
        for err in inventory.errors:
            plan.tool_errors.append(f"inventory: {err}")
        invalid = [s for s in inventory.skipped if not s.endswith("(not installed)")]
        if invalid:
            plan.skipped.append(
                SkippedCheck(
                    check="inventory-entries",
                    reason=f"{len(invalid)} invalid package entries ignored",
                )
            )
        sbom = build_cyclonedx(inventory, asset_id=target.asset_id, generated_at=self.clock())
        data = json.dumps(sbom, sort_keys=True).encode("utf-8")
        sbom_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(sbom_dir, 0o700)
        plan.cleanup.append(sbom_dir)
        for path in (
            sbom_dir / "inventory.cdx.json",
            self.work_dir / "sbom" / f"{target.name}.latest.cdx.json",
        ):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        plan.notes.append(
            f"SBOM: {len(inventory.packages)} dpkg packages of "
            f"{inventory.os_id} {inventory.os_version}"
            f" (inventory collected {inventory.collected_at or 'at unknown time'})"
        )
        plan.attributes.update(
            {
                "inventory_packages": len(inventory.packages),
                "inventory_collected_at": inventory.collected_at,
                "inventory_hostname": inventory.hostname,
                "os": f"{inventory.os_id} {inventory.os_version}",
                "sbom_sha256": sha256_hex(data),
            }
        )
        if target.service_attribution:
            self._attribute_services(target, plan)
        return None

    def _attribute_services(self, target: TargetConfig, plan: Plan) -> None:
        """Evidence-gated package -> host service hints (never affects the scan status)."""
        try:
            units = unit_states(self.unit_fetcher(self.root, self.cfg.inventory))
        except (InventoryUnavailable, UnitInventoryError) as exc:
            plan.notes.append(f"service attribution skipped: unit inventory unavailable ({exc})")
            return
        rules = [(rule.packages, rule.unit) for rule in target.service_attribution]
        hints, notes = package_service_map(target.asset_id, rules, units)
        plan.notes.extend(notes)
        if hints:
            plan.ctx["package_services"] = hints
            plan.attributes["service_units"] = sorted({h.unit for h in hints.values()})

    def _prepare_gitleaks(self, target: TargetConfig) -> Plan:
        cfg = self.cfg.gitleaks
        plan = Plan(
            timeout=cfg.timeout_seconds,
            max_stdout=cfg.max_output_mb * 1024 * 1024,
            success_codes=frozenset({0, GITLEAKS_LEAKS_EXIT}),
            normalize=normalize_gitleaks,
        )
        src = resolve_in_root(self.root, target.paths[0])
        if target.mode == "git" and not (src / ".git").exists():
            plan.preflight_error = f"{target.paths[0]} is not a git repository"
            return plan
        config_file = resolve_in_root(self.root, cfg.config_file)
        if not config_file.is_file():
            plan.preflight_error = f"gitleaks config {cfg.config_file} not found"
            return plan
        if (config_file.parent / ".gitleaksignore").exists():
            plan.preflight_error = (
                "refusing to run: a .gitleaksignore exists next to the gitleaks config"
            )
            return plan
        plan.attributes["gitleaks_config_sha256"] = sha256_hex(config_file.read_bytes())
        plan.spec = ContainerSpec(
            image=self.cfg.images.gitleaks,
            args=[
                target.mode,
                "/src",
                "--config",
                f"/config/{config_file.name}",
                "--gitleaks-ignore-path",
                "/config",
                "--ignore-gitleaks-allow",
                "--redact",
                "--no-banner",
                "--no-color",
                "--log-level",
                "info",
                "--max-target-megabytes",
                str(cfg.max_target_megabytes),
                "--exit-code",
                str(GITLEAKS_LEAKS_EXIT),
                "--report-format",
                "json",
                "--report-path",
                "-",
            ],
            mounts=[Mount(src, "/src"), Mount(config_file.parent, "/config")],
            env={
                "HOME": "/tmp",  # noqa: S108 - container path (private tmpfs)
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "safe.directory",
                "GIT_CONFIG_VALUE_0": "/src",
            },
            purpose=f"gitleaks-{target.mode}",
        )
        plan.notes.append(
            f"gitleaks {target.mode}: default rules + {config_file.name}; inline gitleaks:allow "
            "and repository .gitleaks.toml/.gitleaksignore are ignored; files > "
            f"{cfg.max_target_megabytes} MB skipped"
        )
        return plan

    def _prepare_semgrep(self, target: TargetConfig, scan_run_id: str) -> Plan:
        cfg = self.cfg.semgrep
        plan = Plan(
            timeout=cfg.timeout_seconds,
            max_stdout=cfg.max_output_mb * 1024 * 1024,
            normalize=lambda doc, stderr, ctx: normalize_semgrep(doc, ctx, stderr),
        )
        src = resolve_in_root(self.root, target.paths[0])
        rules_dir = self.work_dir / "semgrep" / scan_run_id
        rules_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(rules_dir, 0o700)
        plan.cleanup.append(rules_dir)
        config_args: list[str] = []
        total = 0
        used: list[str] = []
        digests: list[str] = []
        for name in target.rulesets:
            try:
                resolved, note = rulesets.resolve(
                    cfg, cfg.rulesets[name], root=self.root, allow_network=self.allow_network
                )
            except rulesets.RulesetError as exc:
                plan.skipped.append(SkippedCheck(check=f"ruleset:{name}", reason=str(exc)[:500]))
                continue
            if note:
                plan.notes.append(note)
            staged = rules_dir / f"{name.replace('/', '-')}.yml"
            shutil.copyfile(resolved.path, staged)
            config_args += ["--config", staged.name]
            total += resolved.rules
            used.append(name)
            digests.append(f"{name}={resolved.sha256}")
        if not used:
            plan.preflight_error = "no semgrep ruleset available: " + "; ".join(
                s.reason for s in plan.skipped
            )
            return plan
        ignore_files = self._find_named(src, ".semgrepignore")
        if ignore_files:
            plan.notes.append(
                f"target contains {ignore_files} .semgrepignore file(s); "
                "paths they exclude are not scanned"
            )
        plan.ctx.update(rules_total=total, ruleset_label=",".join(used))
        plan.attributes["ruleset_sha256"] = digests
        plan.spec = ContainerSpec(
            image=self.cfg.images.semgrep,
            args=[
                "semgrep",
                "scan",
                *config_args,
                "--metrics=off",
                "--disable-version-check",
                "--disable-nosem",
                "--json",
                "--timeout",
                str(cfg.per_rule_timeout_seconds),
                "--max-target-bytes",
                str(cfg.max_target_bytes),
                "--jobs",
                str(cfg.jobs),
                "/src",
            ],
            mounts=[Mount(src, "/src"), Mount(rules_dir, "/rules")],
            env={
                "HOME": "/tmp",  # noqa: S108 - container path (private tmpfs)
                "SEMGREP_ENABLE_VERSION_CHECK": "0",
                "SEMGREP_SEND_METRICS": "off",
            },
            workdir="/rules",
            platform=cfg_platform if (cfg_platform := self.cfg.docker.semgrep_platform) else None,
            purpose="semgrep",
        )
        plan.notes.append(
            "semgrep: nosemgrep comments are ignored (--disable-nosem); metrics off; offline"
        )
        return plan

    @staticmethod
    def _find_named(base: Path, name: str, limit: int = 20_000) -> int:
        count = seen = 0
        for _dirpath, dirs, files in os.walk(base, followlinks=False):
            dirs[:] = [d for d in dirs if d != ".git"]
            seen += len(files)
            count += files.count(name)
            if seen > limit:
                break
        return count
