"""``extorq-scan``: run ExtorQ's security scanners and submit ScanRuns + findings.

Commands:

* ``run <trivy|gitleaks|semgrep|linux-packages|all> [--target NAME ...]``
  scans the configured targets (``config/scanners.yaml``) and submits records as
  producer ``scanner-runner`` through the collector SDK outbox (``--sink gateway``,
  default) or writes them to a JSONL file (``--sink jsonl``, dry runs/debugging).
* ``update``: refresh the Trivy vulnerability DB and cached Semgrep registry packs
  (the only steps that use the network; scans themselves run with ``--network none``).
* ``flush``: deliver records still buffered in the outbox.
* ``list`` / ``validate``: show targets with their scope hashes / check the config.

Exit codes: 0 every scan succeeded (or was skipped as configured), 1 at least one
scan was partial, 2 at least one scan failed, 3 configuration error, 4 another run
holds the lock, 5 records could not be delivered (still buffered or dead-lettered).
The JSON summary on stdout never contains secrets or scanned content.
"""

from __future__ import annotations

import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Annotated, Any

import typer

from extorq.common.logging import configure_logging, get_logger
from extorq_scanners import rulesets, trivydb
from extorq_scanners.config import ConfigError, ScannersConfig, load_config, resolve_in_root
from extorq_scanners.runner import ScanRunner, TargetOutcome
from extorq_scanners.scope import scope_for
from extorq_scanners.sink import GatewaySink, JsonlSink, RecordSink
from extorq_scanners.state import LockedError, StateStore

app = typer.Typer(add_completion=False, no_args_is_help=True, help=__doc__)
log = get_logger("extorq.scanners.cli")

KINDS = ("trivy", "gitleaks", "semgrep", "linux-packages", "all")
EXIT_PARTIAL, EXIT_FAILED, EXIT_CONFIG, EXIT_LOCKED, EXIT_UNDELIVERED = 1, 2, 3, 4, 5

RootOpt = Annotated[
    Path, typer.Option("--root", help="ExtorQ repository root (paths in the config are relative)")
]
ConfigOpt = Annotated[
    Path | None, typer.Option("--config", help="config file (default <root>/config/scanners.yaml)")
]


def _setup_logging() -> None:
    """JSON logs via extorq.common.logging, moved to stderr (stdout carries the summary)."""
    configure_logging("scanner-runner")
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.StreamHandler) and handler.stream is sys.stdout:
            handler.setStream(sys.stderr)


def _load(root: Path, config: Path | None) -> ScannersConfig:
    path = config or (root / "config" / "scanners.yaml")
    try:
        return load_config(path)
    except ConfigError as exc:
        typer.echo(f"configuration error: {exc}", err=True)
        raise typer.Exit(EXIT_CONFIG) from None


def _emit(data: dict[str, Any]) -> None:
    typer.echo(json.dumps(data, indent=2, sort_keys=True, default=str))


def _gateway_sink(cfg: ScannersConfig, root: Path) -> GatewaySink:
    state_dir = resolve_in_root(root, cfg.state_dir)
    return GatewaySink(
        state_path=state_dir / "outbox.db",
        base_url=cfg.gateway.url,
        token_file=resolve_in_root(root, cfg.gateway.token_file),
        ca_file=resolve_in_root(root, cfg.gateway.ca_file),
        producer_id=cfg.producer_id,
        timeout_seconds=cfg.gateway.timeout_seconds,
    )


def _outcome_dict(outcome: TargetOutcome) -> dict[str, Any]:
    return {
        "target": outcome.target,
        "kind": outcome.kind,
        "asset_id": outcome.asset_id,
        "status": outcome.status.value if outcome.status else "skipped",
        "scan_run_id": outcome.scan_run_id,
        "findings": outcome.findings,
        "findings_by_severity": outcome.severities,
        "error": outcome.error,
        "skipped_reason": outcome.skipped_reason,
        "duration_seconds": outcome.duration_seconds,
    }


@app.command()
def run(
    kind: Annotated[str, typer.Argument(help="trivy | gitleaks | semgrep | linux-packages | all")],
    target: Annotated[
        list[str] | None, typer.Option("--target", "-t", help="only these target names")
    ] = None,
    root: RootOpt = Path("."),
    config: ConfigOpt = None,
    sink: Annotated[str, typer.Option(help="gateway (SDK outbox) | jsonl")] = "gateway",
    output: Annotated[Path | None, typer.Option(help="JSONL output file for --sink jsonl")] = None,
    offline: Annotated[
        bool, typer.Option(help="never use the network (no DB/ruleset refresh)")
    ] = False,
    drain_seconds: Annotated[
        float, typer.Option(help="max seconds to deliver buffered records at the end")
    ] = 120.0,
    save_raw: Annotated[
        Path | None,
        typer.Option(help="debug: keep raw tool output here (0600; may contain scanned content)"),
    ] = None,
) -> None:
    """Scan configured targets and submit ScanRuns, findings and health records."""
    _setup_logging()
    if kind not in KINDS:
        typer.echo(f"unknown kind {kind!r}; expected one of {', '.join(KINDS)}", err=True)
        raise typer.Exit(EXIT_CONFIG)
    root = root.resolve()
    cfg = _load(root, config)
    try:
        targets = cfg.select(kind, target)
    except ConfigError as exc:
        typer.echo(f"configuration error: {exc}", err=True)
        raise typer.Exit(EXIT_CONFIG) from None
    if not targets:
        typer.echo(f"no enabled targets for {kind!r}", err=True)
        raise typer.Exit(EXIT_CONFIG)

    record_sink: RecordSink
    if sink == "jsonl":
        out = output or (resolve_in_root(root, cfg.work_dir) / "records.jsonl")
        record_sink = JsonlSink(out)
    elif sink == "gateway":
        try:
            record_sink = _gateway_sink(cfg, root)
        except (ConfigError, ValueError, OSError) as exc:
            typer.echo(f"cannot open the gateway sink: {exc}", err=True)
            raise typer.Exit(EXIT_CONFIG) from None
    else:
        typer.echo("--sink must be 'gateway' or 'jsonl'", err=True)
        raise typer.Exit(EXIT_CONFIG)

    state = StateStore(resolve_in_root(root, cfg.state_dir))
    runner = ScanRunner(
        cfg, root, record_sink, state=state, allow_network=not offline, raw_dir=save_raw
    )
    outcomes: list[TargetOutcome] = []
    try:
        with state.lock():
            runner.recover_interrupted()
            for item in targets:
                outcomes.append(runner.run_target(item))
                record_sink.flush(min(30.0, drain_seconds))
            report = record_sink.close(drain_seconds)
    except LockedError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(EXIT_LOCKED) from None

    statuses = Counter(o.status.value if o.status else "skipped" for o in outcomes)
    summary = {
        "kind": kind,
        "sink": sink,
        "scans": [_outcome_dict(o) for o in outcomes],
        "status_counts": dict(statuses),
        "records_submitted": report.submitted,
        "records_delivered": report.delivered if sink == "gateway" else None,
        "records_buffered": report.buffered if sink == "gateway" else None,
        "delivery_errors": report.errors,
    }
    if sink == "jsonl":
        summary["output"] = str(output or (resolve_in_root(root, cfg.work_dir) / "records.jsonl"))
    _emit(summary)
    if statuses.get("failed"):
        raise typer.Exit(EXIT_FAILED)
    if statuses.get("partial"):
        raise typer.Exit(EXIT_PARTIAL)
    if sink == "gateway" and (report.buffered or any("dead" in e for e in report.errors)):
        raise typer.Exit(EXIT_UNDELIVERED)


@app.command()
def flush(
    root: RootOpt = Path("."),
    config: ConfigOpt = None,
    drain_seconds: Annotated[float, typer.Option(help="max seconds to try")] = 120.0,
) -> None:
    """Deliver records still buffered in the scanner outbox."""
    _setup_logging()
    root = root.resolve()
    cfg = _load(root, config)
    state = StateStore(resolve_in_root(root, cfg.state_dir))
    try:
        with state.lock():
            sink = _gateway_sink(cfg, root)
            dead = sink.dead_letters()
            report = sink.close(drain_seconds)
    except LockedError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(EXIT_LOCKED) from None
    _emit(
        {
            "delivered": report.delivered,
            "buffered": report.buffered,
            "dead_lettered_total": dead,
            "errors": report.errors,
        }
    )
    if report.buffered:
        raise typer.Exit(EXIT_UNDELIVERED)


@app.command()
def update(
    root: RootOpt = Path("."),
    config: ConfigOpt = None,
    trivy: Annotated[bool, typer.Option(help="refresh the Trivy vulnerability DB")] = True,
    semgrep: Annotated[bool, typer.Option(help="refresh Semgrep registry rulesets")] = True,
) -> None:
    """Refresh the Trivy DB and Semgrep registry rulesets (network)."""
    _setup_logging()
    root = root.resolve()
    cfg = _load(root, config)
    result: dict[str, Any] = {}
    failed = False
    if trivy:
        from extorq_scanners.docker import DockerRunner

        cache = resolve_in_root(root, cfg.trivy.cache_dir)
        cache.mkdir(parents=True, exist_ok=True)
        docker = DockerRunner(
            docker_bin=cfg.docker.binary,
            name_prefix=cfg.docker.container_prefix,
            memory=cfg.docker.memory,
            cpus=cfg.docker.cpus,
            pids_limit=cfg.docker.pids_limit,
            tmpfs_mb=cfg.docker.tmpfs_mb,
            allowed_images=[cfg.images.trivy],
            allowed_roots=[root],
        )
        error = trivydb.update_db(
            docker, cfg.images.trivy, cache, cfg.trivy.db_update_timeout_seconds
        )
        meta = trivydb.read_metadata(cache)
        result["trivy_db"] = {
            "error": error,
            "updated_at": meta.updated_at if meta else None,
            "downloaded_at": meta.downloaded_at if meta else None,
        }
        failed = failed or error is not None
    if semgrep:
        packs: dict[str, Any] = {}
        cache_dir = resolve_in_root(root, cfg.semgrep.cache_dir)
        for name, ruleset in cfg.semgrep.rulesets.items():
            if ruleset.source != "registry":
                continue
            try:
                resolved = rulesets.fetch_registry(cfg.semgrep, ruleset, cache_dir)
                packs[name] = {"rules": resolved.rules, "sha256": resolved.sha256}
            except rulesets.RulesetError as exc:
                packs[name] = {"error": str(exc)}
                failed = True
        result["semgrep_rulesets"] = packs
    _emit(result)
    if failed:
        raise typer.Exit(EXIT_FAILED)


@app.command("list")
def list_targets(root: RootOpt = Path("."), config: ConfigOpt = None) -> None:
    """Show configured targets, their assets and lifecycle scopes."""
    cfg = _load(root.resolve(), config)
    rows = []
    for t in cfg.targets:
        scope = scope_for(t)
        rows.append(
            {
                "name": t.name,
                "kind": t.kind,
                "mode": t.mode,
                "asset_id": t.asset_id,
                "enabled": t.enabled,
                "scope_targets": scope.targets,
                "scope_description": scope.description,
                "scope_hash": scope.scope_hash,
            }
        )
    _emit({"targets": rows})


@app.command()
def validate(root: RootOpt = Path("."), config: ConfigOpt = None) -> None:
    """Validate config/scanners.yaml (exit 3 when invalid)."""
    cfg = _load(root.resolve(), config)
    _emit({"valid": True, "targets": len(cfg.targets), "producer_id": cfg.producer_id})


def main() -> None:  # pragma: no cover - console entry point
    sys.exit(app())


if __name__ == "__main__":  # pragma: no cover
    main()
