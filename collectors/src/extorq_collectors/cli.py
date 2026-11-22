"""``extorq-collect``: run, inspect and flush the host-native collectors (owner: platform).

Commands::

    extorq-collect run [--only a,b] [--once] [--config FILE ...] [--config-dir DIR]
    extorq-collect status [--config ...] [--json]
    extorq-collect flush [--only a,b] [--timeout 60] [--requeue-dead]

Paths (``config/collectors``, ``var/collectors``, ``var/secrets/tokens``,
``var/tls/ca.crt``) resolve against ``EXTORQ_HOME`` or, when unset, the ExtorQ
repository root found from the current directory. Output never contains tokens
or record contents.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Annotated, Any

import typer

app = typer.Typer(
    name="extorq-collect",
    help="ExtorQ collectors: run, inspect and flush buffered records.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)

EXIT_INVALID = 2
EXIT_BUFFERED = 75  # EX_TEMPFAIL: committed locally, not yet acknowledged by the gateway


def _detect_home() -> Path | None:
    """Repository root: nearest ancestor with ``config/collectors`` and ``pyproject.toml``."""
    if os.environ.get("EXTORQ_HOME"):
        return None  # pydantic-settings reads it
    here = Path.cwd().resolve()
    for candidate in (here, *here.parents):
        if (candidate / "config" / "collectors").is_dir() and (
            candidate / "pyproject.toml"
        ).is_file():
            return candidate
    return None


def _settings() -> Any:
    from extorq.common.config import Settings

    home = _detect_home()
    return Settings(home=home) if home is not None else Settings()


def _configure_logging() -> None:
    from extorq.common.logging import configure_logging

    configure_logging("collectors")


def _load_configs(
    settings: Any,
    config: list[Path] | None,
    config_dir: Path | None,
    only: str | None,
    *,
    include_disabled: bool = False,
) -> list[Any]:
    from extorq_collectors.sdk.config import (
        ConfigLoadError,
        load_collector_configs,
        load_collector_files,
    )

    try:
        if config:
            configs = load_collector_files(
                [settings.resolve(p) for p in config], include_disabled=include_disabled
            )
        else:
            directory = settings.resolve(config_dir or settings.collectors_config_dir)
            configs = load_collector_configs(directory, include_disabled=include_disabled)
    except ConfigLoadError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_INVALID) from None
    if only:
        wanted = {item.strip() for item in only.split(",") if item.strip()}
        unknown = sorted(wanted - {c.collector_id for c in configs})
        if unknown:
            typer.echo(
                f"error: unknown or disabled collector id(s): {', '.join(unknown)}", err=True
            )
            raise typer.Exit(EXIT_INVALID)
        configs = [c for c in configs if c.collector_id in wanted]
    return configs


ConfigOpt = Annotated[
    list[Path] | None,
    typer.Option("--config", help="Collector YAML file(s); default: every file in --config-dir."),
]
ConfigDirOpt = Annotated[
    Path | None,
    typer.Option(
        "--config-dir", help="Directory of collector YAML files (default config/collectors)."
    ),
]
OnlyOpt = Annotated[
    str | None, typer.Option("--only", help="Comma-separated collector ids to run.")
]


@app.command()
def run(
    only: OnlyOpt = None,
    once: Annotated[bool, typer.Option("--once", help="One cycle each, drain, exit.")] = False,
    config: ConfigOpt = None,
    config_dir: ConfigDirOpt = None,
    drain_seconds: Annotated[
        float,
        typer.Option("--drain-seconds", help="--once: max seconds to deliver buffered records."),
    ] = 60.0,
) -> None:
    """Run collectors (each in its own thread; failures are isolated and reported)."""
    _configure_logging()
    from extorq_collectors.sdk.runner import Runner

    settings = _settings()
    configs = _load_configs(settings, config, config_dir, only)
    if not configs:
        typer.echo("error: no enabled collectors configured", err=True)
        raise typer.Exit(1)
    code = Runner(configs, settings, drain_seconds=drain_seconds).run(once=once)
    raise typer.Exit(code)


@app.command()
def status(
    config: ConfigOpt = None,
    config_dir: ConfigDirOpt = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Show local collector state (outbox depth, dead letters, last health). Read-only."""
    from extorq_collectors.sdk.runner import state_path
    from extorq_collectors.sdk.state import read_status

    settings = _settings()
    configs = _load_configs(settings, config, config_dir, None, include_disabled=True)
    rows: list[dict[str, Any]] = []
    for cfg in configs:
        rows.append(
            {
                "collector_id": cfg.collector_id,
                "enabled": cfg.enabled,
                "producer_id": cfg.producer_id,
                "asset_id": cfg.asset_id,
                **(read_status(state_path(settings, cfg.collector_id)) or {"state": "none"}),
            }
        )
    if as_json:
        typer.echo(json.dumps(rows, indent=2, sort_keys=True, default=str))
        return
    for row in rows:
        health = row.get("last_health") or {}
        typer.echo(
            f"{row['collector_id']:<28} enabled={row['enabled']!s:<5} "
            f"outbox={row.get('outbox_depth', '-')!s:<6} dead={row.get('dead_letters', '-')!s:<4} "
            f"status={health.get('status', '-'):<9} last_report={health.get('reported_at', '-')}"
        )
        if health.get("last_error"):
            typer.echo(f"    last_error: {health['last_error']}")


@app.command()
def flush(
    only: OnlyOpt = None,
    config: ConfigOpt = None,
    config_dir: ConfigDirOpt = None,
    timeout: Annotated[float, typer.Option(help="Seconds to keep trying.")] = 60.0,
    requeue_dead: Annotated[
        bool,
        typer.Option(
            "--requeue-dead",
            help="First move dead-lettered records back into the outbox "
            "(after fixing the cause of the rejection).",
        ),
    ] = False,
) -> None:
    """Deliver buffered outbox records of the configured collectors without collecting."""
    _configure_logging()
    from extorq_collectors.sdk.runner import default_client, state_path
    from extorq_collectors.sdk.sender import Sender
    from extorq_collectors.sdk.state import StateStore, read_status

    settings = _settings()
    targets = [
        (c.collector_id, c.producer_id)
        for c in _load_configs(settings, config, config_dir, only, include_disabled=True)
    ]
    remaining = 0
    deadline = time.monotonic() + timeout
    for collector_id, producer_id in targets:
        path = state_path(settings, collector_id)
        state = read_status(path)
        if not state.get("outbox_depth") and not (requeue_dead and state.get("dead_letters")):
            continue
        store = StateStore(path)
        if requeue_dead:
            requeued = store.requeue_dead()
            if requeued:
                typer.echo(f"{collector_id}: requeued {requeued} dead-lettered record(s)")
        client = default_client(settings, producer_id)
        try:
            sender = Sender(store, client, producer_id)
            report = sender.send_pending(deadline=deadline)
            while not report.drained and time.monotonic() < deadline:
                wait = max(0.0, sender.state.next_attempt_at - sender.clock())
                time.sleep(min(1.0, wait) if wait > 0 else 0.05)
                report = sender.send_pending(deadline=deadline)
            depth = store.outbox_depth()
        finally:
            client.close()
            store.close()
        remaining += depth
        typer.echo(
            f"{collector_id}: accepted={report.accepted} duplicates={report.duplicates} "
            f"dead_lettered={report.dead_lettered} still_buffered={depth}"
            + (f" last_error={report.error}" if report.error else "")
        )
    raise typer.Exit(EXIT_BUFFERED if remaining else 0)


def main() -> None:  # pragma: no cover - console script shim
    app()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
