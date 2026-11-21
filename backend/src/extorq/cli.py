"""Root ``extorq`` CLI (PLAN §5). Every command imports its implementation lazily.

Commands owned by other teams resolve their module only when invoked; a module
that does not exist yet produces a clear error and exit code 3 instead of
breaking unrelated commands (``extorq gateway`` must work before ``extorq api``
exists).
"""

from __future__ import annotations

import importlib
import json
import sys
from collections.abc import Callable
from typing import Annotated, Any

import typer

app = typer.Typer(
    name="extorq",
    help="ExtorQ platform services and operator commands.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)
rules_app = typer.Typer(help="Detection rules (owner: C2).", no_args_is_help=True)
context_app = typer.Typer(help="Investigation contexts (owner: C2).", no_args_is_help=True)
ai_app = typer.Typer(
    help="AI enrichment (owner: E). Uses budgeted providers.", no_args_is_help=True
)
healthcheck_app = typer.Typer(
    help="Container healthchecks (used by compose).", hidden=True, no_args_is_help=True
)
app.add_typer(rules_app, name="rules")
app.add_typer(context_app, name="context")
app.add_typer(ai_app, name="ai")
app.add_typer(healthcheck_app, name="healthcheck")

EXIT_MODULE_MISSING = 3


def load(module: str, attribute: str) -> Any:
    """Import ``module.attribute`` lazily with a friendly error when it is not built yet."""
    try:
        mod = importlib.import_module(module)
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        if missing and (module == missing or module.startswith(missing + ".")):
            typer.echo(
                f"error: {module} is not available yet (see docs/team/PLAN.md for its "
                f"owner); this command cannot run in this build.",
                err=True,
            )
            raise typer.Exit(EXIT_MODULE_MISSING) from None
        raise
    try:
        return getattr(mod, attribute)
    except AttributeError:
        typer.echo(f"error: {module}.{attribute} is not implemented yet.", err=True)
        raise typer.Exit(EXIT_MODULE_MISSING) from None


def first_available(candidates: list[tuple[str, str]]) -> Any:
    for module, attribute in candidates:
        try:
            mod = importlib.import_module(module)
        except ModuleNotFoundError as exc:
            if exc.name and (module == exc.name or module.startswith(exc.name + ".")):
                continue
            raise
        target = getattr(mod, attribute, None)
        if target is not None:
            return target
    names = ", ".join(f"{m}.{a}" for m, a in candidates)
    typer.echo(f"error: none of {names} is available yet.", err=True)
    raise typer.Exit(EXIT_MODULE_MISSING)


def _exit(code: int | None) -> None:
    if code:
        raise typer.Exit(int(code))


def _print_model(model: Any) -> None:
    if hasattr(model, "model_dump_json"):
        typer.echo(model.model_dump_json(indent=2))
    else:
        typer.echo(json.dumps(model, indent=2, default=str))


# ── platform services (owner: A) ──────────────────────────────────────


@app.command()
def migrate(
    status: Annotated[bool, typer.Option("--status", help="Only report applied/pending.")] = False,
) -> None:
    """Apply ClickHouse migrations and sync RBAC passwords (admin identity)."""
    main: Callable[..., int] = load("extorq.storage.migrate", "main")
    _exit(main(status_only=status))


@app.command()
def gateway() -> None:
    """Serve the HTTPS ingestion gateway."""
    main: Callable[[], int] = load("extorq.ingest.server", "main")
    _exit(main())


@app.command()
def writer() -> None:
    """Drain the durable spool into ClickHouse."""
    main: Callable[[], int] = load("extorq.pipeline.writer", "main")
    _exit(main())


@healthcheck_app.command("gateway")
def healthcheck_gateway(
    url: str = "https://127.0.0.1:8443/healthz",
    ca_file: str = "/run/secrets/tls_ca_crt",
) -> None:
    """Exit 0 when the gateway answers /healthz with 200 over verified TLS."""
    import ssl
    import urllib.request

    try:
        context = ssl.create_default_context(cafile=ca_file)
        with urllib.request.urlopen(url, context=context, timeout=3) as response:  # noqa: S310
            ok = response.status == 200
    except Exception:  # noqa: BLE001 - any failure means unhealthy
        ok = False
    _exit(0 if ok else 1)


@healthcheck_app.command("writer")
def healthcheck_writer(max_age: float = 60.0) -> None:
    """Exit 0 when the writer heartbeat file is fresh."""
    check: Callable[[float], int] = load("extorq.pipeline.writer", "healthcheck")
    _exit(check(max_age))


@app.command()
def version() -> None:
    """Print the backend version."""
    from extorq.version import __version__

    typer.echo(__version__)


# ── detection (owner: C2) ─────────────────────────────────────────────


@app.command()
def detector(once: Annotated[bool, typer.Option("--once")] = False) -> None:
    """Run the detection + correlation service."""
    main: Callable[..., None] = load("extorq.detection.service", "main")
    main(once=once)


@rules_app.command("validate")
def rules_validate(root: str = "rules") -> None:
    """Load and validate every rule under ROOT."""
    load_rules: Callable[..., list[Any]] = load("extorq.detection.registry", "load_rules")
    try:
        rules = load_rules(root, strict=True)
    except Exception as exc:  # noqa: BLE001 - report validation failures, do not trace
        typer.echo(f"rules invalid: {exc}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"{len(rules)} rules valid")


@rules_app.command(
    "test", context_settings={"allow_extra_args": True, "ignore_unknown_options": True}
)
def rules_test(ctx: typer.Context) -> None:
    """Run the rule test harness (arguments are passed through)."""
    main: Callable[[list[str]], int] = load("extorq.detection.harness", "main")
    _exit(main(list(ctx.args)))


@context_app.command("build")
def context_build(alert_id: str) -> None:
    """Build and store the InvestigationContext for ALERT_ID."""
    builder_cls = load("extorq.correlation.builder", "ContextBuilder")
    save_context = load("extorq.correlation.store", "save_context")
    from extorq.storage.clickhouse import get_client

    ctx = builder_cls(get_client("detect")).build(alert_id)
    save_context(get_client("detect"), ctx)
    _print_model(ctx)


# ── AI (owner: E) ─────────────────────────────────────────────────────


@app.command("ai-worker")
def ai_worker(once: Annotated[bool, typer.Option("--once")] = False) -> None:
    """Run the AI triage worker (Jev; advisory only)."""
    main: Callable[..., None] = load("extorq.ai.worker", "main")
    main(once=once)


@ai_app.command("triage")
def ai_triage(alert_id: str, requested_by: str = "system:cli") -> None:
    """Request a Jev triage assessment for ALERT_ID (budgeted)."""
    service_cls = load("extorq.ai.service", "AIService")
    _print_model(service_cls().request_triage(alert_id, requested_by))


@ai_app.command("summary")
def ai_summary(alert_id: str, requested_by: str = "analyst:cli") -> None:
    """Request a Gemini summary for ALERT_ID (budgeted)."""
    service_cls = load("extorq.ai.service", "AIService")
    _print_model(service_cls().request_summary(alert_id, requested_by))


@ai_app.command("eval", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def ai_eval(ctx: typer.Context) -> None:
    """Run the AI evaluation harness (arguments are passed through)."""
    main = first_available([("extorq.ai.evaluation", "main"), ("extorq.ai.eval", "main")])
    _exit(main(list(ctx.args)))


# ── API (owner: D1) ───────────────────────────────────────────────────


@app.command()
def api(
    host: Annotated[str, typer.Option(envvar="EXTORQ_API_BIND_HOST")] = "127.0.0.1",
    port: Annotated[int, typer.Option(envvar="EXTORQ_API_PORT")] = 8100,
) -> None:
    """Serve the analyst API (compose binds 0.0.0.0:8000 inside the container)."""
    create_app = load("extorq.api.app", "create_app")
    import uvicorn

    configure = first_available(
        [("extorq.api.logs", "configure"), ("extorq.common.logging", "configure_logging")]
    )
    configure("api")
    uvicorn.run(
        create_app,
        factory=True,
        host=host,
        port=port,
        proxy_headers=False,
        server_header=False,
        log_config=None,
        access_log=False,
    )


def main() -> None:  # pragma: no cover - console script shim
    app()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
