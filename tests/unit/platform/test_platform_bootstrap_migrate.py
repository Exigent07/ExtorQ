"""bootstrap.py (secrets, TLS, producer registry), the migration runner and the root CLI.

Bootstrap runs against a temporary root (never the real var/); it needs the openssl
binary and is skipped without it. Generated values are compared, never printed.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from extorq.storage import migrate as mig

REPO = Path(__file__).resolve().parents[3]


def _load_bootstrap() -> Any:
    spec = importlib.util.spec_from_file_location(
        "extorq_bootstrap", REPO / "scripts" / "bootstrap.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations via sys.modules
    spec.loader.exec_module(module)
    return module


bootstrap = _load_bootstrap()
needs_openssl = pytest.mark.skipif(bootstrap.find_openssl() is None, reason="openssl missing")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@needs_openssl
def test_bootstrap_creates_private_material_and_is_idempotent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert bootstrap.bootstrap(tmp_path, rotate=False, rotate_ca=False) == 0
    var = tmp_path / "var"
    secrets_dir = var / "secrets"
    for directory in (
        var,
        secrets_dir,
        secrets_dir / "clickhouse",
        secrets_dir / "tokens",
        var / "tls",
    ):
        assert _mode(directory) == 0o700
    files = [p for p in var.rglob("*") if p.is_file()]
    assert files and all(_mode(p) == 0o600 for p in files)
    for user in bootstrap.CLICKHOUSE_USERS:
        assert (secrets_dir / "clickhouse" / f"{user}_password").is_file()
    for name in bootstrap.SIMPLE_SECRETS:
        assert len((secrets_dir / name).read_text().strip()) >= 32
    tokens = {
        spec.producer_id: (secrets_dir / "tokens" / f"{spec.producer_id}.token").read_text().strip()
        for spec in bootstrap.PRODUCERS
    }
    first_out = capsys.readouterr().out
    for value in tokens.values():
        assert value not in first_out  # only paths and counts are printed
    before = {p: p.read_bytes() for p in files}
    assert bootstrap.bootstrap(tmp_path, rotate=False, rotate_ca=False) == 0
    second_out = capsys.readouterr().out
    assert "created=0" in second_out and "rotated=0" in second_out
    assert {p: p.read_bytes() for p in files} == before  # nothing regenerated


@needs_openssl
def test_producer_registry_matches_plan_and_token_hashes(tmp_path: Path) -> None:
    assert bootstrap.bootstrap(tmp_path, rotate=False, rotate_ca=False) == 0
    secrets_dir = tmp_path / "var" / "secrets"
    registry = json.loads((secrets_dir / "producers.json").read_text())
    entries = {e["producer_id"]: e for e in registry["producers"]}
    assert set(entries) == {
        "macos-workstation-01",
        "linux-ssh-lab-vm-01",
        "k8s-inventory-extorq-lab",
        "k8s-otel-extorq-lab",
        "github-collector",
        "scanner-runner",
        "extorq-selftest",
    }
    for producer_id, entry in entries.items():
        token = (secrets_dir / "tokens" / f"{producer_id}.token").read_text().strip()
        assert entry["token_sha256"] == hashlib.sha256(token.encode()).hexdigest()
        assert token not in json.dumps(registry)
    for producer_id in ("macos-workstation-01", "linux-ssh-lab-vm-01", "k8s-inventory-extorq-lab"):
        assert {"service", "service_instance"} <= set(entries[producer_id]["allowed_kinds"])
    assert "service" not in entries["github-collector"]["allowed_kinds"]
    otel = entries["k8s-otel-extorq-lab"]
    assert otel["allowed_kinds"] == ["event", "collector_health"]
    assert otel["allowed_asset_patterns"] == ["k8s:extorq-lab", "k8s:extorq-lab/node/*"]
    assert entries["extorq-selftest"] == {
        **entries["extorq-selftest"],
        "allowed_kinds": ["collector_health"],
        "allowed_source_types": ["extorq.pipeline"],
    }
    # the registry validates with the gateway's own model
    from extorq.ingest.registry import ProducerRegistry

    assert len(ProducerRegistry(secrets_dir / "producers.json").producer_ids) == 7


@needs_openssl
def test_retired_producer_is_never_authorized_even_with_a_token_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Schema 2.0 retired ``simulation-runner``: a leftover token stays unauthorized."""
    assert bootstrap.bootstrap(tmp_path, rotate=False, rotate_ca=False) == 0
    tokens = tmp_path / "var" / "secrets" / "tokens"
    stale = tokens / "simulation-runner.token"
    stale.write_text("xtq_p_synthetic-stale-token-value\n", encoding="utf-8")
    stale.chmod(0o600)
    capsys.readouterr()
    assert bootstrap.bootstrap(tmp_path, rotate=False, rotate_ca=False) == 0  # idempotent
    out = capsys.readouterr().out
    assert "stale producer tokens" in out and "simulation-runner" in out
    assert "synthetic-stale-token-value" not in out  # ids only, never values
    assert stale.is_file()  # never deleted automatically
    registry = json.loads((tmp_path / "var/secrets/producers.json").read_text())
    ids = {e["producer_id"] for e in registry["producers"]}
    assert "simulation-runner" not in ids
    assert all("simulation_run" not in e["allowed_kinds"] for e in registry["producers"])
    assert all("extorq.simulation" not in e["allowed_source_types"] for e in registry["producers"])
    from extorq.ingest.registry import ProducerRegistry

    loaded = ProducerRegistry(tmp_path / "var/secrets/producers.json")
    assert loaded.authenticate("xtq_p_synthetic-stale-token-value") is None


@needs_openssl
def test_tls_material_ecdsa_p256_sans_and_validity(tmp_path: Path) -> None:
    assert bootstrap.bootstrap(tmp_path, rotate=False, rotate_ca=False) == 0
    tls = tmp_path / "var" / "tls"
    openssl = bootstrap.find_openssl()
    assert bootstrap._leaf_matches(openssl, tls / "ca.crt", tls / "gateway.crt")
    # CA: at most 825 days; gateway leaf: shorter (397 days, renewed at < 30 days left).
    for cert, days in (("ca.crt", bootstrap.CA_DAYS), ("gateway.crt", bootstrap.LEAF_DAYS)):
        text = subprocess.run(
            [openssl, "x509", "-noout", "-text", "-in", str(tls / cert)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        assert "prime256v1" in text or "P-256" in text
        assert days <= 825
        assert bootstrap._cert_valid_for(openssl, tls / cert, (days - 1) * 86400)
        assert not bootstrap._cert_valid_for(openssl, tls / cert, (days + 1) * 86400)


@needs_openssl
def test_rotate_changes_tokens_and_leaf_but_keeps_ca(tmp_path: Path) -> None:
    assert bootstrap.bootstrap(tmp_path, rotate=False, rotate_ca=False) == 0
    tls = tmp_path / "var" / "tls"
    token_file = tmp_path / "var/secrets/tokens/macos-workstation-01.token"
    ca, leaf, token = (
        (tls / "ca.crt").read_bytes(),
        (tls / "gateway.crt").read_bytes(),
        token_file.read_text(),
    )
    assert bootstrap.bootstrap(tmp_path, rotate=True, rotate_ca=False) == 0
    assert (tls / "ca.crt").read_bytes() == ca
    assert (tls / "gateway.crt").read_bytes() != leaf
    assert token_file.read_text() != token


@needs_openssl
def test_every_compose_file_secret_is_created_by_bootstrap(tmp_path: Path) -> None:
    """compose.yaml must never reference a var/ secret that `make bootstrap` does not make."""
    import yaml

    assert bootstrap.bootstrap(tmp_path, rotate=False, rotate_ca=False) == 0
    compose = yaml.safe_load((REPO / "compose.yaml").read_text(encoding="utf-8"))
    files = [
        spec["file"]
        for spec in compose["secrets"].values()
        if isinstance(spec, dict) and "file" in spec
    ]
    assert "./var/secrets/grafana_secret_key" in files
    for path in files:
        if "jev_api_key" in path:
            # Operator-provided (`make jev-key` copies it from .env); bootstrap must never
            # invent it. It must still live under var/ and be overridable.
            assert path.startswith("${EXTORQ_JEV_KEY_PATH:-./var/secrets/"), path
            continue
        assert path.startswith("./var/"), path
        assert (tmp_path / path[2:]).is_file(), f"bootstrap does not create {path}"
    grafana = compose["services"]["grafana"]
    assert "grafana_secret_key" in grafana["secrets"]
    assert (
        grafana["environment"]["GF_SECURITY_SECRET_KEY__FILE"] == "/run/secrets/grafana_secret_key"
    )


# ── migration runner ──────────────────────────────────────────────────


def test_split_statements_respects_quotes_and_comments() -> None:
    sql = (
        "-- comment; not a statement\nCREATE TABLE a (x String DEFAULT ';');\n"
        "/* block; */ INSERT INTO a VALUES ('it''s;fine', \"q;\");\n\nSELECT 1"
    )
    assert mig.split_statements(sql) == [
        "CREATE TABLE a (x String DEFAULT ';')",
        "INSERT INTO a VALUES ('it''s;fine', \"q;\")",
        "SELECT 1",
    ]
    with pytest.raises(mig.MigrationError):
        mig.split_statements("SELECT 'unterminated")


def test_render_placeholders_validate_hex() -> None:
    good = mig.password_hash("synthetic-password", "a" * 32)
    assert good.sha256 == hashlib.sha256(b"synthetic-password" + b"a" * 32).hexdigest()
    text = "BY '{{password_sha256:extorq_ingest}}' SALT '{{ password_salt : extorq_ingest }}'"
    assert mig.render(text, {"extorq_ingest": good}) == f"BY '{good.sha256}' SALT '{'a' * 32}'"
    with pytest.raises(mig.MigrationError, match="unknown user"):
        mig.render("{{password_salt:nobody}}", {"extorq_ingest": good})
    bad = mig.PasswordHash(sha256="'; DROP USER x; --", salt="a" * 32)
    with pytest.raises(mig.MigrationError, match="invalid"):
        mig.render("{{password_sha256:extorq_ingest}}", {"extorq_ingest": bad})


class FakeClickHouse:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.applied: dict[str, str] = {}
        self.users = set(mig.SERVICE_USERS)

    def command(self, sql: str) -> None:
        self.commands.append(sql)

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> Any:
        class Result:
            def __init__(self, rows: list[tuple[Any, ...]]) -> None:
                self.result_rows = rows

        if "schema_migrations" in sql:
            return Result(sorted(self.applied.items()))
        if "system.users" in sql:
            return Result([(u,) for u in sorted(self.users)])
        raise AssertionError(sql)

    def insert(self, table: str, data: list[list[Any]], column_names: list[str]) -> None:
        assert table == "extorq.schema_migrations"
        row = dict(zip(column_names, data[0], strict=True))
        self.applied[row["version"]] = row["checksum"]


def _migrations(tmp_path: Path) -> tuple[Path, Path]:
    mdir, pdir = tmp_path / "migrations", tmp_path / "passwords"
    mdir.mkdir()
    pdir.mkdir()
    (mdir / "0001_one.sql").write_text("CREATE TABLE IF NOT EXISTS t1 (x UInt8) ENGINE=Log;")
    (mdir / "0002_two.sql").write_text(
        "ALTER USER extorq_ingest IDENTIFIED WITH sha256_hash BY "
        "'{{password_sha256:extorq_ingest}}' SALT '{{password_salt:extorq_ingest}}';"
    )
    for user in mig.SERVICE_USERS:
        (pdir / f"{user}_password").write_text(f"synthetic-{user}\n")
    return mdir, pdir


def test_migrator_applies_in_order_records_checksums_and_is_idempotent(tmp_path: Path) -> None:
    mdir, pdir = _migrations(tmp_path)
    ch = FakeClickHouse()
    report = mig.Migrator(ch, mdir, pdir).run()
    assert report.applied == ["0001_one", "0002_two"]
    assert report.passwords_synced == len(mig.SERVICE_USERS)
    assert not any("synthetic-" in c for c in ch.commands)  # plaintext never in SQL
    ch.commands.clear()
    again = mig.Migrator(ch, mdir, pdir).run()
    assert again.applied == [] and again.already_applied == ["0001", "0002"]
    assert not any(c.startswith("CREATE TABLE IF NOT EXISTS t1") for c in ch.commands)


def test_migrator_refuses_changed_applied_migration(tmp_path: Path) -> None:
    mdir, pdir = _migrations(tmp_path)
    ch = FakeClickHouse()
    mig.Migrator(ch, mdir, pdir).run()
    (mdir / "0001_one.sql").write_text("CREATE TABLE IF NOT EXISTS t1 (x UInt16) ENGINE=Log;")
    with pytest.raises(mig.MigrationError, match="checksum mismatch"):
        mig.Migrator(ch, mdir, pdir).run()


def test_migration_file_names_are_strict(tmp_path: Path) -> None:
    (tmp_path / "1_bad.sql").write_text("SELECT 1")
    with pytest.raises(mig.MigrationError, match="unexpected migration file name"):
        mig.discover_migrations(tmp_path)


def test_repository_migrations_are_well_formed() -> None:
    migrations = mig.discover_migrations(REPO / "infra" / "clickhouse" / "migrations")
    assert [m.version for m in migrations][:5] == ["0001", "0002", "0003", "0004", "0005"]
    for migration in migrations:
        assert mig.split_statements(migration.text)
        assert (
            "PASSWORD"
            not in migration.text.upper()
            .replace("PASSWORD_SHA256", "")
            .replace("PASSWORD_SALT", "")
            .replace("PASSWORD_", "")
            or migration.version == "0002"
        )


# ── root CLI ──────────────────────────────────────────────────────────


def test_root_cli_lazy_imports_fail_friendly() -> None:
    import typer

    from extorq import cli

    runner = CliRunner()
    assert runner.invoke(cli.app, ["version"]).exit_code == 0
    with pytest.raises(typer.Exit) as exit_info:
        cli.load("extorq.definitely_missing_module", "main")
    assert exit_info.value.exit_code == cli.EXIT_MODULE_MISSING
    assert cli.load("extorq.storage.migrate", "main") is mig.main
