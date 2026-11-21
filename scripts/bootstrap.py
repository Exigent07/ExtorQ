#!/usr/bin/env python3
"""ExtorQ bootstrap: prerequisites, local secrets, TLS material and producer registry.

Usage::

    uv run python scripts/bootstrap.py            # idempotent: create what is missing
    uv run python scripts/bootstrap.py --rotate   # rotate passwords, tokens and the gateway cert
    uv run python scripts/bootstrap.py --rotate --rotate-ca   # also replace the local CA

Security properties:

* Standard library only (plus the ``openssl`` binary), so it can run before
  ``uv sync`` and has no third-party supply chain.
* Everything it creates lives under ``var/`` (directories 0700, files 0600).
* It prints only paths and counts, never secret values. ``.env`` is never read
  or modified (only its *presence* is reported).
* Files are written atomically (temp file + fsync + rename), so an interrupted
  run never leaves a truncated secret behind.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: PLAN §4.4 ClickHouse identities. Password files: var/secrets/clickhouse/<user>_password.
CLICKHOUSE_USERS: tuple[str, ...] = (
    "extorq_admin",
    "extorq_ingest",
    "extorq_detect",
    "extorq_rules_ro",
    "extorq_ai",
    "extorq_api_ro",
    "extorq_api_writer",
    "extorq_grafana",
)

#: Simple single-value secrets: var/secrets/<name>.
SIMPLE_SECRETS: tuple[str, ...] = (
    "grafana_admin_password",
    "api_service_token",
    "frontend_session_secret",
    "analyst_password",
    "viewer_password",
)

#: Tools needed by some part of the platform; reported by name when missing.
PREREQUISITES: tuple[str, ...] = (
    "docker",
    "uv",
    "pnpm",
    "kind",
    "kubectl",
    "qemu-system-aarch64",
    "openssl",
)

_TELEMETRY_KINDS = [
    "event",
    "asset",
    "inventory_item",
    "finding",
    "scan_run",
    "collector_health",
]
#: Contract 1.1 (PLAN §10): host and Kubernetes-inventory producers also report the
#: services they discover and their instances (processes, containers, Pods).
_SERVICE_AWARE_KINDS = [*_TELEMETRY_KINDS, "service", "service_instance"]
#: "any configured lab asset" (PLAN §4.2/§4.3).
_LAB_ASSET_PATTERNS = ["macos:workstation-01", "linux:lab-vm-01", "k8s:extorq-lab*", "github:*"]


@dataclass(frozen=True)
class ProducerSpec:
    producer_id: str
    allowed_kinds: list[str]
    allowed_source_types: list[str]
    allowed_asset_patterns: list[str]


#: PLAN §4.3 + §10 (service kinds). The gateway authorizes every record against this
#: registry. ``extorq-selftest`` is the SDK heartbeat example's identity (docs/collectors.md):
#: it may only report CollectorHealth for ExtorQ's own pipeline (source ``extorq.pipeline``)
#: from the Mac where it runs (proposal in docs/team/interface-changes/A.md).
PRODUCERS: tuple[ProducerSpec, ...] = (
    ProducerSpec(
        "macos-workstation-01", _SERVICE_AWARE_KINDS, ["macos.*"], ["macos:workstation-01"]
    ),
    ProducerSpec("linux-ssh-lab-vm-01", _SERVICE_AWARE_KINDS, ["linux.*"], ["linux:lab-vm-01"]),
    ProducerSpec(
        "k8s-inventory-extorq-lab",
        _SERVICE_AWARE_KINDS,
        ["k8s.api_inventory", "k8s.events", "k8s.posture"],
        ["k8s:extorq-lab*"],
    ),
    ProducerSpec(
        "k8s-otel-extorq-lab", ["event"], ["k8s.audit", "k8s.container_log"], ["k8s:extorq-lab*"]
    ),
    ProducerSpec("github-collector", _TELEMETRY_KINDS, ["github.*"], ["github:*"]),
    ProducerSpec(
        "scanner-runner",
        ["asset", "finding", "scan_run", "collector_health"],
        ["scanner.*"],
        _LAB_ASSET_PATTERNS,
    ),
    ProducerSpec(
        "simulation-runner", ["simulation_run"], ["extorq.simulation"], _LAB_ASSET_PATTERNS
    ),
    ProducerSpec(
        "extorq-selftest", ["collector_health"], ["extorq.pipeline"], ["macos:workstation-01"]
    ),
)

#: Gateway certificate subject alternative names (PLAN §4.2: VM reaches the Mac as 10.0.2.2,
#: kind pods use host.docker.internal, compose-internal clients use "ingest").
GATEWAY_SANS = (
    "DNS:localhost",
    "DNS:ingest",
    "DNS:host.docker.internal",
    "IP:127.0.0.1",
    "IP:10.0.2.2",
)
CA_DAYS = 825  # upper bound required by the platform brief
LEAF_DAYS = 397  # shorter leaf lifetime; re-issued automatically when < 30 days remain
LEAF_RENEW_SECONDS = 30 * 86400


class BootstrapError(RuntimeError):
    """Fatal bootstrap problem (message never contains secret values)."""


@dataclass
class Report:
    created: int = 0
    kept: int = 0
    rotated: int = 0
    updated: int = 0
    permissions_fixed: int = 0

    def record(self, outcome: str) -> None:
        setattr(self, outcome, getattr(self, outcome) + 1)


# ── filesystem helpers ────────────────────────────────────────────────


def ensure_private_dir(path: Path, report: Report) -> None:
    path.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777
    if mode != 0o700:
        path.chmod(0o700)
        report.permissions_fixed += 1


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` atomically with the given permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def fix_mode(path: Path, report: Report, mode: int = 0o600) -> None:
    if path.exists() and (path.stat().st_mode & 0o777) != mode:
        path.chmod(mode)
        report.permissions_fixed += 1


def read_secret(path: Path) -> str | None:
    """Return the stripped secret value, or None when missing/empty."""
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    return value or None


def new_secret(prefix: str = "", nbytes: int = 32) -> str:
    # URL-safe alphabet only: no quoting issues in XML, SQL hashes, headers or env files.
    return f"{prefix}{secrets.token_urlsafe(nbytes)}"


def ensure_secret(path: Path, *, rotate: bool, report: Report, prefix: str = "") -> str:
    existing = read_secret(path)
    if existing is not None and not rotate:
        fix_mode(path, report)
        report.record("kept")
        return existing
    value = new_secret(prefix)
    atomic_write(path, (value + "\n").encode("utf-8"))
    report.record("rotated" if existing is not None else "created")
    return value


# ── prerequisites ─────────────────────────────────────────────────────


def find_openssl() -> str | None:
    """Prefer a Homebrew OpenSSL 3+; fall back to whatever ``openssl`` is on PATH."""
    for candidate in (
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
    ):
        if os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("openssl")


def check_prerequisites() -> list[str]:
    missing = []
    for tool in PREREQUISITES:
        if tool == "openssl":
            if find_openssl() is None:
                missing.append(tool)
        elif shutil.which(tool) is None:
            missing.append(tool)
    return missing


# ── TLS ───────────────────────────────────────────────────────────────


def run_openssl(openssl: str, args: list[str]) -> str:
    """Run openssl with an argument list (never a shell); return stdout."""
    proc = subprocess.run(
        [openssl, *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        # stderr of openssl never contains key material for these subcommands.
        first_line = (proc.stderr.strip().splitlines() or ["(no stderr)"])[0][:300]
        raise BootstrapError(f"openssl {args[0]} failed: {first_line}")
    return proc.stdout


def _cert_valid_for(openssl: str, cert: Path, seconds: int) -> bool:
    proc = subprocess.run(
        [openssl, "x509", "-checkend", str(seconds), "-noout", "-in", str(cert)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return proc.returncode == 0


def _leaf_matches(openssl: str, ca_crt: Path, leaf: Path) -> bool:
    verify = subprocess.run(
        [openssl, "verify", "-CAfile", str(ca_crt), str(leaf)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if verify.returncode != 0:
        return False
    text = run_openssl(openssl, ["x509", "-noout", "-text", "-in", str(leaf)])
    rendered = text.replace("IP Address:", "IP:")
    return all(san in rendered for san in GATEWAY_SANS)


def _write_ext_file(directory: Path, name: str, content: str) -> Path:
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path


def ensure_tls(tls_dir: Path, *, rotate: bool, rotate_ca: bool, report: Report) -> None:
    openssl = find_openssl()
    if openssl is None:
        raise BootstrapError("openssl not found: cannot create TLS material")
    ca_key, ca_crt = tls_dir / "ca.key", tls_dir / "ca.crt"
    gw_key, gw_crt = tls_dir / "gateway.key", tls_dir / "gateway.crt"

    with tempfile.TemporaryDirectory(prefix="extorq-tls-", dir=tls_dir) as work_name:
        work = Path(work_name)
        os.chmod(work, 0o700)
        ca_changed = False
        ca_present = ca_key.exists() and ca_crt.exists()
        if rotate_ca or not ca_present or not _cert_valid_for(openssl, ca_crt, 90 * 86400):
            ca_conf = _write_ext_file(
                work,
                "ca.cnf",
                "[req]\ndistinguished_name = dn\nprompt = no\nx509_extensions = v3_ca\n"
                "[dn]\nCN = ExtorQ Local Development CA\nO = ExtorQ lab\n"
                "[v3_ca]\nbasicConstraints = critical,CA:TRUE,pathlen:0\n"
                "keyUsage = critical,keyCertSign,cRLSign\n"
                "subjectKeyIdentifier = hash\n",
            )
            tmp_key, tmp_crt = work / "ca.key", work / "ca.crt"
            run_openssl(
                openssl,
                [
                    "genpkey",
                    "-algorithm",
                    "EC",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-out",
                    str(tmp_key),
                ],
            )
            os.chmod(tmp_key, 0o600)
            run_openssl(
                openssl,
                [
                    "req",
                    "-x509",
                    "-new",
                    "-key",
                    str(tmp_key),
                    "-sha256",
                    "-days",
                    str(CA_DAYS),
                    "-config",
                    str(ca_conf),
                    "-extensions",
                    "v3_ca",
                    "-out",
                    str(tmp_crt),
                ],
            )
            atomic_write(ca_key, tmp_key.read_bytes())
            atomic_write(ca_crt, tmp_crt.read_bytes())
            report.record("rotated" if ca_present else "created")
            ca_changed = True
        else:
            fix_mode(ca_key, report)
            fix_mode(ca_crt, report)
            report.record("kept")

        leaf_present = gw_key.exists() and gw_crt.exists()
        leaf_ok = (
            leaf_present
            and not ca_changed
            and _cert_valid_for(openssl, gw_crt, LEAF_RENEW_SECONDS)
            and _leaf_matches(openssl, ca_crt, gw_crt)
        )
        if rotate or not leaf_ok:
            leaf_ext = _write_ext_file(
                work,
                "gateway.ext",
                "basicConstraints = critical,CA:FALSE\n"
                "keyUsage = critical,digitalSignature\n"
                "extendedKeyUsage = serverAuth\n"
                "subjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid,issuer\n"
                f"subjectAltName = {','.join(GATEWAY_SANS)}\n",
            )
            tmp_key, tmp_csr, tmp_crt = work / "gw.key", work / "gw.csr", work / "gw.crt"
            run_openssl(
                openssl,
                [
                    "genpkey",
                    "-algorithm",
                    "EC",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-out",
                    str(tmp_key),
                ],
            )
            os.chmod(tmp_key, 0o600)
            run_openssl(
                openssl,
                [
                    "req",
                    "-new",
                    "-key",
                    str(tmp_key),
                    "-subj",
                    "/CN=extorq-ingest-gateway/O=ExtorQ lab",
                    "-out",
                    str(tmp_csr),
                ],
            )
            serial = "0x" + secrets.token_hex(16)
            run_openssl(
                openssl,
                [
                    "x509",
                    "-req",
                    "-in",
                    str(tmp_csr),
                    "-CA",
                    str(ca_crt),
                    "-CAkey",
                    str(ca_key),
                    "-set_serial",
                    serial,
                    "-sha256",
                    "-days",
                    str(LEAF_DAYS),
                    "-extfile",
                    str(leaf_ext),
                    "-out",
                    str(tmp_crt),
                ],
            )
            if not _leaf_matches(openssl, ca_crt, tmp_crt):
                raise BootstrapError("issued gateway certificate failed verification")
            atomic_write(gw_key, tmp_key.read_bytes())
            atomic_write(gw_crt, tmp_crt.read_bytes())
            report.record("rotated" if leaf_present else "created")
        else:
            fix_mode(gw_key, report)
            fix_mode(gw_crt, report)
            report.record("kept")


# ── ClickHouse admin users.d snippet ──────────────────────────────────


def clickhouse_admin_xml(password: str) -> bytes:
    """users.d snippet defining the migrations-only admin (SHA-256 hash, private networks)."""
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return (
        "<!-- Generated by scripts/bootstrap.py. "
        "Contains a password hash: keep private (0600). -->\n"
        "<clickhouse>\n"
        "  <users>\n"
        "    <extorq_admin>\n"
        f"      <password_sha256_hex>{digest}</password_sha256_hex>\n"
        "      <networks>\n"
        "        <ip>127.0.0.1</ip>\n"
        "        <ip>::1</ip>\n"
        "        <ip>10.0.0.0/8</ip>\n"
        "        <ip>172.16.0.0/12</ip>\n"
        "        <ip>192.168.0.0/16</ip>\n"
        "      </networks>\n"
        "      <profile>extorq_admin</profile>\n"
        "      <quota>default</quota>\n"
        "      <access_management>1</access_management>\n"
        "      <named_collection_control>0</named_collection_control>\n"
        "    </extorq_admin>\n"
        "  </users>\n"
        "</clickhouse>\n"
    ).encode()


# ── producer registry ─────────────────────────────────────────────────


def producers_registry(token_dir: Path) -> bytes:
    entries = []
    for spec in PRODUCERS:
        token = read_secret(token_dir / f"{spec.producer_id}.token")
        if token is None:
            raise BootstrapError(f"token for producer {spec.producer_id} missing after generation")
        entries.append(
            {
                "producer_id": spec.producer_id,
                "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
                "allowed_kinds": spec.allowed_kinds,
                "allowed_source_types": spec.allowed_source_types,
                "allowed_asset_patterns": spec.allowed_asset_patterns,
            }
        )
    document = {"version": 1, "producers": entries}
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_if_changed(path: Path, data: bytes, report: Report) -> None:
    try:
        current = path.read_bytes()
    except FileNotFoundError:
        current = None
    if current == data:
        fix_mode(path, report)
        report.record("kept")
        return
    atomic_write(path, data)
    report.record("created" if current is None else "updated")


# ── main ──────────────────────────────────────────────────────────────


def bootstrap(root: Path, *, rotate: bool, rotate_ca: bool) -> int:
    missing = check_prerequisites()
    if missing:
        print(f"prerequisites missing ({len(missing)}): {', '.join(missing)}")
    else:
        print(f"prerequisites: all {len(PREREQUISITES)} found")
    if "openssl" in missing:
        print("error: openssl is required to create TLS material", file=sys.stderr)
        return 2

    old_umask = os.umask(0o077)
    try:
        report = Report()
        var = root / "var"
        secrets_dir = var / "secrets"
        ch_dir = secrets_dir / "clickhouse"
        token_dir = secrets_dir / "tokens"
        tls_dir = var / "tls"
        for directory in (var, secrets_dir, ch_dir, token_dir, tls_dir, var / "collectors"):
            ensure_private_dir(directory, report)

        ch_report = Report()
        admin_password = ""
        for user in CLICKHOUSE_USERS:
            value = ensure_secret(ch_dir / f"{user}_password", rotate=rotate, report=ch_report)
            if user == "extorq_admin":
                admin_password = value
        write_if_changed(
            ch_dir / "extorq_admin_users.xml", clickhouse_admin_xml(admin_password), ch_report
        )

        simple_report = Report()
        for name in SIMPLE_SECRETS:
            prefix = "xtq_s_" if name == "api_service_token" else ""
            ensure_secret(secrets_dir / name, rotate=rotate, report=simple_report, prefix=prefix)

        token_report = Report()
        for spec in PRODUCERS:
            ensure_secret(
                token_dir / f"{spec.producer_id}.token",
                rotate=rotate,
                report=token_report,
                prefix="xtq_p_",
            )
        registry_report = Report()
        write_if_changed(
            secrets_dir / "producers.json", producers_registry(token_dir), registry_report
        )

        tls_report = Report()
        ensure_tls(tls_dir, rotate=rotate, rotate_ca=rotate_ca, report=tls_report)
    except BootstrapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        os.umask(old_umask)

    def line(label: str, path: Path, rep: Report) -> None:
        rel = path.relative_to(root)
        print(
            f"{label:<28} {rel!s:<34} created={rep.created} kept={rep.kept} "
            f"rotated={rep.rotated} updated={rep.updated}"
        )

    line("clickhouse passwords+admin", ch_dir, ch_report)
    line("service secrets", secrets_dir, simple_report)
    line("producer tokens", token_dir, token_report)
    line("producer registry", secrets_dir / "producers.json", registry_report)
    line("tls (ca, gateway)", tls_dir, tls_report)
    fixed = (
        report.permissions_fixed
        + ch_report.permissions_fixed
        + simple_report.permissions_fixed
        + token_report.permissions_fixed
        + registry_report.permissions_fixed
        + tls_report.permissions_fixed
    )
    print(f"permissions fixed: {fixed}")
    print(f".env present: {'yes' if (root / '.env').exists() else 'no'} (never read or modified)")
    if rotate or rotate_ca:
        print(
            "rotation done: run 'make rotate-apply' (recreates ClickHouse, re-syncs RBAC "
            "passwords, restarts services) and restart collectors"
        )
    print(f"completed at {datetime.now(UTC).isoformat(timespec='seconds')}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="rotate ClickHouse passwords, service secrets, producer tokens and "
        "the gateway certificate",
    )
    parser.add_argument(
        "--rotate-ca",
        action="store_true",
        help="also replace the local CA (collectors must receive the new ca.crt)",
    )
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    return bootstrap(args.root.resolve(), rotate=args.rotate, rotate_ca=args.rotate_ca)


if __name__ == "__main__":
    sys.exit(main())
