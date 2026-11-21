"""Container configuration invariants (compose.yaml and Dockerfiles).

Derived from docs/team/PLAN.md section 4.1 and AGENTS.md invariant 5:

compose.yaml (skipped until it exists; owner A)
* Every published port binds ``127.0.0.1`` explicitly, and only the ports
  documented in PLAN 4.1 / docs/security.md are published.
* ClickHouse publishes nothing itself; any ClickHouse-facing proxy that
  publishes a port is only in the ``debug`` profile.
* The ``data`` network is ``internal: true`` and ClickHouse is attached to it only.
* No ``privileged``, host namespaces, Docker socket mounts or dangerous capabilities.
* Images are pinned (explicit tag that is not ``latest``, or a digest).
* AI provider secrets reach only ``ai-worker`` and ``api``; secret-looking
  environment variables never carry literal values.

Dockerfiles (every ``Dockerfile``/``*.Dockerfile`` in the repository)
* The final stage switches to a non-root ``USER``.
* Base images are pinned; no ``curl | sh`` installs; no secrets in ENV/ARG.

Advisory hardening gaps (``read_only``, ``cap_drop``, ``no-new-privileges``)
are reported as warnings, not failures; docs/security.md tracks them.
"""

from __future__ import annotations

import re
import warnings
from typing import Any

import pytest
import yaml
from security_helpers import REPO_ROOT, format_findings, iter_files, read_text, rel

COMPOSE_FILE = REPO_ROOT / "compose.yaml"

#: Host ports documented in PLAN 4.1 (127.0.0.1 only). Update docs/security.md with any change.
DOCUMENTED_HOST_PORTS = {
    8443: "ingest",
    8000: "api",
    3000: "frontend",
    3001: "grafana",
    18123: "clickhouse-debug",
}
AI_SERVICES = frozenset({"ai-worker", "api"})
AI_SECRET_HINT = re.compile(r"(jev|gemini|typesafe)", re.IGNORECASE)
SECRET_ENV_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)$", re.IGNORECASE)
DANGEROUS_CAPS = frozenset(
    {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH"}
)


def _load_compose() -> dict[str, Any]:
    data = yaml.safe_load(read_text(COMPOSE_FILE)) or {}
    assert isinstance(data, dict), "compose.yaml must be a mapping"
    return data


requires_compose = pytest.mark.skipif(
    not COMPOSE_FILE.exists(), reason="compose.yaml not present yet (owner: A)"
)


def _services() -> dict[str, dict[str, Any]]:
    services = _load_compose().get("services") or {}
    return {name: (svc or {}) for name, svc in services.items()}


def _port_entries(service: dict[str, Any]) -> list[tuple[str | None, str | None, str]]:
    """Normalise ports to (host_ip, published, raw) tuples."""
    entries: list[tuple[str | None, str | None, str]] = []
    for port in service.get("ports") or []:
        if isinstance(port, dict):
            entries.append(
                (
                    str(port["host_ip"]) if port.get("host_ip") is not None else None,
                    str(port["published"]) if port.get("published") is not None else None,
                    repr(port),
                )
            )
            continue
        raw = str(port)
        spec = raw.split("/", 1)[0]
        if spec.startswith("["):  # [::1]:8000:8000
            host_ip, _, rest = spec[1:].partition("]:")
            published = rest.split(":", 1)[0] if ":" in rest else None
            entries.append((host_ip, published, raw))
            continue
        parts = spec.split(":")
        if len(parts) == 3:
            entries.append((parts[0], parts[1], raw))
        elif len(parts) == 2:
            entries.append((None, parts[0], raw))
        else:
            entries.append((None, None, raw))  # container port only: random host port on 0.0.0.0
    return entries


def _is_clickhouse_facing(name: str, service: dict[str, Any]) -> bool:
    image = str(service.get("image", ""))
    return "clickhouse" in name or image.startswith("clickhouse/")


@requires_compose
def test_published_ports_bind_loopback_only() -> None:
    problems: list[str] = []
    for name, service in _services().items():
        for host_ip, published, raw in _port_entries(service):
            if host_ip != "127.0.0.1":
                problems.append(f"{name}: port {raw} must bind 127.0.0.1 explicitly")
                continue
            try:
                port = int(str(published))
            except ValueError:
                problems.append(f"{name}: port {raw} must publish a fixed numeric host port")
                continue
            if port not in DOCUMENTED_HOST_PORTS:
                problems.append(
                    f"{name}: host port {port} is not documented in PLAN 4.1/security.md"
                )
    assert not problems, format_findings(problems)


@requires_compose
def test_clickhouse_is_never_published_outside_debug_profile() -> None:
    problems: list[str] = []
    for name, service in _services().items():
        if not _is_clickhouse_facing(name, service):
            continue
        image = str(service.get("image", ""))
        if image.startswith("clickhouse/") and service.get("ports"):
            problems.append(f"{name}: the ClickHouse server itself must not publish ports")
        if service.get("ports") and "debug" not in (service.get("profiles") or []):
            problems.append(f"{name}: publishes a ClickHouse port outside the 'debug' profile")
        if service.get("ports") and set(service.get("profiles") or []) - {"debug"}:
            problems.append(f"{name}: ClickHouse proxy must be in the 'debug' profile only")
    assert not problems, format_findings(problems)


@requires_compose
def test_data_network_is_internal_and_clickhouse_only_on_it() -> None:
    compose = _load_compose()
    networks = compose.get("networks") or {}
    assert "data" in networks, "compose must define the 'data' network (PLAN 4.1)"
    assert (networks.get("data") or {}).get("internal") is True, (
        "'data' network must be internal: true"
    )
    for name, service in _services().items():
        if str(service.get("image", "")).startswith("clickhouse/"):
            attached = service.get("networks") or []
            attached_names = set(attached) if isinstance(attached, list) else set(attached.keys())
            assert attached_names == {"data"}, (
                f"{name} must be attached only to 'data' (got {attached_names})"
            )


@requires_compose
def test_no_privileged_or_host_namespace_services() -> None:
    problems: list[str] = []
    for name, service in _services().items():
        if service.get("privileged"):
            problems.append(f"{name}: privileged: true")
        for key in ("network_mode", "pid", "ipc", "userns_mode", "uts"):
            if str(service.get(key, "")).lower() == "host":
                problems.append(f"{name}: {key}: host")
        for cap in service.get("cap_add") or []:
            if str(cap).upper().removeprefix("CAP_") in DANGEROUS_CAPS:
                problems.append(f"{name}: cap_add {cap}")
        for volume in service.get("volumes") or []:
            text = volume if isinstance(volume, str) else str((volume or {}).get("source", ""))
            if "docker.sock" in text:
                problems.append(f"{name}: mounts the Docker socket")
        for opt in service.get("security_opt") or []:
            if "unconfined" in str(opt):
                problems.append(f"{name}: security_opt {opt}")
    assert not problems, format_findings(problems)


def _image_is_pinned(image: str) -> bool:
    if "@sha256:" in image:
        return True
    name, _, tag = image.rpartition(":")
    if not name or "/" in tag:  # no tag (registry port is not a tag)
        return False
    return bool(tag) and tag != "latest" and "${" not in tag


@requires_compose
def test_compose_images_are_pinned() -> None:
    problems = [
        f"{name}: image {service['image']!r} is not pinned to a version tag or digest"
        for name, service in _services().items()
        if service.get("image")
        and not service.get("build")
        and not _image_is_pinned(str(service["image"]))
    ]
    assert not problems, format_findings(problems)


def _service_secret_names(service: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for secret in service.get("secrets") or []:
        names.append(secret if isinstance(secret, str) else str((secret or {}).get("source", "")))
    return names


@requires_compose
def test_ai_secrets_reach_only_ai_services() -> None:
    problems: list[str] = []
    for name, service in _services().items():
        if name in AI_SERVICES:
            continue
        for secret in _service_secret_names(service):
            if AI_SECRET_HINT.search(secret):
                problems.append(f"{name}: receives AI provider secret {secret!r}")
        env = service.get("environment") or {}
        keys = env.keys() if isinstance(env, dict) else [str(e).split("=", 1)[0] for e in env]
        for key in keys:
            if AI_SECRET_HINT.search(str(key)) and "API_KEY" in str(key).upper():
                problems.append(f"{name}: environment carries AI key variable {key}")
    assert not problems, format_findings(problems)


@requires_compose
def test_secret_environment_values_are_never_literals() -> None:
    """Secrets travel as files (``*_FILE`` + compose secrets), not literal env values."""
    problems: list[str] = []
    for name, service in _services().items():
        env = service.get("environment") or {}
        items = (
            list(env.items())
            if isinstance(env, dict)
            else [tuple(str(e).split("=", 1)) if "=" in str(e) else (str(e), None) for e in env]
        )
        for key, value in items:
            if str(key).upper().endswith("_FILE") or not SECRET_ENV_NAME.search(str(key)):
                continue
            if value not in (None, ""):
                # Never echo the value.
                problems.append(f"{name}: {key} is set inline; use a *_FILE secret instead")
    assert not problems, format_findings(problems)


@requires_compose
def test_compose_hardening_advisory() -> None:
    """Reports (warns about) missing defence-in-depth options; never fails."""
    gaps: list[str] = []
    for name, service in _services().items():
        security_opt = [str(o) for o in service.get("security_opt") or []]
        if not any("no-new-privileges" in o for o in security_opt):
            gaps.append(f"{name}: no 'no-new-privileges:true'")
        if "ALL" not in [str(c).upper() for c in service.get("cap_drop") or []]:
            gaps.append(f"{name}: no 'cap_drop: [ALL]'")
        if not service.get("read_only"):
            gaps.append(f"{name}: root filesystem not read_only")
    if gaps:
        warnings.warn("compose hardening gaps:\n" + format_findings(gaps), stacklevel=1)


# ── Dockerfiles ──────────────────────────────────────────────────────────────

DOCKERFILES = sorted(
    p
    for p in iter_files(names=("Dockerfile", "Dockerfile.*", "*.Dockerfile"))
    if not p.name.endswith((".dockerignore", ".md"))
)


def _instructions(text: str) -> list[tuple[int, str, str]]:
    """(line, INSTRUCTION, arguments) with continuation lines joined."""
    result: list[tuple[int, str, str]] = []
    buffer = ""
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if not buffer:
            start = number
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        buffer += stripped
        keyword, _, args = buffer.partition(" ")
        result.append((start, keyword.upper(), args.strip()))
        buffer = ""
    return result


def _final_stage(instructions: list[tuple[int, str, str]]) -> list[tuple[int, str, str]]:
    last_from = max((i for i, (_, kw, _) in enumerate(instructions) if kw == "FROM"), default=0)
    return instructions[last_from:]


requires_dockerfiles = pytest.mark.skipif(not DOCKERFILES, reason="no Dockerfiles yet")

ROOT_USERS = {"root", "0", "root:root", "0:0", "root:0", "0:root"}


def dockerfile_problems(text: str, relative: str) -> list[str]:
    problems: list[str] = []
    instructions = _instructions(text)
    if not instructions:
        return [f"{relative}: empty Dockerfile"]
    final = _final_stage(instructions)
    users = [(line, args) for line, kw, args in final if kw == "USER"]
    if not users:
        problems.append(f"{relative}: final stage never switches to a non-root USER")
    elif users[-1][1].strip().lower() in ROOT_USERS:
        problems.append(f"{relative}:{users[-1][0]}: final stage runs as root")
    stage_aliases: set[str] = set()
    arg_defaults: dict[str, str] = {}
    for line, kw, args in instructions:
        if kw == "ARG" and "=" in args:
            key, _, value = args.partition("=")
            arg_defaults[key.strip()] = value.strip().strip("'\"")
        if kw == "FROM":
            tokens = [t for t in args.split() if not t.startswith("--")]
            if not tokens:
                continue
            image = re.sub(
                r"\$\{?(\w+)\}?", lambda m: arg_defaults.get(m.group(1), m.group(0)), tokens[0]
            )
            if len(tokens) >= 3 and tokens[1].upper() == "AS":
                stage_aliases.add(tokens[2].lower())
            if image.lower() in stage_aliases or image == "scratch":
                continue
            if not _image_is_pinned(image):
                problems.append(f"{relative}:{line}: base image {image!r} is not pinned")
        if kw == "RUN" and re.search(r"(curl|wget)[^|;&]*\|\s*(ba|z|da)?sh\b", args):
            problems.append(f"{relative}:{line}: pipes a download into a shell")
        if kw in {"ENV", "ARG"}:
            key = re.split(r"[=\s]", args, maxsplit=1)[0]
            has_value = "=" in args or len(args.split()) > 1
            if SECRET_ENV_NAME.search(key) and not key.upper().endswith("_FILE") and has_value:
                problems.append(
                    f"{relative}:{line}: {kw} {key} bakes a secret-looking value into the image"
                )
    return problems


@requires_dockerfiles
def test_dockerfiles_run_as_non_root_and_are_pinned() -> None:
    problems: list[str] = []
    for path in DOCKERFILES:
        problems.extend(dockerfile_problems(read_text(path), rel(path)))
    assert not problems, format_findings(problems)


# ── self-tests ───────────────────────────────────────────────────────────────


def test_dockerfile_checker_flags_root_and_unpinned_images() -> None:
    bad = "FROM python:latest\nRUN curl -fsSL https://x/install.sh | sh\nENV API_TOKEN=abc\n"
    problems = dockerfile_problems(bad, "Dockerfile")
    assert any("non-root USER" in p for p in problems)
    assert any("not pinned" in p for p in problems)
    assert any("pipes a download" in p for p in problems)
    assert any("API_TOKEN" in p for p in problems)
    assert dockerfile_problems("FROM python:3.12-slim\nUSER root\n", "D")


def test_dockerfile_checker_accepts_hardened_multistage_build() -> None:
    good = (
        "ARG PY=python:3.12-slim\n"
        "FROM ghcr.io/astral-sh/uv:0.12.13 AS uv\n"
        "FROM ${PY} AS build\n"
        "RUN pip install x\n"
        "FROM ${PY}\n"
        "COPY --from=build /app /app\n"
        "ENV EXTORQ_DB_PASSWORD_FILE=/run/secrets/db\n"
        "USER 10001:10001\n"
    )
    assert dockerfile_problems(good, "Dockerfile") == []


@pytest.mark.parametrize(
    ("port", "expected"),
    [
        ("127.0.0.1:8443:8443", ("127.0.0.1", "8443")),
        ("8443:8443", (None, "8443")),
        ("8443", (None, None)),
        ("[::1]:8000:8000/tcp", ("::1", "8000")),
    ],
)
def test_port_parser(port: str, expected: tuple[str | None, str | None]) -> None:
    host_ip, published, _ = _port_entries({"ports": [port]})[0]
    assert (host_ip, published) == expected


def test_port_parser_long_syntax() -> None:
    entry = _port_entries({"ports": [{"target": 3000, "published": 3000, "host_ip": "127.0.0.1"}]})[
        0
    ]
    assert entry[:2] == ("127.0.0.1", "3000")


@pytest.mark.parametrize(
    ("image", "pinned"),
    [
        ("clickhouse/clickhouse-server:26.8.42.13", True),
        ("grafana/grafana:13.1.10", True),
        ("alpine/socat:1.8.0.3", True),
        ("alpine/socat", False),
        ("alpine/socat:latest", False),
        ("localhost:5000/x", False),
        ("ghcr.io/x/y@sha256:" + "a" * 64, True),
    ],
)
def test_image_pinning_rule(image: str, pinned: bool) -> None:
    assert _image_is_pinned(image) is pinned
