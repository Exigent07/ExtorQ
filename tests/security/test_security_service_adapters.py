"""Service-model honesty and data-minimisation invariants (PLAN 10.1; owner: agent F).

Checks the shared service interface (``extorq_collectors.services``) and every
adapter registered by the platform adapter packages that exist at test time:

* every adapter declares what it never collects; category-specific minimums
  (no FTP file contents, credentials, HTTP Authorization headers, DB query text);
* planned adapters are extension points only: they accept nothing, parse
  nothing and never report a service as monitored;
* a well-known port alone never identifies a product (ports give at most
  ``inferred`` attribution and are not used for matching);
* discovery without evidence is impossible;
* a Kubernetes Service and a host service with the same key never share an id;
* lab web-server log formats do not log query strings, bodies, cookies or
  Authorization headers.

Runs without the stack. Adapter packages that do not exist yet are skipped,
never faked.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
from datetime import UTC, datetime

import pytest
from security_helpers import format_findings, iter_files, read_text, rel

services = pytest.importorskip("extorq_collectors.services")

from extorq.contracts.catalog import SourceType  # noqa: E402
from extorq.contracts.identity import service_id  # noqa: E402
from extorq.contracts.service import (  # noqa: E402
    AdapterSupport,
    DiscoveryEvidence,
    MonitoringStatus,
    PortAttribution,
    ServiceCategory,
    ServiceEndpoint,
    ServiceKind,
)
from extorq_collectors.services import (  # noqa: E402
    AdapterContext,
    ServiceCandidate,
    all_adapters,
    classify_coverage,
    match_adapter,
)

#: Packages that register IMPLEMENTED adapters (PLAN 10.2). Missing ones are skipped.
IMPLEMENTED_ADAPTER_PACKAGES = (
    "extorq_collectors.linux.adapters",
    "extorq_collectors.macos.adapters",
    "extorq_collectors.kubernetes.adapters",
)

#: Extension points the amendment requires to be visible as planned (or implemented).
REQUIRED_EXTENSION_POINTS = {"ftp", "postgresql", "mysql", "dns", "redis"}

#: Category -> keyword groups; each group needs at least one keyword in never_collects.
MINIMUM_NEVER_COLLECTS: dict[ServiceCategory, list[tuple[str, ...]]] = {
    ServiceCategory.FTP: [("file content",), ("password", "credential")],
    ServiceCategory.DATABASE: [("query text",), ("password", "credential")],
    ServiceCategory.HTTP_SERVER: [("authorization",)],
    ServiceCategory.WEB_APPLICATION: [("password", "credential")],
    ServiceCategory.SSH: [("password", "credential", "private key")],
    ServiceCategory.CACHE: [("value",), ("password", "credential", "secret")],
    ServiceCategory.DNS: [("tsig", "key")],
}

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)


def _import_adapter_packages() -> list[str]:
    loaded: list[str] = []
    for name in IMPLEMENTED_ADAPTER_PACKAGES:
        try:
            package = importlib.import_module(name)
        except ModuleNotFoundError as exc:
            if exc.name and (name == exc.name or name.startswith(exc.name + ".")):
                continue  # not built yet: skip, never fake
            raise
        loaded.append(name)
        for info in pkgutil.iter_modules(getattr(package, "__path__", []), name + "."):
            importlib.import_module(info.name)
    return loaded


LOADED_PACKAGES = _import_adapter_packages()
ADAPTERS = all_adapters()
PLANNED = [a for a in ADAPTERS if a.support is AdapterSupport.PLANNED]
IMPLEMENTED = [a for a in ADAPTERS if a.support is AdapterSupport.IMPLEMENTED]


def test_registry_lists_required_extension_points() -> None:
    ids = {adapter.adapter_id for adapter in ADAPTERS}
    assert ids >= REQUIRED_EXTENSION_POINTS, sorted(REQUIRED_EXTENSION_POINTS - ids)


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: a.adapter_id)
def test_adapter_declares_identity_and_data_handling(adapter: object) -> None:
    problems: list[str] = []
    if not _IDENTIFIER.match(getattr(adapter, "adapter_id", "")):
        problems.append("adapter_id is not a valid identifier")
    if not isinstance(adapter.support, AdapterSupport):
        problems.append("support is not an AdapterSupport")
    if not isinstance(adapter.category, ServiceCategory):
        problems.append("category is not a ServiceCategory")
    if not adapter.description.strip():
        problems.append("description is empty")
    if not adapter.never_collects or not all(s.strip() for s in adapter.never_collects):
        problems.append("never_collects is empty (data minimisation must be declared)")
    if not all(isinstance(s, SourceType) for s in adapter.source_types):
        problems.append("source_types must be catalog SourceType members")
    if adapter.support is AdapterSupport.IMPLEMENTED and not adapter.source_types:
        problems.append("an implemented adapter must name its telemetry source types")
    assert not problems, format_findings(problems)


@pytest.mark.parametrize(
    "adapter",
    [a for a in ADAPTERS if a.category in MINIMUM_NEVER_COLLECTS],
    ids=lambda a: a.adapter_id,
)
def test_category_minimum_never_collects(adapter: object) -> None:
    declared = " ".join(adapter.never_collects).lower()
    missing = [
        "/".join(group)
        for group in MINIMUM_NEVER_COLLECTS[adapter.category]
        if not any(keyword in declared for keyword in group)
    ]
    assert not missing, f"{adapter.adapter_id}: never_collects lacks {missing}"


@pytest.mark.parametrize("adapter", PLANNED, ids=lambda a: a.adapter_id)
def test_planned_adapters_never_produce_telemetry(adapter: object) -> None:
    ctx = AdapterContext(
        asset_id="linux:lab-vm-01",
        asset_type="linux_host",
        collector_id="f-security-test",
        collector_version="0.0.0",
        service=None,
        observed_time=NOW,
    )
    raw_samples = [
        {},
        {"MESSAGE": "Accepted password for root from 10.0.2.2 port 1 ssh2"},
        {"line": "USER anonymous", "_SYSTEMD_UNIT": "vsftpd.service"},
    ]
    assert not any(adapter.accepts(raw) for raw in raw_samples)
    with pytest.raises(NotImplementedError):
        adapter.parse({}, ctx)
    assert all(s.lower().startswith("planned") for s in adapter.collects), (
        f"{adapter.adapter_id}: planned adapters must label every 'collects' entry as planned"
    )


@pytest.mark.parametrize("adapter", PLANNED, ids=lambda a: a.adapter_id)
def test_planned_adapter_is_never_reported_monitored(adapter: object) -> None:
    support, status, note = classify_coverage(
        adapter,
        enabled=True,
        last_telemetry_at=NOW,
        now=NOW,
        stale_after_seconds=300,
    )
    assert support is AdapterSupport.PLANNED
    assert status is MonitoringStatus.UNMONITORED
    assert "planned" in note


def test_unknown_service_type_is_reported_unmonitored() -> None:
    support, status, _ = classify_coverage(
        None, enabled=True, last_telemetry_at=NOW, now=NOW, stale_after_seconds=300
    )
    assert (support, status) == (AdapterSupport.NONE, MonitoringStatus.UNMONITORED)


@pytest.mark.parametrize(
    "adapter", [a for a in ADAPTERS if a.well_known_ports], ids=lambda a: a.adapter_id
)
def test_well_known_port_alone_never_identifies_a_product(adapter: object) -> None:
    for protocol, port in sorted(adapter.well_known_ports):
        candidate = ServiceCandidate(
            asset_id="linux:lab-vm-01",
            service_kind=ServiceKind.APPLICATION,
            service_key=f"listener-{protocol}-{port}",
            name=f"listener {protocol}/{port}",
            evidence=frozenset({DiscoveryEvidence.LISTENING_SOCKET}),
            endpoints=(
                ServiceEndpoint(
                    protocol=protocol,
                    address="0.0.0.0",  # noqa: S104 - observed bind address, not a bind call
                    port=port,
                    exposure="any",
                    attribution=PortAttribution.UNKNOWN,
                ),
            ),
        )
        matched = match_adapter(candidate)
        assert matched is None, (
            f"port {protocol}/{port} alone matched adapter "
            f"{matched.adapter_id if matched else None}: ports must not identify products"
        )


def test_discovery_requires_evidence() -> None:
    with pytest.raises(ValueError):
        ServiceCandidate(
            asset_id="linux:lab-vm-01",
            service_kind=ServiceKind.HOST_SERVICE,
            service_key="ssh.service",
            name="ssh",
            evidence=frozenset(),
        )


def test_kubernetes_service_never_shares_identity_with_host_service() -> None:
    key = "extorq-apps/ssh"
    for asset in ("k8s:extorq-lab", "linux:lab-vm-01"):
        assert service_id(asset, ServiceKind.K8S_SERVICE.value, key) != service_id(
            asset, ServiceKind.HOST_SERVICE.value, key
        )


# ── source-side minimisation for lab web servers ────────────────────────────

#: nginx variables that would log query strings, bodies, cookies or credentials.
#: ``$request`` is the full request line (with query string); ``$uri`` is the safe choice.
NGINX_FORBIDDEN = re.compile(
    r"\$(request_uri|request_body|request|args|query_string|arg_\w+|http_authorization|"
    r"http_cookie|cookie_\w+|http_proxy_authorization|http_x_api_key)\b"
)
#: Apache LogFormat directives with the same effect: %r (request line incl. query),
#: %q (query string), request headers carrying credentials. Use %m %U %H instead of %r.
APACHE_FORBIDDEN = re.compile(r"%(r|q|\{(Authorization|Cookie|Proxy-Authorization|X-Api-Key)\}i)")


def _log_format_lines(text: str) -> list[tuple[int, str]]:
    """Lines inside nginx ``log_format`` statements or Apache ``LogFormat``/``CustomLog``."""
    lines: list[tuple[int, str]] = []
    in_nginx_format = False
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith("log_format"):
            in_nginx_format = True
        if in_nginx_format or stripped.startswith(("LogFormat", "CustomLog")):
            lines.append((number, stripped))
        if in_nginx_format and stripped.endswith(";"):
            in_nginx_format = False
    return lines


def test_lab_web_server_log_formats_minimise_data() -> None:
    configs = [
        p
        for p in iter_files(suffixes=(".conf",), roots=("infra", "lab"))
        if "log_format" in read_text(p) or "LogFormat" in read_text(p)
    ]
    findings: list[str] = []
    for path in configs:
        for number, line in _log_format_lines(read_text(path)):
            if NGINX_FORBIDDEN.search(line) or APACHE_FORBIDDEN.search(line):
                findings.append(f"{rel(path)}:{number}: log format records sensitive request data")
    assert not findings, format_findings(findings)


@pytest.mark.parametrize(
    ("line", "flagged"),
    [
        ("log_format x '\"$request_uri\"';", True),
        ("log_format x '$request $status';", True),
        ("log_format x '$request_id $request_method $request_time';", False),
        ("log_format x '$http_authorization';", True),
        ("log_format x '$uri $status';", False),
        ('LogFormat "%h %l %u %t \\"%r\\" %>s %q" combined', True),
        ('LogFormat "%{Authorization}i" leak', True),
        ('LogFormat "%h %t %>s" safe', False),
        ('LogFormat "%h %t \\"%m %U %H\\" %>s" safe_request_line', False),
    ],
)
def test_log_format_check_self_test(line: str, flagged: bool) -> None:
    hit = bool(NGINX_FORBIDDEN.search(line) or APACHE_FORBIDDEN.search(line))
    assert hit is flagged


def test_report_loaded_adapter_packages() -> None:
    """Informational: which implemented-adapter packages were present for this run."""
    if not LOADED_PACKAGES:
        pytest.skip("no implemented adapter package present yet (B1/B3/B2 in progress)")
    assert IMPLEMENTED, f"{LOADED_PACKAGES} loaded but registered no implemented adapter"
