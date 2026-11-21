"""Correlation settings (environment prefix ``EXTORQ_CORRELATION_``; no secrets).

Shared NAT / gateway addresses aggregate many origins, so an IP match through one of
them never links two events on its own (relationship stays UNESTABLISHED):

* ``10.0.2.2``   QEMU user-mode (SLIRP) gateway: every connection from the Mac to the
                 lab VM arrives from it.
* ``172.18.0.1`` gateway of the Docker ``kind`` network: kubectl and NodePort traffic
                 from the Mac reaches the kind node from it (observed in the captured
                 kube-apiserver audit records, ``sourceIPs``).
* ``10.244.0.1`` kind pod-network gateway: NodePort traffic from the Mac reaches the
                 lab-portal pods SNATed to it (observed as ``src_ip`` of every lab-portal
                 request in the live container logs, 2026-11-21).
* ``127.0.0.1`` / ``::1`` loopback: local proxies (nginx in front of the lab app).

Context windows are per rule family (rule id prefix): how far before ``first_seen``
and after ``last_seen`` related activity is considered.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_SHARED_NAT_IPS: tuple[str, ...] = (
    "10.0.2.2",
    "172.18.0.1",
    "10.244.0.1",
    "127.0.0.1",
    "::1",
)


@dataclass(frozen=True)
class ContextWindow:
    before_seconds: int
    after_seconds: int


#: Rule id prefix -> context window. GitHub activity is slower (commit -> workflow runs).
DEFAULT_WINDOWS: dict[str, ContextWindow] = {
    "VM": ContextWindow(900, 900),
    "HTTP": ContextWindow(900, 900),
    "CORR": ContextWindow(1800, 900),
    "K8S": ContextWindow(900, 900),
    "GH": ContextWindow(3600, 3600),
    "MAC": ContextWindow(900, 900),
}
FALLBACK_WINDOW = ContextWindow(900, 900)


class CorrelationSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="EXTORQ_CORRELATION_", extra="ignore")

    #: JSON list in the environment, e.g. '["10.0.2.2","127.0.0.1"]'.
    shared_nat_ips: list[str] = Field(default_factory=lambda: list(DEFAULT_SHARED_NAT_IPS))
    #: Relationships kept in a context (contract maximum 300).
    max_related: int = Field(default=250, ge=0, le=300)
    #: Rows read by the identifier/attribute query (all assets).
    max_linked_rows: int = Field(default=1000, ge=10, le=10_000)
    #: Nearest same-asset events kept when only temporal proximity links them.
    max_temporal: int = Field(default=40, ge=0, le=300)
    #: Evidence events fetched for classification/features (alert arrays hold <= 500).
    max_evidence_fetch: int = Field(default=500, ge=1, le=500)

    def window_for(self, rule_id: str) -> ContextWindow:
        return DEFAULT_WINDOWS.get(rule_id.split("-", 1)[0], FALLBACK_WINDOW)
