"""Base class of the implemented Linux service telemetry adapters.

A Linux adapter binds a discovered service (systemd unit, process, socket, config)
to the telemetry the agentless collector can genuinely read for it. Most adapters
read journald entries returned by the dispatch boundary (``journal`` command);
they recognise their records by ``SYSLOG_IDENTIFIER`` and verify the claimed
origin against journald's trusted fields inside the parsers (``_SYSTEMD_UNIT``,
``_EXE``, ``_UID``, ``_PID``). Every event an adapter produces carries the
:class:`~extorq.contracts.service.ServiceRef` of the service it belongs to; a
record whose origin is contradicted by trusted fields is reported as
``system.log.notable`` (forged identity) WITHOUT a service reference.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from extorq.contracts import AdapterSupport, SecurityEvent
from extorq_collectors.linux.common import ParseContext
from extorq_collectors.linux.journal import JournalEntry, entry_from_json
from extorq_collectors.services.base import AdapterContext, ServiceAdapter, ServiceCandidate


class LinuxJournalAdapter(ServiceAdapter):
    """Implemented adapter whose records arrive as dispatched journald entries."""

    support = AdapterSupport.IMPLEMENTED
    #: journald SYSLOG_IDENTIFIER values this adapter owns.
    syslog_identifiers: ClassVar[frozenset[str]] = frozenset()
    #: Product reported when the service matched this adapter by unit/executable evidence.
    product_name: ClassVar[str | None] = None
    #: dpkg packages whose installed version is reported as the service version
    #: (``attributes.version_source`` names the package; never guessed otherwise).
    packages: ClassVar[tuple[str, ...]] = ()
    #: True when the parsers were verified against telemetry of a running instance; False
    #: when they are tested on the product's documented log formats only (reported on the
    #: service as ``adapter_validation`` so an analyst knows how much to trust coverage).
    validated_live: ClassVar[bool] = True

    def infer_product(self, candidate: ServiceCandidate) -> str | None:
        if candidate.product:
            return candidate.product
        if self.product_name and self.matches(candidate):
            return self.product_name
        return super().infer_product(candidate)

    def accepts(self, raw: Mapping[str, Any]) -> bool:
        identifier = raw.get("SYSLOG_IDENTIFIER")
        return isinstance(identifier, str) and identifier in self.syslog_identifiers

    def parse(self, raw: Mapping[str, Any], ctx: AdapterContext) -> list[SecurityEvent]:
        """Generic interface: one dispatched journald entry -> events carrying ``ctx.service``."""
        entry = entry_from_json(dict(raw))
        if entry is None or not self.accepts(raw):
            return []
        pctx = ParseContext(
            asset_id=ctx.asset_id,
            collector_id=ctx.collector_id,
            collector_version=ctx.collector_version,
            observed_time=ctx.observed_time,
            service=ctx.service,
        )
        return self.parse_entry(entry, pctx)

    def parse_entry(self, entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
        """Collector fast path (full ParseContext incl. the collector's own uid)."""
        raise NotImplementedError

    def prerequisite_problems(self, configs: Mapping[str, Any]) -> list[str]:
        """Configuration problems that prevent complete telemetry (empty = none known)."""
        return []
