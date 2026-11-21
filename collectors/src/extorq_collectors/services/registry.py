"""Adapter registry: implemented adapters win over planned ones for the same service."""

from __future__ import annotations

from extorq.contracts.service import AdapterSupport
from extorq_collectors.services.base import ServiceAdapter, ServiceCandidate

_REGISTRY: dict[str, ServiceAdapter] = {}


def register(adapter_cls: type[ServiceAdapter]) -> type[ServiceAdapter]:
    """Class decorator. A later IMPLEMENTED registration replaces a PLANNED one."""
    instance = adapter_cls()
    existing = _REGISTRY.get(instance.adapter_id)
    if (
        existing is not None
        and existing.support is AdapterSupport.IMPLEMENTED
        and instance.support is not AdapterSupport.IMPLEMENTED
    ):
        return adapter_cls
    _REGISTRY[instance.adapter_id] = instance
    return adapter_cls


def all_adapters() -> list[ServiceAdapter]:
    return sorted(_REGISTRY.values(), key=lambda a: a.adapter_id)


def get_adapter(adapter_id: str) -> ServiceAdapter | None:
    return _REGISTRY.get(adapter_id)


def match_adapter(candidate: ServiceCandidate) -> ServiceAdapter | None:
    """Best adapter for a candidate: implemented first, then planned, else None."""
    matches = [a for a in _REGISTRY.values() if a.matches(candidate)]
    for support in (AdapterSupport.IMPLEMENTED, AdapterSupport.PLANNED):
        ranked = sorted((a for a in matches if a.support is support), key=lambda a: a.adapter_id)
        if ranked:
            return ranked[0]
    return None
