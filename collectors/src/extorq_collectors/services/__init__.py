"""Service-aware monitoring for collectors: discovery candidates, adapters, registry.

Importing this package registers the planned adapters. Implemented adapters live
in platform modules (e.g. ``extorq_collectors.linux.adapters``) and register
themselves with :func:`extorq_collectors.services.registry.register`.
"""

from extorq_collectors.services import planned as _planned  # noqa: F401  (registration)
from extorq_collectors.services.base import (
    AdapterContext,
    ServiceAdapter,
    ServiceCandidate,
    build_service,
    classify_coverage,
    exposure_of,
    service_ref,
)
from extorq_collectors.services.registry import all_adapters, get_adapter, match_adapter, register

__all__ = [
    "AdapterContext",
    "ServiceAdapter",
    "ServiceCandidate",
    "all_adapters",
    "build_service",
    "classify_coverage",
    "exposure_of",
    "get_adapter",
    "match_adapter",
    "register",
    "service_ref",
]
