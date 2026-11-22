"""Environment-independent HTTP client for the TypeSafe (Jev) SDK.

The SDK sends the API key in a request header. Its default ``httpx2`` client trusts the
process environment (``trust_env=True``):

* ``HTTPS_PROXY`` / ``HTTP_PROXY`` / ``ALL_PROXY`` (and ``NO_PROXY``) would route every
  request, key header included, through a proxy chosen by whoever controls the environment;
* ``SSL_CERT_FILE`` / ``SSL_CERT_DIR`` would make that proxy's CA trusted, so it could
  terminate TLS and read the key;
* ``SSLKEYLOGFILE`` makes ``ssl.create_default_context`` write TLS session keys to a file.

The client built here never consults the environment:

* ``trust_env=False``: proxy and ``SSL_*`` variables are ignored (no proxy mounts);
* ``verify`` is an explicit TLS client context (certificate and hostname verification,
  TLS >= 1.2) that trusts only certifi's CA bundle and has key logging off. It is built
  with ``ssl.SSLContext`` directly because ``ssl.create_default_context`` reads
  ``SSLKEYLOGFILE``;
* ``follow_redirects=False``: a redirect can never forward the key header to another
  host. The Jev API does not redirect API calls.

``httpx2`` is a hard dependency of typesafe-sdk; certifi comes with ``httpx``, a direct
backend dependency. Residual risks are documented in ``docs/ai-integrations.md``
(process-wide OpenSSL configuration such as ``OPENSSL_CONF``, and anyone able to modify
the installed packages or the CA bundle).
"""

from __future__ import annotations

import logging
import ssl

import certifi
import httpx2


def _quiet_request_logs() -> None:
    # httpx2 logs every request line (method, URL, status) at INFO. The Jev URL carries no
    # secret today, but request lines are no use in service logs and must never become a
    # leak path (e.g. a key passed as a query parameter by a future SDK version).
    logging.getLogger("httpx2").setLevel(logging.WARNING)


def tls_context() -> ssl.SSLContext:
    """TLS client context that ignores ``SSL_CERT_FILE``, ``SSL_CERT_DIR`` and ``SSLKEYLOGFILE``."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(cafile=certifi.where())
    ctx.keylog_filename = None  # type: ignore[assignment]  # typeshed: str only; None disables
    return ctx


def sync_client(
    timeout_seconds: float, *, transport: httpx2.BaseTransport | None = None
) -> httpx2.Client:
    """Synchronous client for the TypeSafe SDK (``transport`` is for offline tests only)."""
    _quiet_request_logs()
    return httpx2.Client(
        trust_env=False,
        verify=tls_context(),
        follow_redirects=False,
        timeout=httpx2.Timeout(timeout_seconds),
        transport=transport,
    )
