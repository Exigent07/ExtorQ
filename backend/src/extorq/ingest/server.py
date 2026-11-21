"""``extorq gateway``: serve the ingest gateway over HTTPS with uvicorn.

TLS: certificate/key from ``EXTORQ_TLS_CERT_FILE`` / ``EXTORQ_TLS_KEY_FILE``
(compose secrets from ``var/tls``), TLS 1.2 minimum, AEAD-only TLS 1.2 cipher
suites (TLS 1.3 suites are always AEAD). Single worker: the SQLite spool has a
single writer per process and uvicorn's concurrency limit bounds load.
"""

from __future__ import annotations

import ssl
import sys

import uvicorn

from extorq.common.config import check_startup, get_settings
from extorq.common.logging import configure_logging, get_logger

TLS12_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20"


def harden_ssl_context(context: ssl.SSLContext) -> ssl.SSLContext:
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(TLS12_CIPHERS)
    context.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE
    return context


def main() -> int:
    configure_logging("ingest")
    log = get_logger("extorq.ingest.server")
    settings = get_settings()
    missing = check_startup(
        "ingest", settings, required_files=("tls_cert_file", "tls_key_file", "producers_file")
    )
    if missing:
        return 2
    from extorq.ingest.app import create_app

    config = uvicorn.Config(
        create_app(settings),
        host=settings.gateway_bind_host,
        port=settings.gateway_port,
        ssl_certfile=str(settings.resolve(settings.tls_cert_file)),
        ssl_keyfile=str(settings.resolve(settings.tls_key_file)),
        ssl_ciphers=TLS12_CIPHERS,
        limit_concurrency=settings.gateway_max_concurrency,
        timeout_keep_alive=5,
        timeout_graceful_shutdown=20,
        server_header=False,
        proxy_headers=False,
        access_log=False,
        log_config=None,
        lifespan="on",
        workers=1,
    )
    config.load()
    if config.ssl is None:
        log.error("gateway_tls_not_configured")
        return 2
    harden_ssl_context(config.ssl)
    log.info(
        "gateway_listening",
        host=settings.gateway_bind_host,
        port=settings.gateway_port,
        tls_min_version="TLSv1.2",
    )
    server = uvicorn.Server(config)
    server.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
