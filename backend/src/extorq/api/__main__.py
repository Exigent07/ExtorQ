"""Development runner: ``uv run python -m extorq.api [--host 127.0.0.1] [--port 8100]``.

Binds to loopback on the dev port 8100 by default (never the compose port 8000).
Production uses ``extorq api`` (platform CLI) inside the compose ``api`` service.
"""

from __future__ import annotations

import argparse

DEV_PORT = 8100


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m extorq.api", description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEV_PORT)
    args = parser.parse_args(argv)
    if args.port == 8000:
        parser.error("port 8000 belongs to the compose api service; use 8100 for development")

    import uvicorn

    from extorq.api.logs import configure

    configure("api")
    uvicorn.run(
        "extorq.api.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        proxy_headers=False,
        server_header=False,
        access_log=True,
    )


if __name__ == "__main__":
    main()
