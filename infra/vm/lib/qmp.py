#!/usr/bin/env python3
"""Minimal QMP client (standard library only) used by infra/vm/vm.sh.

Usage: python3 -I qmp.py <socket-path> <command>
Allowed commands: system_powerdown, query-status. Prints the JSON reply.
"""

from __future__ import annotations

import json
import socket
import sys

ALLOWED = {"system_powerdown", "query-status"}
TIMEOUT = 10.0


def _read_message(sock: socket.socket) -> dict[str, object]:
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("QMP socket closed")
        buf += chunk
        if len(buf) > 1024 * 1024:
            raise ConnectionError("QMP reply too large")
    for line in buf.splitlines():
        message = json.loads(line)
        if "event" not in message:
            return message
    return {}


def qmp(path: str, command: str) -> dict[str, object]:
    if command not in ALLOWED:
        raise ValueError(f"command not allowed: {command}")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.connect(path)
        _read_message(sock)  # greeting
        sock.sendall(json.dumps({"execute": "qmp_capabilities"}).encode() + b"\n")
        _read_message(sock)
        sock.sendall(json.dumps({"execute": command}).encode() + b"\n")
        reply = _read_message(sock)
        while "return" not in reply and "error" not in reply:
            reply = _read_message(sock)
        return reply


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        reply = qmp(argv[1], argv[2])
    except (OSError, ValueError) as exc:
        print(f"qmp: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(reply))
    return 0 if "return" in reply else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
