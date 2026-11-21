"""Legacy diagnostics helpers.

INTENTIONALLY INSECURE LAB FIXTURE: ``legacy_ping`` passes caller input to a shell
(``subprocess`` with ``shell=True``), a command-injection pattern that static analysis
(Semgrep rule ``python.lang.security.audit.subprocess-shell-true``) is expected to
report. Nothing in the service imports or calls this function; it is never deployed.
"""

from __future__ import annotations

import subprocess


def legacy_ping(host: str) -> str:
    """Ping ``host`` once (DO NOT USE: vulnerable to command injection)."""
    completed = subprocess.run(  # noqa: S602 - intentional lab fixture (see module docstring)
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return completed.stdout
