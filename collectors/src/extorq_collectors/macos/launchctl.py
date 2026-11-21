"""Loaded launchd jobs via ``launchctl print`` (read-only, no privileges).

``launchctl print system`` and ``launchctl print gui/<uid>`` list every job
loaded in that domain with its pid (0 = not running) and last exit status, plus
the domain's enable/disable overrides. ``launchctl print system/<label>`` exits
113 with "Could not find service" when a job is not loaded (for example
``com.openssh.sshd`` while Remote Login is off). All of this works as the
logged-in user on macOS 27; the collector only ever runs ``print`` /
``print-disabled`` (enforced by :func:`extorq_collectors.macos.commands.check_read_only_policy`).

Only the ``services`` and ``disabled services`` blocks are parsed. Other blocks
(``environment``: variables set with ``launchctl setenv`` may hold secrets;
endpoints; subdomains) are skipped and never stored.

What remains invisible without root: the Background Task Management database
(which login items/background items are *approved*), jobs of other users, and
per-job details of other domains beyond what ``print`` exposes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from extorq_collectors.macos.commands import CommandResult, CommandRunner

LAUNCHCTL = "/bin/launchctl"
MAX_JOBS = 5000
#: Exit status of ``launchctl print <domain>/<label>`` for a job that is not loaded.
NOT_FOUND_EXIT = 113

_SERVICE_ROW = re.compile(r"^\s*(?P<pid>\d+)\s+(?P<status>\S+)\s+(?P<label>\S.*?)\s*$")
_DISABLED_ROW = re.compile(r'^\s*"(?P<label>[^"]+)"\s*=>\s*(?P<state>enabled|disabled)\s*$')
_LABEL = re.compile(r"^[A-Za-z0-9._-]{1,255}$")


@dataclass(frozen=True, slots=True)
class LoadedJob:
    label: str
    domain: str  # system | gui
    #: pid of the running job, None when loaded but not running.
    pid: int | None
    #: Last exit status column: "-" (never exited), a number, or a marker such as "(pe)".
    last_exit: str | None

    @property
    def running(self) -> bool:
        return self.pid is not None


@dataclass(slots=True)
class DomainListing:
    domain: str
    jobs: dict[str, LoadedJob] = field(default_factory=dict)
    #: label -> True (override enabled) / False (override disabled)
    overrides: dict[str, bool] = field(default_factory=dict)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def _blocks(text: str, names: tuple[str, ...]) -> dict[str, list[str]]:
    """Lines of the top-level (one-tab indented) ``<name> = {`` blocks of a print output."""
    found: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if current is None:
            for name in names:
                if line == f"\t{name} = {{":
                    current = name
                    found[current] = []
                    break
            continue
        if line == "\t}":
            current = None
            continue
        found[current].append(line)
    return found


def parse_domain_print(text: str, domain: str) -> DomainListing:
    """Parse ``launchctl print <domain>`` (services + disabled-services blocks only)."""
    listing = DomainListing(domain=domain)
    blocks = _blocks(text, ("services", "disabled services"))
    if "services" not in blocks:
        listing.error = "no services block in launchctl output"
        return listing
    for line in blocks["services"]:
        match = _SERVICE_ROW.match(line)
        if not match:
            continue
        label = match.group("label")
        if not _LABEL.match(label):
            continue
        pid = int(match.group("pid"))
        status = match.group("status")
        listing.jobs[label] = LoadedJob(
            label=label,
            domain=domain,
            pid=pid if pid > 0 else None,
            last_exit=None if status == "-" else status,
        )
        if len(listing.jobs) >= MAX_JOBS:
            break
    for line in blocks.get("disabled services", []):
        match = _DISABLED_ROW.match(line)
        if match and _LABEL.match(match.group("label")):
            listing.overrides[match.group("label")] = match.group("state") == "enabled"
    return listing


def domain_argv(domain: str) -> list[str]:
    return [LAUNCHCTL, "print", domain]


def collect_domain(runner: CommandRunner, domain: str, *, timeout: float) -> DomainListing:
    """Run ``launchctl print <domain>``; errors are returned, never raised."""
    result: CommandResult = runner.run(domain_argv(domain), timeout=timeout, max_stdout=8 * 1024**2)
    if not result.ok:
        return DomainListing(domain=domain, error=result.summary())
    return parse_domain_print(result.text(), domain)


def domain_name(domain: str) -> str:
    """``gui/501`` -> ``gui``; ``system`` -> ``system``."""
    return domain.split("/", 1)[0]
