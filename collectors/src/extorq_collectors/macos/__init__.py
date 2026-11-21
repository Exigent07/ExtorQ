"""Native macOS endpoint collector (asset ``macos:workstation-01``).

Sources: unified logging (``macos.unified_log``), LaunchAgents/LaunchDaemons
(``macos.launchd``), host posture (``macos.posture``) and inventory
(``macos.inventory``). Everything runs as the logged-in user with supported,
read-only interfaces: no sudo, no Full Disk Access, no configuration profiles.
Standard tools do not provide EDR-grade process telemetry; see
docs/telemetry/macos.md for the explicit list of collection gaps.

The collector class lives in :mod:`extorq_collectors.macos.collector` (it needs
the collector SDK); the parsing modules here are pure and SDK-independent.
"""
