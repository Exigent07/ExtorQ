#!/usr/bin/env python3
"""Switch the host collectors to a fast polling profile for testing, and back.

``on``  backs up config/collectors/*.yaml to var/fast-profile/orig/ and rewrites every
        ``interval_seconds`` up to 300 s to 10 s (GitHub: 15 s, to respect API rate limits).
        Long-cadence work (packages, posture at 900/3600 s) is left alone.
``off`` restores the originals exactly. ``status`` says which profile is active.
Restart the collectors afterwards (``make collectors-stop collectors-start``); the Makefile
targets ``fast-on`` / ``fast-off`` do everything including the detector.
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONFIG = REPO / "config" / "collectors"
BACKUP = REPO / "var" / "fast-profile" / "orig"
_LINE = re.compile(r"^(?P<lead>\s*)interval_seconds:\s*(?P<value>\d+)(?P<tail>.*)$")
_SECTION = re.compile(r"^ {6}(?P<name>[a-z_]+):\s*$")
#: macOS sources that enforce a 60 s floor themselves (they spawn ps/fdesetup/system tools).
_MACOS_FLOOR_SECTIONS = {"inventory", "posture", "asset", "applications", "services"}


def _fast(name: str, value: int) -> int:
    if value > 300:
        return value
    return 15 if name.startswith("github") else 10


def on() -> None:
    if BACKUP.exists():
        print("fast profile already on (originals are in var/fast-profile/orig)")
        return
    BACKUP.mkdir(parents=True, mode=0o700)
    changed = 0
    for path in sorted(CONFIG.glob("*.yaml")):
        shutil.copy2(path, BACKUP / path.name)
        out: list[str] = []
        section = ""
        for line in path.read_text(encoding="utf-8").splitlines():
            head = _SECTION.match(line)
            if head:
                section = head["name"]
            m = _LINE.match(line)
            if m and not (path.stem == "macos" and section in _MACOS_FLOOR_SECTIONS):
                new = _fast(path.stem, int(m["value"]))
                if new != int(m["value"]):
                    line = f"{m['lead']}interval_seconds: {new}{m['tail']}"
                    changed += 1
            out.append(line)
        path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"fast profile ON: {changed} interval(s) shortened; originals in {BACKUP}")


def off() -> None:
    if not BACKUP.exists():
        print("fast profile is not on")
        return
    for saved in sorted(BACKUP.glob("*.yaml")):
        shutil.copy2(saved, CONFIG / saved.name)
    shutil.rmtree(BACKUP)
    print("fast profile OFF: collector configs restored")


def main(argv: list[str]) -> int:
    action = argv[1] if len(argv) > 1 else "status"
    if action == "on":
        on()
    elif action == "off":
        off()
    elif action == "status":
        print("fast profile: " + ("ON" if BACKUP.exists() else "off"))
    else:
        print("usage: fast_profile.py on|off|status", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
