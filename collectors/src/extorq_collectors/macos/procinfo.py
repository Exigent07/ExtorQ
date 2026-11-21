"""Kernel-reported executable paths via ``proc_pidpath`` (libproc, public API).

``ps -o comm`` shows ``argv[0]``, which every process chooses for itself (a
binary started as ``qemu-system-aarch64`` from a shell, or one that renames
itself, shows no path at all; malware can pretend to be ``/usr/sbin/sshd``).
``proc_pidpath(3)`` (``<libproc.h>``) asks the kernel for the path of the
executable image instead. On macOS 27 it works without privileges for the
current user's AND for root's processes, and it is not affected by the socket
table restriction that hides ``netstat`` output from the collector's process tree.

Failure is never fatal: if the library or the call is unavailable (other OS,
process exited, permission denied), the path is ``None`` and the collector
falls back to the ``ps`` value, marked as unverified.
"""

from __future__ import annotations

import ctypes
import sys
from collections.abc import Callable
from functools import lru_cache

#: PROC_PIDPATHINFO_MAXSIZE = 4 * MAXPATHLEN (libproc.h)
PATH_BUFFER = 4 * 1024
LIBPROC = "/usr/lib/libproc.dylib"

PathResolver = Callable[[int], str | None]


@lru_cache(maxsize=1)
def _libproc() -> ctypes.CDLL | None:
    # No os.path.exists() pre-check: since macOS 11 system libraries live in the dyld
    # shared cache and are not present as files, yet dlopen() resolves them.
    if sys.platform != "darwin":
        return None
    try:
        lib = ctypes.CDLL(LIBPROC, use_errno=True)
        lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        lib.proc_pidpath.restype = ctypes.c_int
    except (OSError, AttributeError):
        return None
    return lib


def pid_path(pid: int) -> str | None:
    """Absolute executable path of ``pid`` as reported by the kernel, or ``None``."""
    if not isinstance(pid, int) or pid <= 0 or pid > 0x7FFFFFFF:
        return None
    lib = _libproc()
    if lib is None:
        return None
    buffer = ctypes.create_string_buffer(PATH_BUFFER)
    try:
        length = lib.proc_pidpath(pid, buffer, PATH_BUFFER)
    except (OSError, ctypes.ArgumentError):
        return None
    if length <= 0:
        return None
    path = buffer.value.decode("utf-8", errors="replace")
    return path if path.startswith("/") else None


def no_paths(_pid: int) -> str | None:
    """Resolver used where verification is disabled or in tests."""
    return None
