#!/usr/bin/env python3
"""ExtorQ lab portal: a deliberately small web application that produces genuine
application security telemetry for the ExtorQ lab.

* Python 3 standard library only (the same file runs on the Ubuntu lab VM behind
  nginx and, unchanged, as B2's Kubernetes container image).
* Configured exclusively through environment variables (see README.md).
* Writes exactly one JSON object per line to stdout following the shared log
  contract ``lab-portal.log.v1`` (docs/team/interface-changes/B1.md section 1).
  stderr only carries human-readable startup/fatal diagnostics.
* Passwords are never logged. Request data is never reflected into HTML.

Endpoints: GET / (page), POST /login (form or JSON), POST /logout,
GET /admin (401 without a session), GET /healthz.

Helper mode: ``python3 app.py --hash-password`` reads a password from stdin and
prints a PBKDF2-SHA256 hash for LAB_PORTAL_PASSWORD_HASH_FILE.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

SERVICE = "lab-portal"
VERSION = "1.0.0"

MAX_BODY_BYTES = 4096
MAX_USER_CHARS = 64
MAX_ROUTE_CHARS = 512
MAX_UA_CHARS = 512
MAX_METHOD_CHARS = 16
MAX_SESSIONS = 1024
PBKDF2_ITERATIONS = 600_000
SESSION_COOKIE = "lab_session"

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_HASH_RE = re.compile(r"^pbkdf2_sha256\$(\d{5,7})\$([A-Za-z0-9+/=]{16,64})\$([A-Za-z0-9+/=]{40,64})$")
_SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{20,64}$")

#: Exact key order of the shared log contract. Every key is always present.
LOG_KEYS = (
    "ts", "level", "service", "event", "user", "src_ip", "request_id",
    "request_id_source", "method", "route", "status", "reason", "user_agent",
    "duration_ms",
)


# ── Utilities ──────────────────────────────────────────────────────────────────


def utc_ts() -> str:
    """RFC 3339 UTC timestamp with millisecond precision and a Z suffix."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def clean_text(value: str | None, limit: int) -> str | None:
    """Strip control characters and bound the length of untrusted text."""
    if value is None:
        return None
    return _CONTROL_RE.sub("?", value)[:limit]


def normalize_ip(value: str | None) -> str | None:
    """Canonical textual IP (IPv4-mapped IPv6 collapsed to IPv4); None if invalid."""
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean (0/1)")


def env_int(name: str, default: int, low: int, high: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = int(raw.strip())
    if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return value


# ── Credentials ────────────────────────────────────────────────────────────────


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations, base64.b64encode(salt).decode(), base64.b64encode(digest).decode()
    )


class Credential:
    """The single demo credential. Either a PBKDF2 hash (preferred) or plain text."""

    def __init__(self, *, pbkdf2: tuple[int, bytes, bytes] | None = None,
                 plain: bytes | None = None) -> None:
        if (pbkdf2 is None) == (plain is None):
            raise ValueError("exactly one credential form is required")
        self._pbkdf2 = pbkdf2
        self._plain = plain

    @classmethod
    def from_hash(cls, text: str) -> Credential:
        match = _HASH_RE.match(text.strip())
        if not match:
            raise ValueError("password hash file is not in pbkdf2_sha256$iter$salt$hash format")
        iterations = int(match.group(1))
        return cls(pbkdf2=(iterations, base64.b64decode(match.group(2)),
                           base64.b64decode(match.group(3))))

    @classmethod
    def from_plain(cls, text: str) -> Credential:
        value = text.rstrip("\r\n")
        if len(value) < 12:
            raise ValueError("plain-text demo password must be at least 12 characters")
        return cls(plain=value.encode("utf-8"))

    def verify(self, password: str) -> bool:
        candidate = password.encode("utf-8")
        if self._pbkdf2 is not None:
            iterations, salt, expected = self._pbkdf2
            digest = hashlib.pbkdf2_hmac("sha256", candidate, salt, iterations)
            return hmac.compare_digest(digest, expected)
        assert self._plain is not None
        return hmac.compare_digest(candidate, self._plain)


#: Used for unknown users so that response time does not reveal valid names.
_DUMMY_CREDENTIAL = Credential(
    pbkdf2=(PBKDF2_ITERATIONS, b"extorq-dummy-salt", hashlib.sha256(b"dummy").digest())
)


def _read_secret_file(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read(4096)


def load_credential() -> Credential | None:
    hash_file = os.environ.get("LAB_PORTAL_PASSWORD_HASH_FILE", "").strip()
    plain_file = os.environ.get("LAB_PORTAL_PASSWORD_FILE", "").strip()
    if not hash_file and not plain_file:
        cred_dir = os.environ.get("CREDENTIALS_DIRECTORY", "").strip()
        candidate = os.path.join(cred_dir, "demo_password_hash") if cred_dir else ""
        if candidate and os.path.isfile(candidate):
            hash_file = candidate
    if hash_file:
        return Credential.from_hash(_read_secret_file(hash_file))
    if plain_file:
        return Credential.from_plain(_read_secret_file(plain_file))
    return None


# ── Configuration ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    log_access: bool
    log_access_healthz: bool
    trusted_proxies: frozenset[str]
    demo_user: str
    credential: Credential | None
    session_ttl: int
    cookie_secure: bool
    max_concurrency: int

    @classmethod
    def from_env(cls) -> Config:
        proxies: set[str] = set()
        for item in os.environ.get("LAB_PORTAL_TRUSTED_PROXIES", "127.0.0.1").split(","):
            item = item.strip()
            if not item:
                continue
            normalized = normalize_ip(item)
            if normalized is None:
                raise ValueError(f"LAB_PORTAL_TRUSTED_PROXIES contains an invalid IP: {item!r}")
            proxies.add(normalized)
        demo_user = os.environ.get("LAB_PORTAL_DEMO_USER", "lab-admin").strip()
        if not re.fullmatch(r"[a-z][a-z0-9._-]{2,31}", demo_user):
            raise ValueError("LAB_PORTAL_DEMO_USER must match [a-z][a-z0-9._-]{2,31}")
        return cls(
            host=os.environ.get("LAB_PORTAL_HOST", "127.0.0.1").strip() or "127.0.0.1",
            port=env_int("LAB_PORTAL_PORT", 8080, 1, 65535),
            log_access=env_flag("LOG_ACCESS", False),
            log_access_healthz=env_flag("LOG_ACCESS_HEALTHZ", False),
            trusted_proxies=frozenset(proxies),
            demo_user=demo_user,
            credential=load_credential(),
            session_ttl=env_int("LAB_PORTAL_SESSION_TTL", 3600, 60, 86400),
            cookie_secure=env_flag("LAB_PORTAL_COOKIE_SECURE", False),
            max_concurrency=env_int("LAB_PORTAL_MAX_CONCURRENCY", 32, 1, 512),
        )


# ── Event output ───────────────────────────────────────────────────────────────


class EventLog:
    """Thread-safe writer of contract lines (one JSON object per line)."""

    def __init__(self, stream: Any = None) -> None:
        self._stream = stream if stream is not None else sys.stdout
        self._lock = threading.Lock()

    def emit(self, record: dict[str, Any]) -> None:
        ordered = {key: record.get(key) for key in LOG_KEYS}
        line = json.dumps(ordered, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        with self._lock:
            try:
                self._stream.write(line + "\n")
                self._stream.flush()
            except (OSError, ValueError):
                pass  # stdout gone (journald restart / closed pipe): never crash a request


class SessionStore:
    """In-memory sessions with expiry and a hard size bound."""

    def __init__(self, ttl: int, max_sessions: int = MAX_SESSIONS) -> None:
        self._ttl = ttl
        self._max = max_sessions
        self._lock = threading.Lock()
        self._sessions: dict[str, tuple[str, float]] = {}

    def create(self, user: str) -> str:
        token = secrets.token_urlsafe(32)
        now = time.monotonic()
        with self._lock:
            for key in [k for k, (_, exp) in self._sessions.items() if exp <= now]:
                del self._sessions[key]
            while len(self._sessions) >= self._max:
                oldest = min(self._sessions, key=lambda k: self._sessions[k][1])
                del self._sessions[oldest]
            self._sessions[token] = (user, now + self._ttl)
        return token

    def lookup(self, token: str | None) -> tuple[str | None, str | None]:
        """Return (user, None) for a valid session or (None, denial_reason)."""
        if not token:
            return None, "missing_session"
        if not _SESSION_RE.match(token):
            return None, "invalid_session"
        now = time.monotonic()
        with self._lock:
            entry = self._sessions.get(token)
            if entry is None:
                return None, "invalid_session"
            user, expires = entry
            if expires <= now:
                del self._sessions[token]
                return None, "expired_session"
        return user, None

    def delete(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._sessions.pop(token, None)


# ── HTTP ───────────────────────────────────────────────────────────────────────

_SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Content-Security-Policy",
     "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"),
)

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>ExtorQ Lab Portal</title>
<style>body{{font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem}}
input{{display:block;margin:.4rem 0 1rem;padding:.4rem;width:100%}}</style></head>
<body><h1>ExtorQ Lab Portal</h1>
<p>Intentionally small lab application. Every login attempt is security telemetry.</p>
{body}
</body></html>
"""

_LOGIN_FORM = """<form method="post" action="/login">
<label>Username<input name="username" autocomplete="username" maxlength="64" required></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button></form>"""


@dataclass
class RequestInfo:
    method: str
    route: str
    src_ip: str | None
    request_id: str
    request_id_source: str
    user_agent: str | None
    started: float


class LabPortalHandler(BaseHTTPRequestHandler):
    server_version = "lab-portal"
    sys_version = ""
    timeout = 15  # socket timeout for slow clients

    # Set by make_server().
    config: Config
    events: EventLog
    sessions: SessionStore

    # BaseHTTPRequestHandler's own stderr access/error logging is disabled:
    # the only telemetry is the contract output on stdout.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    # ── request context ──
    def _info(self) -> RequestInfo:
        peer = normalize_ip(self.client_address[0] if self.client_address else None)
        trusted = peer is not None and peer in self.config.trusted_proxies
        src_ip = peer
        request_id = None
        if trusted:
            real_ip = self.headers.get("X-Real-IP")
            if real_ip is not None:
                src_ip = normalize_ip(real_ip)
            propagated = self.headers.get("X-Request-ID")
            if propagated and _REQUEST_ID_RE.match(propagated.strip()):
                request_id = propagated.strip()
        source = "propagated" if request_id else "generated"
        route = urlsplit(self.path).path or "/"
        return RequestInfo(
            method=clean_text(self.command, MAX_METHOD_CHARS) or "",
            route=clean_text(route, MAX_ROUTE_CHARS) or "/",
            src_ip=src_ip,
            request_id=request_id or uuid.uuid4().hex,
            request_id_source=source,
            user_agent=clean_text(self.headers.get("User-Agent"), MAX_UA_CHARS),
            started=time.perf_counter(),
        )

    def _record(self, info: RequestInfo, event: str, level: str, status: int,
                user: str | None = None, reason: str | None = None) -> None:
        self.events.emit({
            "ts": utc_ts(),
            "level": level,
            "service": SERVICE,
            "event": event,
            "user": user,
            "src_ip": info.src_ip,
            "request_id": info.request_id,
            "request_id_source": info.request_id_source,
            "method": info.method,
            "route": info.route,
            "status": status,
            "reason": reason,
            "user_agent": info.user_agent,
            "duration_ms": round((time.perf_counter() - info.started) * 1000.0, 3),
        })

    def _access(self, info: RequestInfo, status: int, user: str | None = None) -> None:
        if not self.config.log_access:
            return
        if info.route == "/healthz" and not self.config.log_access_healthz:
            return
        level = "error" if status >= 500 else "warning" if status >= 400 else "info"
        self._record(info, "http.request", level, status, user=user)

    # ── responses ──
    def _send(self, info: RequestInfo, status: int, body: bytes, content_type: str,
              extra_headers: tuple[tuple[str, str], ...] = ()) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Request-ID", info.request_id)
        for name, value in _SECURITY_HEADERS + extra_headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_html(self, info: RequestInfo, status: int, body_html: str,
                   extra_headers: tuple[tuple[str, str], ...] = ()) -> None:
        page = _PAGE.format(body=body_html).encode("utf-8")
        self._send(info, status, page, "text/html; charset=utf-8", extra_headers)

    def _send_json(self, info: RequestInfo, status: int, payload: dict[str, Any],
                   extra_headers: tuple[tuple[str, str], ...] = ()) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self._send(info, status, body, "application/json", extra_headers)

    def _cookie(self, token: str, max_age: int) -> tuple[str, str]:
        attrs = f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
        if self.config.cookie_secure:
            attrs += "; Secure"
        return ("Set-Cookie", attrs)

    def _session_token(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        for part in raw.split(";")[:32]:
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE:
                return value.strip() or None
        return None

    def _wants_json(self) -> bool:
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        accept = (self.headers.get("Accept") or "").lower()
        return ctype == "application/json" or (
            "application/json" in accept and "text/html" not in accept
        )

    # ── methods ──
    def do_GET(self) -> None:  # noqa: N802
        info = self._info()
        try:
            if info.route == "/healthz":
                self._send_json(info, 200, {"status": "ok"})
                self._access(info, 200)
            elif info.route == "/":
                self._send_html(info, 200, _LOGIN_FORM)
                self._access(info, 200)
            elif info.route == "/admin":
                self._admin(info)
            elif info.route in ("/login", "/logout"):
                self._method_not_allowed(info, "POST")
            else:
                self._send(info, 404, b"not found\n", "text/plain; charset=utf-8")
                self._access(info, 404)
        except (BrokenPipeError, ConnectionResetError, TimeoutError, socket.timeout):
            return

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        info = self._info()
        try:
            if info.route == "/login":
                self._login(info)
            elif info.route == "/logout":
                self.sessions.delete(self._session_token())
                self._send_html(info, 303, "<p>Signed out.</p>",
                                (("Location", "/"), self._cookie("", 0)))
                self._access(info, 303)
            elif info.route in ("/", "/admin", "/healthz"):
                self._method_not_allowed(info, "GET, HEAD")
            else:
                self._send(info, 404, b"not found\n", "text/plain; charset=utf-8")
                self._access(info, 404)
        except (BrokenPipeError, ConnectionResetError, TimeoutError, socket.timeout):
            return

    def _unsupported(self) -> None:
        info = self._info()
        try:
            self._method_not_allowed(info, "GET, HEAD, POST")
        except (BrokenPipeError, ConnectionResetError, TimeoutError, socket.timeout):
            return

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _unsupported  # noqa: N815

    def _method_not_allowed(self, info: RequestInfo, allow: str) -> None:
        self._send(info, 405, b"method not allowed\n", "text/plain; charset=utf-8",
                   (("Allow", allow),))
        self._access(info, 405)

    def _admin(self, info: RequestInfo) -> None:
        user, reason = self.sessions.lookup(self._session_token())
        if user is None:
            self._record(info, "authz.denied", "warning", 401, reason=reason)
            if self._wants_json():
                self._send_json(info, 401, {"ok": False, "error": "authentication_required"})
            else:
                self._send_html(info, 401, "<p>Authentication required.</p>" + _LOGIN_FORM)
            self._access(info, 401)
            return
        self._send_html(info, 200, "<h2>Admin area</h2><p>Signed in as <b>{}</b>.</p>"
                        "<form method=\"post\" action=\"/logout\"><button>Sign out</button></form>"
                        .format(html.escape(user)))
        self._access(info, 200, user=user)

    def _read_credentials(self) -> tuple[str | None, str | None, str | None, int]:
        """Parse the login body. Returns (username, password, failure_reason, status)."""
        length_header = self.headers.get("Content-Length")
        try:
            length = int(length_header) if length_header is not None else -1
        except ValueError:
            length = -1
        if length < 0:
            return None, None, "malformed_body", 400
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            return None, None, "body_too_large", 413
        raw = self.rfile.read(length) if length else b""
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        username: Any
        password: Any
        if ctype == "application/x-www-form-urlencoded":
            try:
                fields = parse_qs(raw.decode("utf-8"), keep_blank_values=True,
                                  strict_parsing=False, max_num_fields=8)
            except (UnicodeDecodeError, ValueError):
                return None, None, "malformed_body", 400
            username = (fields.get("username") or [None])[0]
            password = (fields.get("password") or [None])[0]
        elif ctype == "application/json":
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                return None, None, "malformed_body", 400
            if not isinstance(data, dict):
                return None, None, "malformed_body", 400
            username, password = data.get("username"), data.get("password")
        else:
            return None, None, "unsupported_media_type", 415
        if not isinstance(username, str) or not isinstance(password, str):
            safe_user = clean_text(username.strip(), MAX_USER_CHARS) if isinstance(username, str) else None
            return safe_user or None, None, "missing_credentials", 400
        safe_user = clean_text(username.strip(), MAX_USER_CHARS)
        if not safe_user or not password:
            return safe_user or None, None, "missing_credentials", 400
        return safe_user, password, None, 200

    def _login(self, info: RequestInfo) -> None:
        wants_json = self._wants_json()
        username, password, reason, status = self._read_credentials()
        if reason is None and username is not None and password is not None:
            credential = self.config.credential
            if credential is None:
                _DUMMY_CREDENTIAL.verify(password)
                reason, status = "login_disabled", 401
            elif username == self.config.demo_user:
                if credential.verify(password):
                    token = self.sessions.create(username)
                    cookie = self._cookie(token, self.config.session_ttl)
                    if wants_json:
                        self._record(info, "auth.login_succeeded", "info", 200, user=username)
                        self._send_json(info, 200, {"ok": True}, (cookie,))
                        self._access(info, 200, user=username)
                    else:
                        self._record(info, "auth.login_succeeded", "info", 303, user=username)
                        self._send_html(info, 303, "<p>Signed in.</p>",
                                        (("Location", "/admin"), cookie))
                        self._access(info, 303, user=username)
                    return
                reason, status = "invalid_password", 401
            else:
                _DUMMY_CREDENTIAL.verify(password)
                reason, status = "unknown_user", 401
        password = None  # never kept, never logged
        self._record(info, "auth.login_failed", "warning", status, user=username, reason=reason)
        if wants_json:
            error = "invalid_credentials" if status == 401 else "bad_request"
            self._send_json(info, status, {"ok": False, "error": error})
        else:
            message = ("Invalid username or password." if status == 401
                       else "The request could not be processed.")
            self._send_html(info, status, f"<p>{message}</p>" + _LOGIN_FORM)
        self._access(info, status, user=username)


class LabPortalServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a hard bound on concurrent request threads."""

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler],
                 max_concurrency: int) -> None:
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        self._slots = threading.BoundedSemaphore(max_concurrency)
        super().__init__(address, handler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)  # over capacity: drop instead of queueing threads
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_server(config: Config, events: EventLog | None = None) -> LabPortalServer:
    handler = type("BoundLabPortalHandler", (LabPortalHandler,), {
        "config": config,
        "events": events or EventLog(),
        "sessions": SessionStore(config.session_ttl),
    })
    return LabPortalServer((config.host, config.port), handler, config.max_concurrency)


def main(argv: list[str]) -> int:
    if argv[1:] == ["--hash-password"]:
        password = sys.stdin.readline().rstrip("\r\n")
        if len(password) < 12:
            print("password must be at least 12 characters", file=sys.stderr)
            return 2
        print(hash_password(password))
        return 0
    if len(argv) > 1:
        print("usage: app.py [--hash-password]", file=sys.stderr)
        return 2
    try:
        config = Config.from_env()
    except (ValueError, OSError) as exc:
        print(f"lab-portal: configuration error: {exc}", file=sys.stderr)
        return 2
    server = make_server(config)

    def _stop(signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    print(f"lab-portal {VERSION} listening on {config.host}:{config.port} "
          f"(log_access={int(config.log_access)}, credential="
          f"{'configured' if config.credential else 'MISSING: logins fail closed'})",
          file=sys.stderr, flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
