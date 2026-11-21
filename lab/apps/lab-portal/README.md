# lab-portal

A deliberately small web application that generates genuine application
security telemetry for the ExtorQ lab. Owner: B1. One source file
(`app.py`, Python ≥ 3.11 standard library only), configured only by
environment variables. The same source runs:

* on the Ubuntu lab VM (`linux:lab-vm-01`) behind nginx, as the hardened
  systemd unit `lab-portal.service` (DynamicUser, ProtectSystem=strict, ...);
* in the Kind cluster (`k8s:extorq-lab`) as B2's container image.

## Endpoints

| Method | Path | Behaviour |
|---|---|---|
| GET | `/` | static page with a login form |
| POST | `/login` | form (`application/x-www-form-urlencoded`) or JSON body with `username`, `password`; success sets an HttpOnly, SameSite=Strict session cookie |
| POST | `/logout` | drops the session |
| GET | `/admin` | 200 with a valid session, otherwise **401** (`authz.denied`) |
| GET | `/healthz` | `{"status":"ok"}` (probe endpoint) |

Request bodies are limited to 4 KiB, concurrent request threads to
`LAB_PORTAL_MAX_CONCURRENCY`, client sockets time out after 15 s. Responses
carry `X-Request-ID`, `nosniff`, a restrictive CSP and `Cache-Control: no-store`.
Responses never reveal whether a user name exists; unknown users still incur the
full PBKDF2 cost.

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `LAB_PORTAL_HOST` | `127.0.0.1` | bind address (`0.0.0.0` in a container) |
| `LAB_PORTAL_PORT` | `8080` | bind port |
| `LOG_ACCESS` | `0` | `1`: also emit one `http.request` line per request (k8s; on the VM nginx logs access) |
| `LOG_ACCESS_HEALTHZ` | `0` | `1`: include `/healthz` in access lines |
| `LAB_PORTAL_TRUSTED_PROXIES` | `127.0.0.1` | peers whose `X-Real-IP` / `X-Request-ID` are trusted |
| `LAB_PORTAL_DEMO_USER` | `lab-admin` | the single demo account |
| `LAB_PORTAL_PASSWORD_HASH_FILE` | — | file with `pbkdf2_sha256$<iter>$<salt>$<hash>` (preferred) |
| `LAB_PORTAL_PASSWORD_FILE` | — | file with a plain-text password (≥ 12 chars), compared in constant time |
| `LAB_PORTAL_SESSION_TTL` | `3600` | session lifetime (seconds) |
| `LAB_PORTAL_COOKIE_SECURE` | `0` | `1`: add `Secure` to the cookie (when served over TLS) |
| `LAB_PORTAL_MAX_CONCURRENCY` | `32` | maximum concurrent request threads |

Without a credential the app starts but every login fails closed
(`reason=login_disabled`). If neither file variable is set and systemd's
`$CREDENTIALS_DIRECTORY/demo_password_hash` exists, it is used.

The demo credential is generated at provisioning time and never committed:
on the VM it is created by `/usr/local/sbin/extorq-provision` and readable only
by root (`sudo cat /etc/extorq/lab-portal/demo-credentials`); in Kubernetes it
comes from a Secret mounted as a file. Hash a password with
`python3 app.py --hash-password` (reads one line from stdin).

## Log contract (`lab-portal.log.v1`)

One JSON object per line on stdout, every key always present, defined in
`docs/team/interface-changes/B1.md` §1 and `docs/telemetry/linux.md`:

```json
{"ts":"2026-11-21T10:04:02.123Z","level":"warning","service":"lab-portal","event":"auth.login_failed","user":"admin","src_ip":"10.0.2.2","request_id":"9f2c...","request_id_source":"propagated","method":"POST","route":"/login","status":401,"reason":"unknown_user","user_agent":"curl/8.7.1","duration_ms":45.112}
```

Passwords are never logged. `user` is attacker-controlled input (sanitised and
truncated), as are `route` and `user_agent`.

## Run locally

```sh
LAB_PORTAL_PORT=18080 LOG_ACCESS=1 python3 lab/apps/lab-portal/app.py
```

Tests: `uv run pytest tests/unit/linux/test_lab_portal.py -q`.
