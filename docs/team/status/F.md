# Agent F status (Security assurance, QA, documentation)

Last update: 2026-11-21 (in progress; review pass 1 done)

## Doing
- Docs baseline (threat model, privilege audit, ADRs, README, architecture, deployment,
  operations, testing, known limitations, telemetry index, demo runbook, AGENTS.md).
- Review pass 2 once compose/CI/collectors/rules land.

## Done
- Security test suite `tests/security/` (static + Docker-based, runs without the stack):
  repo hygiene, gitleaks (pinned image, tree + history + positive control), Python AST
  checks (shell, dynamic SQL, eval/unsafe deserialisation, TLS verification), frontend
  XSS/credential checks, compose/Dockerfile checks, CI workflow checks, Kubernetes RBAC/
  workload/audit-policy/kind checks, QEMU hostfwd check, rule-SQL checks, analyst API
  authorization (route graph + behaviour), prompt-injection corpus (47 synthetic cases)
  with sanitiser contract test.
- Interface proposals: `docs/team/interface-changes/F.md` (F-IC-1..5).
- Review pass 1 (findings below).

## Verified (commands and observed results)
| Claim | Command | Result |
|---|---|---|
| Security suite runs, lint clean | `uv run ruff check tests/security && uv run pytest tests/security -q` | ruff: all checks passed; pytest: 1 failed (F-04/F-05 pragma requests to A), rest passed or skipped pending artifacts (see Testing) |
| gitleaks detects and redacts a runtime-generated synthetic token | `uv run pytest tests/security/test_security_secret_scan.py -q` | 3 passed (tree scan clean, history clean, positive control detects `github-pat`, value absent from output) |
| Gateway gzip bomb guard | python probe: `gunzip_limited(gzip(64 MiB zeros), 4 MiB)` | `BodyError 413` in 0.002 s; multi-member gzip -> 400 |
| Gateway quarantines NaN records and denies cross-asset records | python probe over `prepare_batch` | NaN -> quarantined `record_not_serialisable`; `linux-ssh-lab-vm-01` sending `macos:workstation-01` -> denied `asset_not_allowed` |
| Every analyst API route authenticated; mutations analyst-only | `uv run pytest tests/security/test_security_api_authz.py -q` | 6 passed (17 /api/v1 routes need the principal; POST summary/state need analyst; viewer -> 403; bad token -> 401) |
| E's AI sanitiser neutralises the corpus | python probe: `clean_untrusted`/`clean_output` over 47 cases | 0 violations (no Cc/Cf/Co/Cs, no 32-hex ids, no `<`/`>`, outputs defanged) |
| A's `sanitize_untrusted` meets the documented contract | `uv run pytest tests/security/test_security_prompt_injection_corpus.py -q` | 55 passed (length bound + no C0/C1 controls for all 47 payloads) |
| Contracts accept NaN; `record_identity` then raises | python probe (synthetic record) | `ValueError: Out of range float values are not JSON compliant` (F-IC-1) |
| `.gitignore` gaps | `git check-ignore -q --no-index id_ed25519 kubeconfig` | both NOT ignored (F-IC-2) |
| B2 RBAC read-only, audit policy safe, kind binds loopback | `uv run pytest tests/security/test_security_lab_boundaries.py -q` | 10 passed |

## Not verified
- Live ClickHouse privileges per user (needs `STACK READY`; RBAC reviewed statically only).
- B1 dispatcher behaviour inside the VM (code reviewed; not executed by F).
- compose.yaml, Dockerfiles, CI workflows, rule SQL: not present at review time (tests skip).
- Frontend runtime behaviour (code reviewed only).

## Review findings (pass 1, 2026-11-21)
| ID | Severity | Component | File:line | Issue | Recommendation | Status |
|---|---|---|---|---|---|---|
| F-01 | Medium | All (topology) | PLAN 4.2; `infra/vm/vm.sh:367`; kind pods via `host.docker.internal` | "Loopback-only" is not isolation from the lab: the VM reaches Mac loopback at 10.0.2.2 (QEMU user net) and kind pods reach it via `host.docker.internal`. Gateway 8443, API 8000, console 3000, Grafana 3001 and (debug) ClickHouse 18123 are reachable from the intentionally attackable lab assets. | Keep every published service authenticated (true today); never run the `debug` profile during demos; consider QEMU `restrict=on` after provisioning (collection is SSH pull, the VM need not reach the host). Documented in threat model. | open (by design) |
| F-02 | Low | A redaction | `backend/src/extorq/common/redaction.py` (`_CONTROLS`) | `sanitize_untrusted` keeps Unicode tag characters (U+E0000-E007F), U+2028/2029, U+00AD, U+180E (verified). Invisible instructions / forged line breaks survive in stored `message`/`raw` shown in UI, Grafana and terminals. (AI path is protected by E's `clean_untrusted`.) | Strip all `Cf` characters (as E does) and map Zl/Zp to space. | open |
| F-03 | Low | A redaction | `backend/src/extorq/common/redaction.py` (`_CONTROLS`) | The regex embeds literal bidi/zero-width characters (U+202A-202E, U+2066-2069, U+200B-200F, U+FEFF) in source: Trojan Source review hazard. | Use `\u` escapes; lead could enable ruff `PLE2502`. | open |
| F-04 | Info | A migrate | `backend/src/extorq/storage/migrate.py:294` | `ALTER USER ... BY '<hex>' SALT '<hex>'` built with an f-string. Reviewed safe: allow-listed user, regex-validated hex, ClickHouse cannot bind parameters here. | Add `# extorq: sql-reviewed <reason>` on the call lines (security suite fails until then); prefer `fullmatch`. | open |
| F-05 | Info | A spool | `backend/src/extorq/pipeline/spool.py:175` | `PRAGMA {name}` guarded by `str.isidentifier()` (allows non-ASCII identifiers); callers pass constants. | Add the pragma marker; optionally an explicit pragma allow-list. | open |
| F-06 | Low | A redaction | `backend/src/extorq/common/redaction.py` (`_RULES`) | Whitespace-separated CLI secrets (`--password x`, `-p<secret>`) and `Authorization: Token x` are not redacted (verified). sudo command lines are a realistic source. | Add CLI-flag and generic `Authorization: <scheme> <value>` rules. | open |
| F-07 | Info | Lead contracts | `backend/src/extorq/contracts/common.py` | NaN/Infinity validate, then break `canonical_json`/`record_identity` (verified). Gateway already quarantines them (verified), so this is defence in depth. | F-IC-1: `allow_inf_nan=False`. | proposed |
| F-08 | Info | Lead | `.gitignore` | `id_ed25519*` and bare `kubeconfig` are not ignored (verified); today such files live under ignored `var/`. | F-IC-2. | proposed |
| F-09 | Low | Host | `.env` (metadata only) | `.env` is mode 0644 (world-readable on the host); it holds the Jev/Gemini keys. Observed with `ls -l`, content never read. | User/lead: `chmod 600 .env`. | open |
| F-10 | Low | B2 | `infra/kind/manifests/40-posture-lab.yaml` | Deliberately weak posture target runs as root with read-only hostPath `/var/log`; on the single-node cluster that includes the API audit log and all pod logs. Only cluster-admin can exec into it today. | Mount a narrower path (e.g. `/var/log/journal` or a dedicated dummy dir) so the finding stays genuine without audit-log read access. | open |
| F-11 | Info | B2 | `infra/kind/manifests/00-namespaces.yaml:41` | `extorq-restricted` enforces PSA `baseline` (deliberate: baseline already denies privileged/host-namespace pods for K8S-001). Name may mislead in the demo. | Say "baseline enforcement" in the demo/docs or rename. | open |
| F-12 | Info | D1 | `backend/src/extorq/api/auth.py` | By design, any holder of the API service token can assert any user/role; the API is reachable from lab assets (F-01). | Token only in the frontend container; rotate with `bootstrap.py --rotate`. Documented. | accepted |
| F-13 | Info | D2 | `frontend/src/lib/server/session.ts` | Stateless JWS sessions (8 h): logout clears the cookie, a copied token stays valid until expiry; rotating `frontend_session_secret` revokes all. | Accept for the lab; documented. | accepted |
| F-14 | Info | C1 | `collectors/src/extorq_collectors/github/token.py` | Optional `gh auth token` fallback uses the operator's broad OAuth scopes (opt-in, warns in health). | Use a fine-grained read-only PAT for the demo; keep the fallback off. | open |
| F-15 | Resolved | D2 | `frontend/src/components/ui/chart.tsx` | shadcn `ChartStyle` used `dangerouslySetInnerHTML` for CSS built from config keys. | D2 replaced it with validated CSS custom properties (`SAFE_CONFIG_KEY`, `SAFE_COLOR`); re-scan clean. | resolved |

Positive controls confirmed in review (code read; see Verified for executed checks):
A gateway (streamed size limits, bounded gzip, constant-time token check over all
producers, per-record authorization, quarantine with redacted excerpts), A ClickHouse
(default user removed, MySQL/Postgres/interserver ports removed, system tables need
grants, session_log on, RBAC = PLAN 4.4, Grafana without raw/payload), A bootstrap
(256-bit secrets, atomic 0600 writes, EC P-256 CA pathlen:0), B1 dispatcher
(`python3 -I`, strict grammar, fixed argv, minimal env, timeouts, watchdog, hashed
denial logging) and sshd (publickey only, ForceCommand + `restrict,command=`), B2
(read-only RBAC, no secrets, Metadata audit for secrets/tokens, separate admin
kubeconfig under var/, short-lived inventory token), C1 (repr-safe token, mode
warnings), C2 (rule SQL guard), D1 (fail-closed auth), D2 (HttpOnly SameSite=Strict
JWS session, constant-time login, header stripping, CSP nonce), E (providers off by
default, SecretStr keys, daily caps, evidence-id verification, strong sanitiser).

## Blockers
- none

## Next
- Docs baseline; review pass 2 (compose, CI, Dockerfiles, collectors, rules, writer).
- Live RBAC probe once `STACK READY`.
