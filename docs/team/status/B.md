# B status (session 3): macOS (B3) + Kubernetes (B2)

Session 3 acts for both B3 and B2. Detailed role status with commands and results:
[B3.md](B3.md) (macOS), [B2.md](B2.md) (Kubernetes). Proposals: `docs/team/interface-changes/B.md`.

Last update: 2026-11-21T20:50Z (all session-3 items done)

| # | Item | State |
|---|---|---|
| 1 | macOS fixture data minimisation (F-24, PLAN 11) | done: 55 files / 6,753 lines -> 47 files / 904 lines; only `com.example.*` (synthetic) plus Apple's `com.openssh.sshd` / `org.cups.cupsd` match the F-24 grep; provenance README rewritten |
| 2 | MAC-001 leftover + always-cleanup script | done: leftover `51ff258a3b7d` absent (removed in session 2), its `item_deleted` confirmed; script now always removes the plist (EXIT trap), trap-tested; live run `c6c33bd9c454` created/deleted automatically, MAC-001 alert fired |
| 3 | macOS sshd -> `auth.ssh.*` (B3-IC-1 merged) | done: 5 types as on Linux, OpenSSH 10 `sshd-auth`, sender-path verification, ServiceRef to `com.openssh.sshd`; synthetic-tested (Remote Login stays off) |
| 4 | Kubernetes instances always carry `asset_id` (A-IC-2) | done: unscheduled pods on the cluster asset; runner redeployed; live check pod accepted + tombstoned; 0 quarantined k8s records |
| 5 | tests + ruff on B paths | done: macOS 110 + Kubernetes 124 = 234 passed; security 296 passed; full `uv run pytest -q` 1910 passed, 5 skipped; ruff/format/mypy clean |

Notes:
- The default kubectl context on this host is `kind-motorq-security`: every kubectl call in this
  session used `--kubeconfig var/kube/extorq-lab-admin.kubeconfig --context kind-extorq-lab`
  explicitly. The motorq-security cluster was never touched.
- No git operations, no live AI calls, no GitHub writes, no compose service rebuilt.

Announcements:
- 2026-11-21T20:31Z: restarted the shared background collector runner (`make collectors-stop`
  then `make collectors-start`, graceful SIGTERM; gap < 1 min for github-repos, k8s-inventory,
  linux-ssh-lab-vm-01, macos-workstation-01) so k8s-inventory runs the A-IC-2 code. New runner
  pid 59404; all four collectors reported `ok` right after. Note: the runner had already been
  restarted by someone else shortly before (pid 55444 at 20:25Z, then 58294).
- 2026-11-21T20:31:41Z-20:32:35Z: a never-schedulable check pod `extorq-apps/extorq-b2-asset-check`
  existed in extorq-lab (deleted; audit and inventory events for it are genuine and expected).
- 2026-11-21T20:33:47Z-20:35:59Z: MAC-001 run `c6c33bd9c454` (LaunchAgent created and removed
  automatically; a "Background Items Added" notification may have appeared).
