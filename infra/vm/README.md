# Lab VM `lab-vm-01` (owner B1)

Ubuntu 24.04 LTS "noble" arm64 cloud image on QEMU with Apple Hypervisor.framework (HVF),
provisioned by cloud-init (NoCloud seed). Asset id `linux:lab-vm-01`. Telemetry and the
collection boundary are described in `docs/telemetry/linux.md`.

## Commands (`infra/vm/vm.sh`)

| Command | What it does |
|---|---|
| `fetch` | download the pinned cloud image (serial `20261017`), verify `SHA256SUMS.gpg` with the committed Ubuntu signing key (`trust/`, fingerprint `D2EB 4462 6FDD C30B 513D 5BB7 1A5D 6C4C 7DB8 7C81`; needs `gpgv`, otherwise HTTPS + pinned hash only, `EXTORQ_VM_REQUIRE_GPG=1` makes it mandatory) and the image against `SHA256SUMS` + the pinned hash |
| `create` | `fetch` + ed25519 keys + VM host key + `known_hosts` + 16 GB qcow2 overlay + writable EFI vars + seed ISO (`hdiutil makehybrid -iso -joliet -default-volume-name cidata`). Idempotent |
| `up` | `create` if needed, boot headless (`-accel hvf -cpu host -smp 2 -m 2048`, edk2 UEFI, virtio disk + seed, `-display none`, serial console to `var/vm/console.log`, `-daemonize -pidfile`), wait for SSH (host key verified) and cloud-init. Idempotent: an already running VM is reused |
| `down` | ACPI power-off via QMP, SIGTERM/SIGKILL fallback after 90 s |
| `status` | image, disk, process, SSH reachability, cloud-init, `ssh nginx auditd lab-portal` state |
| `ssh [cmd]` | operator shell / command as `extorq-admin` (sudo) |
| `redeploy` | push dispatcher, provisioning script, sshd drop-in, nginx site, audit rules, lab-portal unit and app into the running VM and reload the services (keeps all telemetry) |
| `console [-n]` | follow (or print) the serial console log |
| `destroy --yes [--purge]` | stop and delete disk/seed/state (`--purge`: also image and keys) |

Start/stop for other agents: `infra/vm/vm.sh up` / `infra/vm/vm.sh down`;
`infra/vm/vm.sh status` shows whether it is running. The VM is left running.

Everything lives in `var/vm/` (0700, gitignored): `images/` (verified base image),
`keys/` (`extorq-admin`, `extorq-collector`, the VM's `ssh_host_ed25519_key`; 0600),
`known_hosts` (0600, pinned host key), `seed/` + `seed.iso` (rendered user-data contains
the host private key: never committed), `lab-vm-01.qcow2`, `efi-vars.fd`, `qemu.pid`,
`qmp.sock`, `console.log`.

## Network

QEMU user-mode networking (SLIRP) with host forwards bound to **127.0.0.1 only**:

| Mac | Guest |
|---|---|
| `127.0.0.1:2222` | `22` (sshd) |
| `127.0.0.1:8088` | `80` (nginx -> lab-portal on 127.0.0.1:8080) |

Nothing is opened on the Mac's external interfaces. Every connection from the Mac appears
inside the VM from `10.0.2.2` (the SLIRP gateway). The VM reaches the Mac's loopback as
`10.0.2.2` (e.g. a future push agent could use `https://10.0.2.2:8443`; the gateway
certificate already lists `IP:10.0.2.2`). **Planned, not implemented**: a push agent; today
collection is pull-only and the VM never needs to reach the Mac (see F-01 in
`docs/team/status/F.md` for the exposure this implies).

## Provisioning (cloud-init + `files/provision/extorq-provision.sh`)

* Users: `extorq-admin` (key only, passwordless sudo, lab operator) and
  `extorq-collector` (locked password, no sudo, groups `adm` + `systemd-journal`, key in
  root-owned `/etc/ssh/authorized_keys/extorq-collector`, home root-owned).
* sshd drop-in `files/sshd/10-extorq-hardening.conf` (publickey only, no root, MaxAuthTries 3,
  LogLevel VERBOSE, `Match User extorq-collector` -> `ForceCommand` dispatch boundary, no TTY,
  no forwarding).
* Dispatch boundary `files/extorq-collect-dispatch` -> `/usr/local/sbin/extorq-collect-dispatch`
  (root:root 0755, Python 3 stdlib, `python3 -I`).
* nginx site `files/nginx/extorq-lab.conf`: JSON access log (`$uri`, `$request_id`) and error
  log to journald (`nginx_access` / `nginx_error`), proxy to lab-portal with `X-Real-IP` and
  `X-Request-ID`, `server_tokens off`, small body/time limits.
* lab-portal (`lab/apps/lab-portal/app.py`) as `files/systemd/lab-portal.service`
  (DynamicUser, NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp, syscall filter,
  IP allow-list localhost, no capabilities). The demo credential is generated inside the VM
  (`/etc/extorq/lab-portal/`, root 0700) and passed with `LoadCredential=`; it never leaves the VM.
* auditd: `log_group = adm`, `log_format = ENRICHED`, `/var/log/audit` 0750 root:adm,
  rules `files/audit/extorq.rules` (watches + root exec by real users).
* PAM: `pam_motd` skipped for `extorq-collector` (no root `update-motd` scripts per collector
  login). journald persistent (`/var/log/journal`).

Known limitation: the kernel command line has no `audit=1`, so processes started before
auditd (systemd PID 1) are not audited; unit enable/disable links created by PID 1 are
visible only through the inventory diff. Adding `audit=1 audit_backlog_limit=8192` to
GRUB would need a reboot (**planned**, not applied to the running VM).

## Troubleshooting

* `vm.sh up` waits up to 600 s for SSH and 900 s for cloud-init; watch `vm.sh console`.
* Port in use: another process holds 127.0.0.1:2222/8088 (`lsof -nP -iTCP:2222`).
* Host key mismatch: the VM was recreated without `create` regenerating `known_hosts`;
  never disable `StrictHostKeyChecking`, run `vm.sh destroy --yes` + `vm.sh up`.
* Collector check: `uv run python -c 'from pathlib import Path; from extorq_collectors.linux.ssh
  import SSHDispatchClient, SSHTarget; print(SSHDispatchClient(SSHTarget.from_mapping({},
  base_dir=Path.cwd())).run("version"))'`.
