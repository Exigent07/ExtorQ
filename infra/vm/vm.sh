#!/usr/bin/env bash
# infra/vm/vm.sh - lifecycle of the ExtorQ lab VM "lab-vm-01"
# (Ubuntu 24.04 LTS "noble" arm64 cloud image on QEMU + HVF, macOS host).
#
# Usage: infra/vm/vm.sh <command> [options]
#   fetch             only download + verify the pinned cloud image (signature + SHA256)
#   create            download + verify the image, generate keys, overlay disk, seed ISO
#   up                create if needed, boot headless, wait for SSH and cloud-init
#   down              graceful ACPI power-off (QMP), SIGTERM/SIGKILL fallback
#   status            show state (created, running, ports, SSH, cloud-init)
#   ssh [cmd...]      SSH as the lab operator extorq-admin (sudo)
#   redeploy          push the dispatcher, lab-portal and config files from the repo
#                     into the running VM and reload services (keeps all telemetry)
#   console [-n]      follow the serial console log (-n: print the tail and exit)
#   destroy --yes     stop and delete the VM disk/seed/state (keeps image + keys)
#   destroy --yes --purge   also delete the downloaded image and all keys
#
# Everything lives in var/vm/ (gitignored, 0700). Host ports are bound to
# 127.0.0.1 only: SSH 127.0.0.1:2222 -> guest 22, HTTP 127.0.0.1:8088 -> guest 80.
# The guest reaches the Mac loopback as 10.0.2.2 (QEMU user-mode networking);
# nothing is ever opened on the Mac's external interfaces.
#
# Compatible with the macOS system bash (3.2): no associative arrays, no mapfile.
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
VM_DIR="${EXTORQ_VM_DIR:-${REPO_ROOT}/var/vm}"

VM_NAME="lab-vm-01"
SSH_HOST="127.0.0.1"
SSH_PORT="${EXTORQ_VM_SSH_PORT:-2222}"
HTTP_PORT="${EXTORQ_VM_HTTP_PORT:-8088}"
VM_MEMORY_MB="${EXTORQ_VM_MEMORY_MB:-2048}"
VM_CPUS="${EXTORQ_VM_CPUS:-2}"
DISK_SIZE="${EXTORQ_VM_DISK_SIZE:-16G}"

# Pinned Ubuntu cloud image release (reproducible builds). Override the serial
# with EXTORQ_VM_UBUNTU_SERIAL=<yyyymmdd>; the published SHA256SUMS (signature
# checked with the committed Ubuntu signing key) is then the only hash source.
UBUNTU_SERIAL="${EXTORQ_VM_UBUNTU_SERIAL:-20261017}"
PINNED_SERIAL="20261017"
PINNED_IMAGE_SHA256="50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e"
IMAGE_REMOTE_NAME="noble-server-cloudimg-arm64.img"
IMAGE_BASE_URL="https://cloud-images.ubuntu.com/noble/${UBUNTU_SERIAL}"
SIGNING_KEY_FILE="${SCRIPT_DIR}/trust/ubuntu-cloud-images-signing-key.asc"
SIGNING_KEY_FPR="D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"  # gitleaks:allow (public Ubuntu cloud-image signing key fingerprint, not a secret)

QEMU_BIN="${EXTORQ_QEMU_BIN:-qemu-system-aarch64}"
QEMU_SHARE_DEFAULT="/opt/homebrew/share/qemu"
QEMU_SHARE="${EXTORQ_QEMU_SHARE:-${QEMU_SHARE_DEFAULT}}"
EFI_CODE="${QEMU_SHARE}/edk2-aarch64-code.fd"
EFI_VARS_TEMPLATE="${QEMU_SHARE}/edk2-arm-vars.fd"

IMAGES_DIR="${VM_DIR}/images"
KEYS_DIR="${VM_DIR}/keys"
SEED_DIR="${VM_DIR}/seed"
BASE_IMAGE="${IMAGES_DIR}/noble-server-cloudimg-arm64-${UBUNTU_SERIAL}.img"
SUMS_FILE="${IMAGES_DIR}/SHA256SUMS-${UBUNTU_SERIAL}"
SUMS_SIG_FILE="${IMAGES_DIR}/SHA256SUMS-${UBUNTU_SERIAL}.gpg"
VERIFIED_MARKER="${BASE_IMAGE}.verified"
DISK="${VM_DIR}/${VM_NAME}.qcow2"
EFI_VARS="${VM_DIR}/efi-vars.fd"
SEED_ISO="${VM_DIR}/seed.iso"
INSTANCE_ID_FILE="${VM_DIR}/instance-id"
PIDFILE="${VM_DIR}/qemu.pid"
QMP_SOCK="${VM_DIR}/qmp.sock"
CONSOLE_LOG="${VM_DIR}/console.log"
KNOWN_HOSTS="${VM_DIR}/known_hosts"
ADMIN_KEY="${KEYS_DIR}/extorq-admin"
COLLECTOR_KEY="${KEYS_DIR}/extorq-collector"
HOST_KEY="${KEYS_DIR}/ssh_host_ed25519_key"

SSH_WAIT_SECONDS="${EXTORQ_VM_SSH_WAIT_SECONDS:-600}"
CLOUD_INIT_WAIT_SECONDS="${EXTORQ_VM_CLOUD_INIT_WAIT_SECONDS:-900}"

log() { printf 'vm.sh: %s\n' "$*" >&2; }
die() { printf 'vm.sh: error: %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,23p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1 ($2)"
}

require_tools() {
  require_tool "${QEMU_BIN}" "brew install qemu"
  require_tool qemu-img "brew install qemu"
  require_tool hdiutil "macOS built-in"
  require_tool ssh "macOS built-in"
  require_tool ssh-keygen "macOS built-in"
  require_tool curl "macOS built-in"
  require_tool shasum "macOS built-in"
  require_tool python3 "macOS/Homebrew python3 (stdlib only)"
  [ -r "${EFI_CODE}" ] || die "UEFI firmware not found: ${EFI_CODE} (set EXTORQ_QEMU_SHARE)"
  [ -r "${EFI_VARS_TEMPLATE}" ] || die "UEFI vars template not found: ${EFI_VARS_TEMPLATE}"
}

ensure_dirs() {
  mkdir -p "${VM_DIR}" "${IMAGES_DIR}" "${KEYS_DIR}" "${SEED_DIR}"
  chmod 0700 "${VM_DIR}" "${IMAGES_DIR}" "${KEYS_DIR}" "${SEED_DIR}"
}

sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }

# ── Image download and verification ────────────────────────────────────────────

verify_sums_signature() {
  if ! command -v gpgv >/dev/null 2>&1 || ! command -v gpg >/dev/null 2>&1; then
    if [ "${EXTORQ_VM_REQUIRE_GPG:-0}" = "1" ]; then
      die "gpg/gpgv not available but EXTORQ_VM_REQUIRE_GPG=1"
    fi
    log "WARNING: gpg/gpgv not installed; SHA256SUMS signature NOT verified (HTTPS + pinned hash only)"
    return 0
  fi
  local tmp keyring status
  tmp="$(mktemp -d "${VM_DIR}/.gpg.XXXXXX")"
  keyring="${tmp}/ubuntu-cloud-images.gpg"
  # Dearmor the committed public key into a private keyring (no agent, no dirmngr).
  gpg --homedir "${tmp}" --batch --quiet --dearmor <"${SIGNING_KEY_FILE}" >"${keyring}"
  if ! status="$(gpgv --status-fd 1 --keyring "${keyring}" "${SUMS_SIG_FILE}" "${SUMS_FILE}" 2>/dev/null)"; then
    rm -rf "${tmp}"
    die "SHA256SUMS signature verification FAILED for serial ${UBUNTU_SERIAL}"
  fi
  rm -rf "${tmp}"
  if ! printf '%s\n' "${status}" | grep -q "^\[GNUPG:\] VALIDSIG .* ${SIGNING_KEY_FPR}\$"; then
    die "SHA256SUMS not signed by the pinned Ubuntu key ${SIGNING_KEY_FPR}"
  fi
  log "SHA256SUMS signature OK (Ubuntu cloud image key ${SIGNING_KEY_FPR})"
}

fetch_image() {
  if [ -f "${BASE_IMAGE}" ] && [ -f "${VERIFIED_MARKER}" ]; then
    local recorded
    recorded="$(cat "${VERIFIED_MARKER}")"
    if [ "$(sha256_of "${BASE_IMAGE}")" = "${recorded}" ]; then
      log "base image present and verified: ${BASE_IMAGE##*/}"
      return 0
    fi
    log "base image hash no longer matches its verification record; re-downloading"
    chmod 0600 "${BASE_IMAGE}" 2>/dev/null || true
    rm -f "${BASE_IMAGE}" "${VERIFIED_MARKER}"
  fi

  log "downloading SHA256SUMS for noble serial ${UBUNTU_SERIAL}"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --connect-timeout 20 --max-time 120 --retry 3 --retry-delay 2 \
    -o "${SUMS_FILE}" "${IMAGE_BASE_URL}/SHA256SUMS"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --connect-timeout 20 --max-time 120 --retry 3 --retry-delay 2 \
    -o "${SUMS_SIG_FILE}" "${IMAGE_BASE_URL}/SHA256SUMS.gpg"
  verify_sums_signature

  local expected
  expected="$(awk -v f="*${IMAGE_REMOTE_NAME}" '$2 == f {print $1}' "${SUMS_FILE}")"
  [ -n "${expected}" ] || die "${IMAGE_REMOTE_NAME} not listed in SHA256SUMS"
  printf '%s' "${expected}" | grep -Eq '^[0-9a-f]{64}$' || die "malformed hash in SHA256SUMS"
  if [ "${UBUNTU_SERIAL}" = "${PINNED_SERIAL}" ] && [ "${expected}" != "${PINNED_IMAGE_SHA256}" ]; then
    die "SHA256SUMS hash ${expected} differs from the pinned hash for serial ${PINNED_SERIAL}"
  fi

  local part="${BASE_IMAGE}.part"
  log "downloading ${IMAGE_REMOTE_NAME} (~600 MB) from ${IMAGE_BASE_URL}"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --connect-timeout 20 --retry 5 --retry-delay 3 --continue-at - \
    -o "${part}" "${IMAGE_BASE_URL}/${IMAGE_REMOTE_NAME}"
  local actual
  actual="$(sha256_of "${part}")"
  if [ "${actual}" != "${expected}" ]; then
    rm -f "${part}"
    die "image SHA256 mismatch: expected ${expected}, got ${actual} (partial download removed)"
  fi
  mv "${part}" "${BASE_IMAGE}"
  chmod 0444 "${BASE_IMAGE}"
  printf '%s\n' "${actual}" >"${VERIFIED_MARKER}"
  chmod 0600 "${VERIFIED_MARKER}"
  log "image verified: sha256 ${actual}"
}

# ── Keys and known_hosts ───────────────────────────────────────────────────────

gen_key() {
  local path="$1" comment="$2"
  if [ ! -f "${path}" ]; then
    ssh-keygen -q -t ed25519 -N '' -C "${comment}" -f "${path}"
    log "generated ed25519 key ${path#"${REPO_ROOT}"/}"
  fi
  chmod 0600 "${path}" "${path}.pub"
}

gen_keys() {
  gen_key "${ADMIN_KEY}" "extorq-admin@extorq-lab"
  gen_key "${COLLECTOR_KEY}" "extorq-collector@extorq-lab"
  gen_key "${HOST_KEY}" "root@${VM_NAME}"
  local host_pub
  host_pub="$(awk '{print $1" "$2}' "${HOST_KEY}.pub")"
  printf '[%s]:%s %s\n' "${SSH_HOST}" "${SSH_PORT}" "${host_pub}" >"${KNOWN_HOSTS}.tmp"
  mv "${KNOWN_HOSTS}.tmp" "${KNOWN_HOSTS}"
  chmod 0600 "${KNOWN_HOSTS}"
}

# ── Seed ISO (cloud-init NoCloud) ──────────────────────────────────────────────

build_seed() {
  if [ ! -f "${INSTANCE_ID_FILE}" ]; then
    printf 'iid-extorq-%s-%s\n' "${VM_NAME}" "$(date -u +%Y%m%dT%H%M%SZ)" >"${INSTANCE_ID_FILE}"
  fi
  local instance_id
  instance_id="$(cat "${INSTANCE_ID_FILE}")"
  python3 -I "${SCRIPT_DIR}/lib/render_cloud_init.py" \
    --template-dir "${SCRIPT_DIR}/cloud-init" \
    --files-dir "${SCRIPT_DIR}/files" \
    --lab-portal-dir "${REPO_ROOT}/lab/apps/lab-portal" \
    --admin-pubkey "${ADMIN_KEY}.pub" \
    --collector-pubkey "${COLLECTOR_KEY}.pub" \
    --host-key "${HOST_KEY}" \
    --hostname "${VM_NAME}" \
    --instance-id "${instance_id}" \
    --out-dir "${SEED_DIR}"
  rm -f "${SEED_ISO}"
  hdiutil makehybrid -quiet -iso -joliet -default-volume-name cidata -o "${SEED_ISO}" "${SEED_DIR}"
  chmod 0600 "${SEED_ISO}" "${SEED_DIR}"/*
  log "seed ISO built (instance ${instance_id})"
}

create_disk() {
  if [ ! -f "${DISK}" ]; then
    # Relative backing path: the overlay stays valid if var/vm moves as a whole.
    (cd "${VM_DIR}" && qemu-img create -q -f qcow2 -F qcow2 \
      -b "images/${BASE_IMAGE##*/}" "${DISK##*/}" "${DISK_SIZE}")
    chmod 0600 "${DISK}"
    log "created overlay ${DISK##*/} (${DISK_SIZE}) on ${BASE_IMAGE##*/}"
  fi
  if [ ! -f "${EFI_VARS}" ]; then
    cp "${EFI_VARS_TEMPLATE}" "${EFI_VARS}"
    chmod 0600 "${EFI_VARS}"
  fi
}

cmd_create() {
  require_tools
  ensure_dirs
  fetch_image
  gen_keys
  if [ -f "${DISK}" ] && [ -f "${SEED_ISO}" ]; then
    log "VM already created (disk and seed present); use 'destroy --yes' + 'create' to rebuild"
    return 0
  fi
  build_seed
  create_disk
  log "created ${VM_NAME}; start it with: infra/vm/vm.sh up"
}

# ── Process state ──────────────────────────────────────────────────────────────

vm_pid() {
  [ -f "${PIDFILE}" ] || return 1
  local pid
  pid="$(tr -cd '0-9' <"${PIDFILE}")"
  [ -n "${pid}" ] || return 1
  # Guard against PID reuse: the process must be our QEMU.
  if ps -ww -p "${pid}" -o command= 2>/dev/null | grep -Fq "file=${DISK},"; then
    printf '%s\n' "${pid}"
    return 0
  fi
  return 1
}

port_in_use() {
  lsof -nP -iTCP@"${SSH_HOST}":"$1" -sTCP:LISTEN >/dev/null 2>&1
}

# Common ssh options as a global array (bash 3.2 safe; never empty).
SSH_OPTS=()
init_ssh_opts() {
  # -F /dev/null: ignore the operator's ~/.ssh/config so behaviour is reproducible.
  SSH_OPTS=(-F /dev/null -i "${ADMIN_KEY}"
    -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=${KNOWN_HOSTS}"
    -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no
    -o HostKeyAlgorithms=ssh-ed25519 -o PasswordAuthentication=no
    -o KbdInteractiveAuthentication=no -o ConnectTimeout=5
    -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o LogLevel=ERROR
    -p "${SSH_PORT}")
}
init_ssh_opts

admin_ssh() {
  ssh "${SSH_OPTS[@]}" "extorq-admin@${SSH_HOST}" "$@"
}

wait_for_ssh() {
  local deadline=$(( $(date +%s) + SSH_WAIT_SECONDS ))
  log "waiting for SSH on ${SSH_HOST}:${SSH_PORT} (timeout ${SSH_WAIT_SECONDS}s)"
  while :; do
    if admin_ssh true </dev/null >/dev/null 2>&1; then
      log "SSH is answering (host key verified against ${KNOWN_HOSTS##*/})"
      return 0
    fi
    vm_pid >/dev/null || die "QEMU exited during boot; see ${CONSOLE_LOG}"
    [ "$(date +%s)" -lt "${deadline}" ] || die "SSH did not answer within ${SSH_WAIT_SECONDS}s; see ${CONSOLE_LOG}"
    sleep 3
  done
}

cloud_init_state() {
  # Prints cloud-init's extended status: running | degraded running | done |
  # degraded done | error | disabled | unknown. `cloud-init status` exits non-zero
  # for degraded states, so its exit code is deliberately ignored.
  admin_ssh "cloud-init status --format=json 2>/dev/null; true" </dev/null 2>/dev/null |
    python3 -I -c 'import json,sys
try:
    d = json.load(sys.stdin)
except ValueError:
    print("unknown"); sys.exit(0)
print(d.get("extended_status") or d.get("status") or "unknown")' || echo unknown
}

wait_for_cloud_init() {
  log "waiting for cloud-init to finish (timeout ${CLOUD_INIT_WAIT_SECONDS}s)"
  local deadline=$(( $(date +%s) + CLOUD_INIT_WAIT_SECONDS ))
  local state
  while :; do
    state="$(cloud_init_state)"
    case "${state}" in
      done)
        log "cloud-init: done"
        return 0 ;;
      "degraded done")
        log "cloud-init finished with warnings; details: infra/vm/vm.sh ssh sudo cloud-init status --long"
        return 0 ;;
      error|disabled)
        log "cloud-init state '${state}'; details: infra/vm/vm.sh ssh sudo cloud-init status --long"
        return 1 ;;
    esac
    [ "$(date +%s)" -lt "${deadline}" ] || die "cloud-init did not finish within ${CLOUD_INIT_WAIT_SECONDS}s (state ${state})"
    sleep 5
  done
}

cmd_up() {
  local pid
  if pid="$(vm_pid)"; then
    log "${VM_NAME} already running (pid ${pid})"
    wait_for_ssh
    return 0
  fi
  cmd_create
  rm -f "${PIDFILE}" "${QMP_SOCK}"
  if port_in_use "${SSH_PORT}"; then die "127.0.0.1:${SSH_PORT} is already in use by another process"; fi
  if port_in_use "${HTTP_PORT}"; then die "127.0.0.1:${HTTP_PORT} is already in use by another process"; fi

  if [ -f "${CONSOLE_LOG}" ] && [ "$(wc -c <"${CONSOLE_LOG}")" -gt 10485760 ]; then
    mv -f "${CONSOLE_LOG}" "${CONSOLE_LOG}.1"
  fi
  printf '\n===== vm.sh: boot %s =====\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"${CONSOLE_LOG}"
  chmod 0600 "${CONSOLE_LOG}"

  log "booting ${VM_NAME} (hvf, ${VM_CPUS} vCPU, ${VM_MEMORY_MB} MiB, ssh 127.0.0.1:${SSH_PORT}, http 127.0.0.1:${HTTP_PORT})"
  "${QEMU_BIN}" \
    -name "extorq-${VM_NAME}" \
    -machine virt -accel hvf -cpu host \
    -smp "${VM_CPUS}" -m "${VM_MEMORY_MB}" \
    -nodefaults -display none \
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=${EFI_CODE}" \
    -drive "if=pflash,format=raw,unit=1,file=${EFI_VARS}" \
    -drive "if=none,id=disk0,format=qcow2,file=${DISK},discard=unmap" \
    -device virtio-blk-pci,drive=disk0,bootindex=0 \
    -drive "if=none,id=seed0,format=raw,readonly=on,file=${SEED_ISO}" \
    -device virtio-blk-pci,drive=seed0 \
    -netdev "user,id=net0,ipv6=off,hostfwd=tcp:${SSH_HOST}:${SSH_PORT}-:22,hostfwd=tcp:${SSH_HOST}:${HTTP_PORT}-:80" \
    -device virtio-net-pci,netdev=net0 \
    -device virtio-rng-pci \
    -chardev "file,id=serial0,path=${CONSOLE_LOG},append=on" \
    -serial chardev:serial0 \
    -monitor none \
    -qmp "unix:${QMP_SOCK},server=on,wait=off" \
    -pidfile "${PIDFILE}" \
    -daemonize
  pid="$(vm_pid)" || die "QEMU did not start; see ${CONSOLE_LOG}"
  log "QEMU running (pid ${pid}); console: ${CONSOLE_LOG#"${REPO_ROOT}"/}"
  wait_for_ssh
  wait_for_cloud_init || true
  log "${VM_NAME} is up. Operator shell: infra/vm/vm.sh ssh"
}

cmd_down() {
  local pid
  if ! pid="$(vm_pid)"; then
    log "${VM_NAME} is not running"
    rm -f "${PIDFILE}" "${QMP_SOCK}"
    return 0
  fi
  log "requesting ACPI power-off via QMP (pid ${pid})"
  if ! python3 -I "${SCRIPT_DIR}/lib/qmp.py" "${QMP_SOCK}" system_powerdown >/dev/null 2>&1; then
    log "QMP unavailable; falling back to SIGTERM"
    kill -TERM "${pid}" 2>/dev/null || true
  fi
  local waited=0
  while kill -0 "${pid}" 2>/dev/null; do
    if [ "${waited}" -ge 90 ]; then
      log "guest did not power off within 90s; sending SIGTERM"
      kill -TERM "${pid}" 2>/dev/null || true
      sleep 5
      kill -0 "${pid}" 2>/dev/null && { log "sending SIGKILL"; kill -KILL "${pid}" 2>/dev/null || true; }
      break
    fi
    sleep 2
    waited=$((waited + 2))
  done
  rm -f "${PIDFILE}" "${QMP_SOCK}"
  log "${VM_NAME} stopped"
}

cmd_status() {
  local created="no" running="no" pid="-"
  [ -f "${DISK}" ] && created="yes"
  if pid="$(vm_pid)"; then running="yes"; else pid="-"; fi
  printf 'vm:            %s\n' "${VM_NAME}"
  printf 'state dir:     %s\n' "${VM_DIR}"
  printf 'image:         %s\n' "$( [ -f "${VERIFIED_MARKER}" ] && echo "${BASE_IMAGE##*/} (verified)" || echo "not downloaded")"
  printf 'created:       %s\n' "${created}"
  printf 'running:       %s (pid %s)\n' "${running}" "${pid}"
  printf 'ssh:           %s:%s (users extorq-admin, extorq-collector)\n' "${SSH_HOST}" "${SSH_PORT}"
  printf 'http:          http://%s:%s/\n' "${SSH_HOST}" "${HTTP_PORT}"
  if [ "${created}" = "yes" ]; then
    printf 'disk:          %s\n' "$(qemu-img info --force-share --output=human "${DISK}" 2>/dev/null | awk -F': ' '/^disk size/ {print $2}') used of ${DISK_SIZE}"
  fi
  if [ "${running}" = "yes" ]; then
    if admin_ssh true </dev/null >/dev/null 2>&1; then
      printf 'ssh reachable: yes\n'
      printf 'cloud-init:    %s\n' "$(cloud_init_state)"
      printf 'services:      %s\n' "$(admin_ssh 'for s in ssh nginx auditd lab-portal; do printf "%s=%s " "$s" "$(systemctl is-active $s)"; done' </dev/null 2>/dev/null || echo unknown)"
    else
      printf 'ssh reachable: no\n'
    fi
  fi
}

cmd_ssh() {
  [ -f "${ADMIN_KEY}" ] || die "no admin key; run: infra/vm/vm.sh create"
  vm_pid >/dev/null || die "${VM_NAME} is not running; run: infra/vm/vm.sh up"
  if [ "$#" -eq 0 ]; then
    exec ssh "${SSH_OPTS[@]}" -t "extorq-admin@${SSH_HOST}"
  fi
  exec ssh "${SSH_OPTS[@]}" "extorq-admin@${SSH_HOST}" "$@"
}

# Files deployed by cloud-init, re-deployable into a running VM:
# "<source relative to repo root>|<destination>|<mode>"
REDEPLOY_FILES="infra/vm/files/extorq-collect-dispatch|/usr/local/sbin/extorq-collect-dispatch|0755
infra/vm/files/provision/extorq-provision.sh|/usr/local/sbin/extorq-provision|0755
infra/vm/files/sshd/10-extorq-hardening.conf|/etc/ssh/sshd_config.d/10-extorq-hardening.conf|0644
infra/vm/files/nginx/extorq-lab.conf|/etc/nginx/conf.d/extorq-lab.conf|0644
infra/vm/files/audit/extorq.rules|/etc/audit/rules.d/extorq.rules|0640
infra/vm/files/systemd/lab-portal.service|/etc/systemd/system/lab-portal.service|0644
lab/apps/lab-portal/app.py|/opt/extorq/lab-portal/app.py|0644
lab/apps/lab-portal/README.md|/opt/extorq/lab-portal/README.md|0644"

cmd_redeploy() {
  vm_pid >/dev/null || die "${VM_NAME} is not running; run: infra/vm/vm.sh up"
  local line src dst mode
  while IFS= read -r line; do
    [ -n "${line}" ] || continue
    src="${line%%|*}"; line="${line#*|}"
    dst="${line%%|*}"; mode="${line##*|}"
    [ -f "${REPO_ROOT}/${src}" ] || die "missing source file ${src}"
    # Destinations are fixed strings above (never user input).
    admin_ssh "sudo install -D -o root -g root -m ${mode} /dev/stdin '${dst}'" <"${REPO_ROOT}/${src}" \
      || die "failed to deploy ${dst}"
    log "deployed ${dst} (${mode})"
  done <<EOF_FILES
${REDEPLOY_FILES}
EOF_FILES
  admin_ssh 'set -e
    sudo sshd -t
    sudo systemctl try-restart ssh.service
    sudo nginx -t 2>/dev/null
    sudo systemctl reload nginx.service
    sudo augenrules --load >/dev/null
    sudo systemctl daemon-reload
    sudo systemctl restart lab-portal.service
    printf "services: "; for s in ssh nginx auditd lab-portal; do printf "%s=%s " "$s" "$(systemctl is-active $s)"; done; echo' </dev/null \
    || die "service reload failed; inspect with: infra/vm/vm.sh ssh"
  log "redeploy complete"
}

cmd_console() {
  [ -f "${CONSOLE_LOG}" ] || die "no console log yet (${CONSOLE_LOG})"
  if [ "${1:-}" = "-n" ] || [ "${1:-}" = "--no-follow" ]; then
    tail -n 200 "${CONSOLE_LOG}"
  else
    exec tail -n 200 -F "${CONSOLE_LOG}"
  fi
}

cmd_destroy() {
  local yes="no" purge="no" arg
  for arg in "$@"; do
    case "${arg}" in
      --yes) yes="yes" ;;
      --purge) purge="yes" ;;
      *) die "unknown destroy option: ${arg}" ;;
    esac
  done
  [ "${yes}" = "yes" ] || die "destroy deletes the VM disk and all telemetry inside it; re-run with --yes"
  cmd_down
  rm -f "${DISK}" "${EFI_VARS}" "${SEED_ISO}" "${INSTANCE_ID_FILE}" "${CONSOLE_LOG}" "${CONSOLE_LOG}.1"
  rm -rf "${SEED_DIR}"
  if [ "${purge}" = "yes" ]; then
    chmod -R u+w "${IMAGES_DIR}" 2>/dev/null || true
    rm -rf "${IMAGES_DIR}" "${KEYS_DIR}" "${KNOWN_HOSTS}"
    log "purged image cache and keys"
  fi
  log "${VM_NAME} destroyed"
}

main() {
  local cmd="${1:-}"
  [ -n "${cmd}" ] || { usage; exit 2; }
  shift
  case "${cmd}" in
    fetch) require_tools; ensure_dirs; fetch_image ;;
    create) cmd_create ;;
    up) cmd_up ;;
    down) cmd_down ;;
    status) cmd_status ;;
    ssh) cmd_ssh "$@" ;;
    redeploy) cmd_redeploy ;;
    console) cmd_console "$@" ;;
    destroy) cmd_destroy "$@" ;;
    -h|--help|help) usage ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
