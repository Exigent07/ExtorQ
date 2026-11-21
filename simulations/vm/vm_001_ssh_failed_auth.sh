#!/usr/bin/env bash
# VM-001 - failed SSH authentication burst against the lab VM (ExtorQ lab simulation, owner B1).
#
# From the Mac, opens at least 8 SSH connections to 127.0.0.1:2222 (the lab VM through QEMU
# user-mode networking) as the non-existent user "extorq-sim-<run_id>", each offering only a
# freshly generated throwaway ed25519 key. Every attempt fails: the account does not exist,
# the VM accepts public keys only (no password or keyboard-interactive authentication is
# offered by the client or allowed by the server). A final connection offers four throwaway
# keys in one session so sshd's MaxAuthTries (3) limit is exceeded as well.
#
# Nothing on the VM changes. The throwaway keys live in a private temporary directory and are
# deleted on exit. The VM sees every connection from 10.0.2.2 (the SLIRP gateway).
#
# Usage: simulations/vm/vm_001_ssh_failed_auth.sh [--run-id ID] [--attempts N] [--cleanup]
#   --run-id ID    reuse a run id (8-32 lower-case alphanumerics; generated if omitted)
#   --attempts N   single-key failed connections (default 8, minimum 8, maximum 30)
#   --cleanup      nothing persistent is created; records the run as cleaned_up
# Environment: EXTORQ_SIM_RECORD=0 skips SimulationRun recording.
set -Eeuo pipefail
umask 077

# shellcheck source=simulations/vm/common.sh
. "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

SCENARIO="VM-001"
RUN_ID=""
ATTEMPTS=8
CLEANUP=0

while [ $# -gt 0 ]; do
  case "$1" in
    --run-id) [ $# -ge 2 ] || sim_die "--run-id needs a value"; RUN_ID="$2"; shift 2 ;;
    --attempts) [ $# -ge 2 ] || sim_die "--attempts needs a value"; ATTEMPTS="$2"; shift 2 ;;
    --cleanup) CLEANUP=1; shift ;;
    -h|--help) sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) sim_die "unknown argument: $1" ;;
  esac
done
printf '%s' "${ATTEMPTS}" | grep -Eq '^[0-9]{1,2}$' || sim_die "--attempts must be a number"
[ "${ATTEMPTS}" -ge 8 ] && [ "${ATTEMPTS}" -le 30 ] || sim_die "--attempts must be 8..30"

if [ "${CLEANUP}" -eq 1 ]; then
  [ -n "${RUN_ID}" ] || sim_die "--cleanup requires --run-id"
  sim_validate_run_id "${RUN_ID}"
  sim_info "VM-001 creates nothing on the VM; throwaway keys were deleted when the run ended"
  sim_record "${SCENARIO}" cleaned_up "${RUN_ID}"
  exit 0
fi

[ -n "${RUN_ID}" ] || RUN_ID="$(sim_new_run_id)"
sim_validate_run_id "${RUN_ID}"
sim_require_vm
command -v ssh-keygen >/dev/null || sim_die "ssh-keygen not found"

SIM_USER="extorq-sim-${RUN_ID}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/extorq-vm001.XXXXXX")"
cleanup_tmp() { rm -rf "${WORK_DIR}"; }
trap cleanup_tmp EXIT

for k in 0 1 2 3 4; do
  ssh-keygen -q -t ed25519 -N '' -C "extorq-sim-${RUN_ID}-throwaway-${k}" -f "${WORK_DIR}/key${k}"
done

ssh_attempt() {  # ssh_attempt <identity args...>; returns the ssh exit status
  ssh -F /dev/null -T \
    -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
    -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
    -o PreferredAuthentications=publickey \
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=${KNOWN_HOSTS}" \
    -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 \
    -o ConnectTimeout=10 -o LogLevel=ERROR \
    -p "${VM_SSH_PORT}" "$@" -l "${SIM_USER}" "${VM_SSH_HOST}" true </dev/null >/dev/null 2>&1
}

sim_record "${SCENARIO}" started "${RUN_ID}"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sim_info "run ${RUN_ID}: ${ATTEMPTS} failed public-key logins as ${SIM_USER} -> ${VM_SSH_HOST}:${VM_SSH_PORT}"

failed=0
i=1
while [ "${i}" -le "${ATTEMPTS}" ]; do
  if ssh_attempt -i "${WORK_DIR}/key0"; then
    sim_record "${SCENARIO}" failed "${RUN_ID}"
    sim_die "attempt ${i} unexpectedly SUCCEEDED - the VM accepted an unknown user; investigate"
  fi
  failed=$((failed + 1))
  i=$((i + 1))
  sleep 0.3
done

sim_info "one more connection offering 4 throwaway keys (exceeds MaxAuthTries=3)"
if ssh_attempt -i "${WORK_DIR}/key1" -i "${WORK_DIR}/key2" -i "${WORK_DIR}/key3" -i "${WORK_DIR}/key4"; then
  sim_record "${SCENARIO}" failed "${RUN_ID}"
  sim_die "multi-key attempt unexpectedly SUCCEEDED; investigate"
fi
failed=$((failed + 1))

sim_record "${SCENARIO}" completed "${RUN_ID}"
cat <<EOF

VM-001 run ${RUN_ID}: ${failed} SSH connections, all rejected (started ${STARTED_AT}).

Expected genuine telemetry (asset ${ASSET_ID}, source linux.journald, service ssh, within one
collector interval, default 30 s). Every event carries simulation.run_id=${RUN_ID} because the
user name contains "extorq-sim-${RUN_ID}"; src_ip is 10.0.2.2 (QEMU SLIRP gateway):
  auth.ssh.invalid_user        x ${failed}   "Invalid user ${SIM_USER} from 10.0.2.2 port N" (one per connection)
  auth.ssh.preauth_closed      x ${ATTEMPTS}   "Connection closed by invalid user ${SIM_USER} 10.0.2.2 port N [preauth]"
  auth.ssh.max_auth_exceeded   x 2   "error: maximum authentication attempts exceeded for invalid user ..." and
                                     "Disconnecting invalid user ... Too many authentication failures [preauth]"
  (OpenSSH 9.6 writes no "Failed publickey" line for NON-EXISTENT users - verified on the lab VM -
   so auth.ssh.login_failed is not expected from this scenario; it appears for existing accounts.)
Expected detection: VM-001 (>= 5 distinct (src_ip, src_port) connections from 10.0.2.2 in 5 min).
Nothing to revert. Record cleanup with: $0 --cleanup --run-id ${RUN_ID}
EOF
sim_print_verify "${RUN_ID}"
