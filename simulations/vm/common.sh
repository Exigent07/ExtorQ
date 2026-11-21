# simulations/vm/common.sh - shared helpers for the ExtorQ VM and HTTP simulations (owner B1).
# Sourced by simulations/vm/*.sh and simulations/http/*.sh; never executed directly.
#
# Every simulation:
#   * generates a run id (8-32 lower-case alphanumerics) or accepts --run-id,
#   * records the SimulationRun through A's CLI
#       uv run extorq-collect sim-record --scenario <ID> --asset linux:lab-vm-01 \
#            --status started|completed|failed|cleaned_up --run-id <id>
#     (when the CLI is not installed yet the run is NOT recorded and this is said),
#   * performs one safe, reversible action against the lab VM only,
#   * prints the genuine telemetry it expects and how to verify it.
# Compatible with the macOS system bash (3.2).

SIM_COMMON_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SIM_COMMON_DIR}/../.." && pwd -P)"
VM_DIR="${EXTORQ_VM_DIR:-${REPO_ROOT}/var/vm}"
ASSET_ID="linux:lab-vm-01"
VM_SSH_HOST="127.0.0.1"
VM_SSH_PORT="${EXTORQ_VM_SSH_PORT:-2222}"
VM_HTTP_PORT="${EXTORQ_VM_HTTP_PORT:-8088}"
KNOWN_HOSTS="${VM_DIR}/known_hosts"
RECORD_SIMULATION="${EXTORQ_SIM_RECORD:-1}"

sim_info() { printf '==> %s\n' "$*"; }
sim_warn() { printf 'warning: %s\n' "$*" >&2; }
sim_die() { printf 'error: %s\n' "$*" >&2; exit 1; }

sim_new_run_id() {
  # 12 lower-case hex characters from the kernel CSPRNG (od reads exactly 6 bytes, so the
  # pipeline cannot die of SIGPIPE under `set -o pipefail`).
  od -An -N6 -tx1 /dev/urandom | tr -d ' \n'
}

sim_random_secret() {  # throwaway random string (hex), never a real credential
  od -An -N18 -tx1 /dev/urandom | tr -d ' \n'
}

sim_validate_run_id() {
  printf '%s' "$1" | grep -Eq '^[a-z0-9]{8,32}$' || sim_die "invalid run id '$1' (8-32 lower-case alphanumerics)"
}

sim_require_vm() {
  [ -f "${KNOWN_HOSTS}" ] || sim_die "lab VM not created (${KNOWN_HOSTS} missing): run infra/vm/vm.sh up"
  nc -z -w 3 "${VM_SSH_HOST}" "${VM_SSH_PORT}" >/dev/null 2>&1 \
    || sim_die "lab VM SSH ${VM_SSH_HOST}:${VM_SSH_PORT} not reachable: run infra/vm/vm.sh up"
}

# sim_record <scenario> <status> <run_id>
sim_record() {
  local scenario="$1" status="$2" run_id="$3"
  if [ "${RECORD_SIMULATION}" != "1" ]; then
    sim_info "SimulationRun not recorded (EXTORQ_SIM_RECORD=${RECORD_SIMULATION}): ${scenario} ${status} ${run_id}"
    return 0
  fi
  if ! (cd "${REPO_ROOT}" && uv run --quiet extorq-collect sim-record --help >/dev/null 2>&1); then
    sim_warn "'extorq-collect sim-record' is not available yet (collector SDK CLI, owner A):"
    sim_warn "SimulationRun ${scenario}/${run_id} status=${status} was NOT recorded"
    return 0
  fi
  if (cd "${REPO_ROOT}" && uv run --quiet extorq-collect sim-record \
      --scenario "${scenario}" --asset "${ASSET_ID}" --status "${status}" --run-id "${run_id}"); then
    sim_info "SimulationRun ${scenario}/${run_id} recorded: ${status}"
  else
    sim_warn "recording SimulationRun ${scenario}/${run_id} status=${status} failed (gateway down?)"
  fi
}

sim_print_verify() {  # sim_print_verify <run_id>
  cat <<EOF

Verify (ClickHouse via the debug proxy, read-only user extorq_api_ro; no password on the
command line - the helper reads var/secrets/clickhouse/extorq_api_ro_password itself):
  uv run python -m extorq_collectors.linux.verify --run-id $1
  uv run python -m extorq_collectors.linux.verify --asset ${ASSET_ID} --since-minutes 30
EOF
}
