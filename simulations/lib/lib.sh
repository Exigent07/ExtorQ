# simulations/lib/lib.sh - bash helpers for ExtorQ scenario scripts (owner C2).
#
# Source it from a scenario script (compatible with the macOS system bash 3.2):
#   . "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/../lib/lib.sh"
#
#   run_id="$(extorq_sim_new_run_id)"          # 12 hex chars from the OS CSPRNG
#   marker="$(extorq_sim_marker "$run_id")"     # extorq-sim-<run_id>
#   extorq_sim_wait_alert VM-001 "$run_id" 600  # exit 0 when the alert exists, 1 on timeout
#   extorq_sim_verify "$run_id" --expect VM-001 # alert + evidence + source types
#
# All queries are read-only (ClickHouse user extorq_api_ro through the debug proxy
# 127.0.0.1:18123); the password is read from var/secrets by the Python helper, never
# passed on a command line. Function names are prefixed extorq_sim_ so they never
# collide with the area helpers (e.g. simulations/vm/common.sh).

EXTORQ_SIMLIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
EXTORQ_SIM_REPO_ROOT="$(cd -- "${EXTORQ_SIMLIB_DIR}/../.." && pwd -P)"

extorq_sim_py() {
  (cd "${EXTORQ_SIM_REPO_ROOT}" && uv run --quiet python "$@")
}

extorq_sim_new_run_id() {
  extorq_sim_py simulations/lib/simlib.py new-run-id
}

extorq_sim_marker() {
  [ $# -eq 1 ] || { printf 'usage: extorq_sim_marker RUN_ID\n' >&2; return 2; }
  extorq_sim_py simulations/lib/simlib.py marker "$1"
}

extorq_sim_wait_alert() {
  [ $# -ge 2 ] || { printf 'usage: extorq_sim_wait_alert RULE_ID RUN_ID [TIMEOUT_S]\n' >&2; return 2; }
  extorq_sim_py simulations/lib/simlib.py wait-alert --rule "$1" --run-id "$2" --timeout "${3:-600}"
}

extorq_sim_tagged() {
  [ $# -eq 1 ] || { printf 'usage: extorq_sim_tagged RUN_ID\n' >&2; return 2; }
  extorq_sim_py simulations/lib/simlib.py tagged --run-id "$1"
}

extorq_sim_verify() {
  [ $# -ge 1 ] || { printf 'usage: extorq_sim_verify RUN_ID [--expect RULE] [--wait S]\n' >&2; return 2; }
  extorq_sim_py simulations/lib/verify_scenario.py "$@"
}
