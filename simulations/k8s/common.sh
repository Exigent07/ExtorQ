# simulations/k8s/common.sh - shared helpers for the ExtorQ Kubernetes simulations (owner B2).
# Sourced by simulations/k8s/*.sh; never executed directly. Compatible with macOS bash 3.2.
#
# Every simulation:
#   * targets ONLY the ExtorQ lab cluster: kubectl always gets
#     --kubeconfig var/kube/extorq-lab-admin.kubeconfig --context kind-extorq-lab
#     (never ~/.kube/config, never another cluster such as motorq-security);
#   * generates a run id (8-32 lower-case alphanumerics) or accepts --run-id, and names
#     every object it creates extorq-sim-<run_id> (label extorq.io/simulation=<run_id>),
#     so the telemetry carries the simulation marker (event.simulation);
#   * records the SimulationRun with A's CLI
#       uv run extorq-collect sim-record --scenario <ID> --asset k8s:extorq-lab \
#            --status started|completed|failed|cleaned_up --run-id <id>;
#   * prints the genuine telemetry it expects and checks it read-only in ClickHouse with
#       uv run python -m extorq_collectors.kubernetes.verify --scenario <ID> --run-id <id>.

SIM_K8S_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SIM_K8S_DIR}/../.." && pwd -P)"
ASSET_ID="k8s:extorq-lab"
CLUSTER_NAME="extorq-lab"
KUBE_CONTEXT="kind-extorq-lab"
ADMIN_KUBECONFIG="${REPO_ROOT}/var/kube/extorq-lab-admin.kubeconfig"
RECORD_SIMULATION="${EXTORQ_SIM_RECORD:-1}"
# Pinned image already present on the node (used only in manifests that admission denies
# or that never run a workload).
SIM_IMAGE="alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"

sim_info() { printf '==> %s\n' "$*"; }
sim_warn() { printf 'warning: %s\n' "$*" >&2; }
sim_die() { printf 'error: %s\n' "$*" >&2; exit 1; }

sim_new_run_id() {
  # 12 lower-case hex characters from the kernel CSPRNG (od reads exactly 6 bytes, so the
  # pipeline cannot die of SIGPIPE under `set -o pipefail`).
  od -An -N6 -tx1 /dev/urandom | tr -d ' \n'
}

sim_validate_run_id() {
  printf '%s' "$1" | grep -Eq '^[a-z0-9]{8,32}$' \
    || sim_die "invalid run id '$1' (8-32 lower-case alphanumerics)"
}

kc() { kubectl --kubeconfig "${ADMIN_KUBECONFIG}" --context "${KUBE_CONTEXT}" --request-timeout=20s "$@"; }

sim_require_cluster() {
  command -v kubectl >/dev/null 2>&1 || sim_die "kubectl not found"
  command -v kind >/dev/null 2>&1 || sim_die "kind not found"
  kind get clusters 2>/dev/null | grep -x "${CLUSTER_NAME}" >/dev/null \
    || sim_die "kind cluster ${CLUSTER_NAME} not found: run infra/kind/kind.sh up"
  [ -s "${ADMIN_KUBECONFIG}" ] || sim_die "missing ${ADMIN_KUBECONFIG}: run infra/kind/kind.sh status"
  kc get --raw /readyz >/dev/null 2>&1 || sim_die "API server of ${CLUSTER_NAME} is not ready"
}

# sim_record <scenario> <status> <run_id> [description] [expected_rules] [note]
sim_record() {
  local scenario="$1" status="$2" run_id="$3" description="${4:-}" rules="${5:-}" note="${6:-}"
  if [ "${RECORD_SIMULATION}" != "1" ]; then
    sim_info "SimulationRun not recorded (EXTORQ_SIM_RECORD=${RECORD_SIMULATION}): ${scenario} ${status} ${run_id}"
    return 0
  fi
  set -- --scenario "${scenario}" --asset "${ASSET_ID}" --status "${status}" --run-id "${run_id}"
  [ -n "${description}" ] && set -- "$@" --description "${description}"
  [ -n "${rules}" ] && set -- "$@" --expected-rules "${rules}"
  [ -n "${note}" ] && set -- "$@" --note "${note}"
  local rc=0
  (cd "${REPO_ROOT}" && uv run --quiet extorq-collect sim-record "$@") || rc=$?
  case "${rc}" in
    0) sim_info "SimulationRun ${scenario}/${run_id} recorded: ${status}" ;;
    75) sim_warn "SimulationRun ${scenario}/${run_id} ${status} committed locally, not yet delivered (gateway down?); 'uv run extorq-collect flush' retries" ;;
    *) sim_warn "recording SimulationRun ${scenario}/${run_id} status=${status} failed (exit ${rc})" ;;
  esac
}

# sim_verify <scenario> <run_id> <wait_seconds>: read-only evidence check; returns its exit code.
sim_verify() {
  (cd "${REPO_ROOT}" && uv run --quiet python -m extorq_collectors.kubernetes.verify \
    --scenario "$1" --run-id "$2" --wait "$3")
}

# sim_object_label <kind> <name> [namespace]: value of label extorq.io/simulation ('' if absent)
sim_object_label() {
  local kind="$1" name="$2" ns="${3:-}"
  if [ -n "${ns}" ]; then
    kc -n "${ns}" get "${kind}" "${name}" --ignore-not-found \
      -o jsonpath='{.metadata.labels.extorq\.io/simulation}' 2>/dev/null || true
  else
    kc get "${kind}" "${name}" --ignore-not-found \
      -o jsonpath='{.metadata.labels.extorq\.io/simulation}' 2>/dev/null || true
  fi
}

# sim_exists <kind> <name> [namespace]: 0 if the object exists
sim_exists() {
  local kind="$1" name="$2" ns="${3:-}" out
  if [ -n "${ns}" ]; then
    out="$(kc -n "${ns}" get "${kind}" "${name}" --ignore-not-found -o name 2>/dev/null)" || return 2
  else
    out="$(kc get "${kind}" "${name}" --ignore-not-found -o name 2>/dev/null)" || return 2
  fi
  [ -n "${out}" ]
}
