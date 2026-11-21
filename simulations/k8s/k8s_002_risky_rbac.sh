#!/usr/bin/env bash
# K8S-002 simulation: a ServiceAccount is bound to cluster-admin, then removed (owner B2).
#
#   simulations/k8s/k8s_002_risky_rbac.sh [--run-id ID] [--wait SECONDS] [--collect-once]
#   simulations/k8s/k8s_002_risky_rbac.sh --cleanup --run-id ID
#
# What it does (in the lab cluster only, reverted by the script itself):
#   1. kubectl create ServiceAccount extorq-apps/extorq-sim-<run_id>
#      (automountServiceAccountToken=false; no token Secret exists, so nobody can
#      authenticate as it unless they can already create tokens);
#   2. kubectl create ClusterRoleBinding extorq-sim-<run_id> -> ClusterRole cluster-admin
#      with that ServiceAccount as subject;
#   3. waits until the audit evidence AND the inventory evidence are in ClickHouse
#      (needs the inventory collector running: `uv run extorq-collect run`, or pass
#      --collect-once to run one inventory cycle from this script);
#   4. ALWAYS deletes both objects (EXIT/INT/TERM trap as well) and verifies they are gone.
#   Objects are touched only if their name is extorq-sim-<run_id> AND their label
#   extorq.io/simulation equals the run id.
#
# Genuine telemetry it produces:
#   k8s.api.request (k8s.audit)   create clusterrolebindings extorq-sim-<run_id> -> 201,
#       request_summary {role_ref: ClusterRole/cluster-admin, subjects: [...]},
#       risk_flags [cluster_admin], user kubernetes-admin; create serviceaccounts; deletes
#   k8s.resource.created (k8s.api_inventory) clusterrolebindings extorq-sim-<run_id>,
#       risk_flags [cluster_admin], baseline=false; later k8s.resource.deleted
#   all carry simulation.run_id=<run_id>  -> detection rule K8S-002 (high when both agree)
set -Eeuo pipefail
# shellcheck source=simulations/k8s/common.sh
. "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

SCENARIO="K8S-002"
NAMESPACE="extorq-apps"
RUN_ID=""
WAIT_SECONDS=240
CLEANUP_ONLY=0
COLLECT_ONCE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --run-id) RUN_ID="${2:-}"; shift 2 ;;
    --wait) WAIT_SECONDS="${2:-}"; shift 2 ;;
    --collect-once) COLLECT_ONCE=1; shift ;;
    --cleanup) CLEANUP_ONLY=1; shift ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) sim_die "unknown argument: $1" ;;
  esac
done
printf '%s' "${WAIT_SECONDS}" | grep -Eq '^[0-9]{1,4}$' || sim_die "--wait expects seconds"

sim_require_cluster

collect_once() {
  [ "${COLLECT_ONCE}" = "1" ] || return 0
  sim_info "running one inventory collector cycle (extorq-collect run --only k8s-inventory --once)"
  (cd "${REPO_ROOT}" && uv run --quiet extorq-collect run --only k8s-inventory --once) \
    || sim_warn "inventory cycle reported a problem (see output above)"
}

# delete_owned <kind> <name> [namespace]: delete only our labelled object; 0 when absent after.
delete_owned() {
  local kind="$1" name="$2" ns="${3:-}" label
  if ! sim_exists "${kind}" "${name}" ${ns:+"${ns}"}; then
    return 0
  fi
  label="$(sim_object_label "${kind}" "${name}" ${ns:+"${ns}"})"
  if [ "${label}" != "${RUN_ID}" ]; then
    sim_warn "${kind} ${name} exists but is not labelled extorq.io/simulation=${RUN_ID}; not deleting"
    return 1
  fi
  if [ -n "${ns}" ]; then
    kc -n "${ns}" delete "${kind}" "${name}" --wait=true >/dev/null
  else
    kc delete "${kind}" "${name}" --wait=true >/dev/null
  fi
  ! sim_exists "${kind}" "${name}" ${ns:+"${ns}"}
}

CLEANED=0
cleanup() {
  [ "${CLEANED}" = "1" ] && return 0
  CLEANED=1
  local ok=1
  delete_owned clusterrolebinding "${NAME}" || ok=0
  delete_owned serviceaccount "${NAME}" "${NAMESPACE}" || ok=0
  if [ "${ok}" = "1" ]; then
    sim_info "cleanup verified: clusterrolebinding/${NAME} and serviceaccount ${NAMESPACE}/${NAME} are gone"
    sim_record "${SCENARIO}" cleaned_up "${RUN_ID}"
  else
    sim_warn "CLEANUP INCOMPLETE for run ${RUN_ID}: re-run $0 --cleanup --run-id ${RUN_ID}"
    return 1
  fi
}

if [ "${CLEANUP_ONLY}" = "1" ]; then
  [ -n "${RUN_ID}" ] || sim_die "--cleanup needs --run-id"
  sim_validate_run_id "${RUN_ID}"
  NAME="extorq-sim-${RUN_ID}"
  cleanup || exit 1
  exit 0
fi

[ -n "${RUN_ID}" ] || RUN_ID="$(sim_new_run_id)"
sim_validate_run_id "${RUN_ID}"
NAME="extorq-sim-${RUN_ID}"
trap 'rc=$?; cleanup || rc=1; exit "${rc}"' EXIT
trap 'exit 130' INT TERM

sim_info "K8S-002 run ${RUN_ID}: bind ServiceAccount ${NAMESPACE}/${NAME} to cluster-admin"
sim_record "${SCENARIO}" started "${RUN_ID}" \
  "ClusterRoleBinding ${NAME} grants cluster-admin to ServiceAccount ${NAMESPACE}/${NAME}; removed after evidence" \
  "K8S-002"

kc create -f - >/dev/null <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${NAME}
  namespace: ${NAMESPACE}
  labels:
    extorq.io/simulation: "${RUN_ID}"
    extorq.io/scenario: k8s-002
automountServiceAccountToken: false
EOF
sim_info "created serviceaccount ${NAMESPACE}/${NAME}"

kc create -f - >/dev/null <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${NAME}
  labels:
    extorq.io/simulation: "${RUN_ID}"
    extorq.io/scenario: k8s-002
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: ${NAME}
    namespace: ${NAMESPACE}
EOF
sim_info "created clusterrolebinding/${NAME} -> ClusterRole cluster-admin"
sim_record "${SCENARIO}" completed "${RUN_ID}"

cat <<EOF

Expected genuine telemetry:
  k8s.audit         create serviceaccounts ${NAMESPACE}/${NAME}; create clusterrolebindings ${NAME}
                    -> 201, request_summary role_ref=ClusterRole/cluster-admin, risk_flags [cluster_admin]
  k8s.api_inventory k8s.resource.created clusterrolebindings ${NAME} (risk_flags [cluster_admin],
                    baseline=false) and serviceaccounts ${NAMESPACE}/${NAME}
  simulation.run_id=${RUN_ID} on all of them; detection rule K8S-002 (high when audit + state agree)
EOF

collect_once
evidence=0
if [ "${WAIT_SECONDS}" -gt 0 ]; then
  sim_info "waiting up to ${WAIT_SECONDS}s for audit + inventory evidence (read-only check)"
  sim_verify "${SCENARIO}" "${RUN_ID}" "${WAIT_SECONDS}" || evidence=1
fi

sim_info "cleanup (mandatory): deleting the binding and the service account"
cleanup || sim_die "cleanup failed"
trap - EXIT
collect_once
if [ "${evidence}" -ne 0 ]; then
  sim_die "expected evidence not found (is the inventory collector running? 'uv run extorq-collect status')"
fi
if [ "${WAIT_SECONDS}" -gt 0 ]; then
  sim_info "deletion evidence (audit now; inventory once the collector has run):"
  sim_verify "K8S-002-CLEANUP" "${RUN_ID}" 60 || sim_warn "deletion evidence not complete yet"
fi
