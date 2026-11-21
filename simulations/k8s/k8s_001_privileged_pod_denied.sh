#!/usr/bin/env bash
# K8S-001 simulation: a privileged, host-PID pod is DENIED by Pod Security admission (owner B2).
#
#   simulations/k8s/k8s_001_privileged_pod_denied.sh [--run-id ID] [--wait SECONDS | --no-wait]
#   simulations/k8s/k8s_001_privileged_pod_denied.sh --cleanup --run-id ID
#
# What it does (safe and reversible):
#   kubectl create (as the lab admin) of Pod extorq-sim-<run_id> in namespace
#   extorq-restricted with securityContext.privileged=true and hostPID=true. The namespace
#   enforces Pod Security "baseline", so the API server answers HTTP 403 and NO pod is
#   created. Nothing runs, nothing needs undoing; --cleanup only double-checks that no such
#   pod exists (and deletes it if the admission control had failed open).
#
# Genuine telemetry it produces (kube-apiserver audit log -> OTel -> gateway -> ClickHouse):
#   k8s.api.request  verb=create resource=pods namespace=extorq-restricted
#                    object_name=extorq-sim-<run_id> response_code=403 outcome=denied
#                    attributes.pod_security_violation  ("violates PodSecurity baseline:latest")
#                    attributes.request_summary         {"host_pid":true,"privileged":[...]}
#                    attributes.risk_flags              [host_pid, privileged]
#                    simulation.run_id = <run_id>
#   -> detection rule K8S-001 (one alert per audit id).
set -Eeuo pipefail
# shellcheck source=simulations/k8s/common.sh
. "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

SCENARIO="K8S-001"
NAMESPACE="extorq-restricted"
RUN_ID=""
WAIT_SECONDS=180
CLEANUP=0

while [ $# -gt 0 ]; do
  case "$1" in
    --run-id) RUN_ID="${2:-}"; shift 2 ;;
    --wait) WAIT_SECONDS="${2:-}"; shift 2 ;;
    --no-wait) WAIT_SECONDS=0; shift ;;
    --cleanup) CLEANUP=1; shift ;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) sim_die "unknown argument: $1" ;;
  esac
done
printf '%s' "${WAIT_SECONDS}" | grep -Eq '^[0-9]{1,4}$' || sim_die "--wait expects seconds"

sim_require_cluster

if [ "${CLEANUP}" = "1" ]; then
  [ -n "${RUN_ID}" ] || sim_die "--cleanup needs --run-id"
  sim_validate_run_id "${RUN_ID}"
  NAME="extorq-sim-${RUN_ID}"
  if sim_exists pod "${NAME}" "${NAMESPACE}"; then
    [ "$(sim_object_label pod "${NAME}" "${NAMESPACE}")" = "${RUN_ID}" ] \
      || sim_die "pod ${NAMESPACE}/${NAME} exists but is not labelled for run ${RUN_ID}; not touching it"
    sim_warn "pod ${NAMESPACE}/${NAME} EXISTS (admission did not deny it): deleting"
    kc -n "${NAMESPACE}" delete pod "${NAME}" --wait=true >/dev/null
  fi
  sim_exists pod "${NAME}" "${NAMESPACE}" && sim_die "pod ${NAMESPACE}/${NAME} still present"
  sim_info "verified: no pod ${NAMESPACE}/${NAME} exists"
  sim_record "${SCENARIO}" cleaned_up "${RUN_ID}"
  exit 0
fi

[ -n "${RUN_ID}" ] || RUN_ID="$(sim_new_run_id)"
sim_validate_run_id "${RUN_ID}"
NAME="extorq-sim-${RUN_ID}"
sim_info "K8S-001 run ${RUN_ID}: create privileged hostPID pod ${NAMESPACE}/${NAME} (expect HTTP 403)"
sim_record "${SCENARIO}" started "${RUN_ID}" \
  "Privileged + hostPID pod ${NAME} submitted to ${NAMESPACE} (PSA baseline enforce); expected 403 denial" \
  "K8S-001"

manifest="$(cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${NAME}
  namespace: ${NAMESPACE}
  labels:
    extorq.io/simulation: "${RUN_ID}"
    extorq.io/scenario: k8s-001
spec:
  hostPID: true
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
    - name: sim
      image: ${SIM_IMAGE}
      command: ["sleep", "30"]
      securityContext:
        privileged: true
EOF
)"

rc=0
output="$(printf '%s\n' "${manifest}" | kc create -f - 2>&1)" || rc=$?
# kubectl's message is printed sanitised (first 3 lines, no control characters).
printf '%s\n' "${output}" | head -n 3 | LC_ALL=C tr -cd '[:print:]\n' | sed 's/^/    kubectl: /'

if [ "${rc}" -eq 0 ]; then
  sim_warn "the API server ACCEPTED the privileged pod: Pod Security enforcement is not working"
  kc -n "${NAMESPACE}" delete pod "${NAME}" --wait=true >/dev/null 2>&1 || true
  sim_record "${SCENARIO}" failed "${RUN_ID}" "" "" "pod was admitted; deleted immediately"
  exit 1
fi
if ! printf '%s' "${output}" | grep -q 'violates PodSecurity'; then
  sim_record "${SCENARIO}" failed "${RUN_ID}" "" "" "create failed without a PodSecurity denial"
  sim_die "create failed for another reason (see kubectl output above)"
fi
if sim_exists pod "${NAME}" "${NAMESPACE}"; then
  sim_die "pod ${NAMESPACE}/${NAME} exists despite the denial"
fi
sim_info "denied by Pod Security admission (HTTP 403); verified no pod ${NAMESPACE}/${NAME} exists"
sim_record "${SCENARIO}" completed "${RUN_ID}"

cat <<EOF

Expected genuine telemetry (kube-apiserver audit -> OTel DaemonSet -> gateway -> ClickHouse):
  k8s.api.request create pods ${NAMESPACE}/${NAME} -> 403 (denied_by=pod_security),
  attributes.pod_security_violation, request_summary {host_pid, privileged}, risk_flags
  [host_pid, privileged], simulation.run_id=${RUN_ID}; detection rule K8S-001.
EOF

if [ "${WAIT_SECONDS}" -gt 0 ]; then
  sim_info "waiting up to ${WAIT_SECONDS}s for the evidence in ClickHouse (read-only check)"
  sim_verify "${SCENARIO}" "${RUN_ID}" "${WAIT_SECONDS}" \
    || sim_die "expected telemetry not found (is the OTel DaemonSet running? infra/kind/kind.sh status)"
fi
sim_info "nothing to clean up (no object was created); optional check: $0 --cleanup --run-id ${RUN_ID}"
