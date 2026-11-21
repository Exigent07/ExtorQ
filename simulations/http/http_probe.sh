#!/usr/bin/env bash
# HTTP-001 - web probing and failed application logins against the lab portal
# (ExtorQ lab simulation, owner B1).
#
# From the Mac, requests a list of probe-like paths on http://127.0.0.1:8088 (nginx -> lab-portal
# on the lab VM) and submits 5 bad logins to POST /login for the demo account "lab-admin" with
# random throwaway passwords (never the real credential, never printed). Every request carries a
# User-Agent containing "extorq-sim-<run_id>". Nothing is changed on the VM.
#
# Usage: simulations/http/http_probe.sh [--run-id ID] [--cleanup --run-id ID]
# Environment: EXTORQ_SIM_RECORD=0 skips SimulationRun recording.
set -Eeuo pipefail
umask 077

# shellcheck source=simulations/vm/common.sh
. "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/../vm/common.sh"

SCENARIO="HTTP-001"
RUN_ID=""
CLEANUP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --run-id) [ $# -ge 2 ] || sim_die "--run-id needs a value"; RUN_ID="$2"; shift 2 ;;
    --cleanup) CLEANUP=1; shift ;;
    -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) sim_die "unknown argument: $1" ;;
  esac
done

if [ "${CLEANUP}" -eq 1 ]; then
  [ -n "${RUN_ID}" ] || sim_die "--cleanup requires --run-id"
  sim_validate_run_id "${RUN_ID}"
  sim_info "HTTP-001 changes nothing on the VM; nothing to revert"
  sim_record "${SCENARIO}" cleaned_up "${RUN_ID}"
  exit 0
fi

[ -n "${RUN_ID}" ] || RUN_ID="$(sim_new_run_id)"
sim_validate_run_id "${RUN_ID}"
command -v curl >/dev/null || sim_die "curl not found"
BASE="http://127.0.0.1:${VM_HTTP_PORT}"
curl -s -o /dev/null --max-time 5 "${BASE}/healthz" || sim_die "lab portal ${BASE} not reachable: infra/vm/vm.sh up"

UA="Mozilla/5.0 (compatible; extorq-sim-${RUN_ID}; ExtorQ HTTP probe simulation)"
PROBE_PATHS="/.env /.git/config /wp-login.php /phpmyadmin/ /server-status /admin"

sim_record "${SCENARIO}" started "${RUN_ID}"
sim_info "run ${RUN_ID}: probing ${BASE} with User-Agent containing extorq-sim-${RUN_ID}"
for path in ${PROBE_PATHS}; do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -A "${UA}" "${BASE}${path}" || echo 000)"
  printf '    GET  %-16s -> %s\n' "${path}" "${code}"
  sleep 0.2
done

for n in 1 2 3 4 5; do
  # Random throwaway password (36 hex chars): never printed, never the real credential.
  guess="$(sim_random_secret)"
  code="$(printf 'username=lab-admin&password=%s' "${guess}" | curl -s -o /dev/null -w '%{http_code}' \
    --max-time 5 -A "${UA}" -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-binary @- "${BASE}/login" || echo 000)"
  guess=""
  printf '    POST %-16s -> %s (bad login %d/5)\n' "/login" "${code}" "${n}"
  sleep 0.2
done
sim_record "${SCENARIO}" completed "${RUN_ID}"

cat <<EOF

HTTP-001 run ${RUN_ID}: 6 probe requests and 5 failed logins sent.

Expected genuine telemetry (asset ${ASSET_ID}; simulation.run_id=${RUN_ID} from the User-Agent;
src_ip 10.0.2.2 = QEMU SLIRP gateway as seen by nginx; nginx \$request_id propagates to the app):
  http.request (linux.nginx, service nginx)            x 11  routes /.env /.git/config /wp-login.php
                                                       /phpmyadmin/ /server-status /admin /login
  app.authz.denied (linux.app, service lab-portal)     x 1   route /admin, reason missing_session
  app.auth.login_failed (linux.app, service lab-portal) x 5  user lab-admin, reason invalid_password,
                                                       http.request_id equal to the nginx line's id
No mandatory detection; this is the first step of the CORR-002 sequence
(HTTP probing -> SSH authentication failures -> unexpected systemd change on one host).
EOF
sim_print_verify "${RUN_ID}"
