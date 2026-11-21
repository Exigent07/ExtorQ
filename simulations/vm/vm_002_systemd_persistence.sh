#!/usr/bin/env bash
# VM-002 - systemd persistence on the lab VM (ExtorQ lab simulation, owner B1).
#
# As the lab operator extorq-admin (sudo), creates
#   /etc/systemd/system/extorq-sim-<run_id>.service   (Type=oneshot, ExecStart=/bin/true)
# runs `systemctl daemon-reload` and `systemctl enable` on it. The unit is NOT started; even
# if it ran (next boot) it only executes /bin/true. Cleanup disables and removes the unit and
# reloads systemd.
#
# Usage: simulations/vm/vm_002_systemd_persistence.sh [--run-id ID]
#        simulations/vm/vm_002_systemd_persistence.sh --cleanup --run-id ID
# Environment: EXTORQ_SIM_RECORD=0 skips SimulationRun recording.
set -Eeuo pipefail
umask 077

# shellcheck source=simulations/vm/common.sh
. "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

SCENARIO="VM-002"
RUN_ID=""
CLEANUP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --run-id) [ $# -ge 2 ] || sim_die "--run-id needs a value"; RUN_ID="$2"; shift 2 ;;
    --cleanup) CLEANUP=1; shift ;;
    -h|--help) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) sim_die "unknown argument: $1" ;;
  esac
done

if [ "${CLEANUP}" -eq 1 ] && [ -z "${RUN_ID}" ]; then
  sim_die "--cleanup requires --run-id"
fi
[ -n "${RUN_ID}" ] || RUN_ID="$(sim_new_run_id)"
sim_validate_run_id "${RUN_ID}"
sim_require_vm
[ -f "${VM_DIR}/keys/extorq-admin" ] || sim_die "operator key missing: run infra/vm/vm.sh create"

UNIT="extorq-sim-${RUN_ID}.service"

# The remote script is fixed text; its only input is the unit name, passed as an argument
# and re-validated on the VM. It runs as root through sudo (operator account).
REMOTE_SCRIPT='set -eu
action="$1"; unit="$2"
case "$unit" in
  extorq-sim-*.service) ;;
  *) echo "refusing unit name" >&2; exit 2 ;;
esac
run_id="${unit#extorq-sim-}"; run_id="${run_id%.service}"
case "$run_id" in ""|*[!a-z0-9]*) echo "invalid run id" >&2; exit 2 ;; esac
path="/etc/systemd/system/${unit}"
if [ "$action" = create ]; then
  if [ -e "$path" ]; then echo "unit already exists: $path" >&2; exit 3; fi
  umask 022
  cat >"$path" <<EOF
[Unit]
Description=ExtorQ simulation VM-002 run ${run_id} (harmless persistence marker)

[Service]
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$unit"
  printf "created %s, enabled=%s, active=%s\n" "$path" "$(systemctl is-enabled "$unit")" \
    "$(systemctl is-active "$unit" || true)"
else
  systemctl disable "$unit" 2>/dev/null || true
  rm -f "$path"
  systemctl daemon-reload
  printf "removed %s (exists now: %s)\n" "$path" "$( [ -e "$path" ] && echo yes || echo no)"
fi'

run_remote() {  # run_remote create|cleanup
  printf '%s\n' "${REMOTE_SCRIPT}" | ssh -F /dev/null -T -i "${VM_DIR}/keys/extorq-admin" \
    -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=${KNOWN_HOSTS}" \
    -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 \
    -o ConnectTimeout=10 -o LogLevel=ERROR -p "${VM_SSH_PORT}" \
    "extorq-admin@${VM_SSH_HOST}" sudo /bin/sh -s -- "$1" "${UNIT}"
}

if [ "${CLEANUP}" -eq 1 ]; then
  sim_info "VM-002 cleanup: disabling and removing ${UNIT}"
  run_remote cleanup
  sim_record "${SCENARIO}" cleaned_up "${RUN_ID}"
  cat <<EOF

Expected genuine telemetry for the cleanup (asset ${ASSET_ID}):
  persistence.systemd.unit_deleted (linux.inventory) resource.name=${UNIT}
  service.removed (linux.inventory) for ${UNIT}
  file.audit.watch key=extorq_systemd (linux.auditd): unlink of the unit file by rm (the wants/ symlink
                                         is removed by PID 1, not audited - see above)
  system.systemd.daemon_reload (linux.journald), auth.sudo.command (linux.journald)
EOF
  sim_print_verify "${RUN_ID}"
  exit 0
fi

sim_record "${SCENARIO}" started "${RUN_ID}"
sim_info "run ${RUN_ID}: creating and enabling /etc/systemd/system/${UNIT} on the lab VM"
if ! run_remote create; then
  sim_record "${SCENARIO}" failed "${RUN_ID}"
  sim_die "remote action failed"
fi
sim_record "${SCENARIO}" completed "${RUN_ID}"

cat <<EOF

VM-002 run ${RUN_ID}: ${UNIT} created and enabled (not started; ExecStart=/bin/true).

Expected genuine telemetry (asset ${ASSET_ID}; every record carries simulation.run_id=${RUN_ID}
because the unit name contains "extorq-sim-${RUN_ID}"):
  file.audit.watch key=extorq_systemd (linux.auditd)  unit file written by /bin/sh (auid extorq-admin
                                                       via sudo). The wants/ symlink is created by PID 1
                                                       over D-Bus; PID 1 started before auditd, so it has
                                                       no audit context (no audit=1 at boot): the
                                                       inventory diff below is the evidence for it.
  process.audit.exec key=extorq_root_exec (linux.auditd) systemctl daemon-reload / enable as root
  auth.sudo.command (linux.journald)                  COMMAND=/bin/sh -s -- create ${UNIT}
  system.systemd.daemon_reload (linux.journald, service systemd)
  persistence.systemd.unit_created (linux.inventory)  resource.path=/etc/systemd/system/${UNIT}
                                                       attributes.sha256, exec_start=/bin/true
  persistence.systemd.unit_enabled (linux.inventory)  wanted_by=multi-user.target
  service.discovered (linux.inventory)                ${UNIT}: no adapter, unmonitored, not running
Inventory diffs appear within one inventory interval (default 60 s).
Expected detection: VM-002 (unit not in allowlist; high confidence when inventory and auditd agree).
Revert with: $0 --cleanup --run-id ${RUN_ID}
EOF
sim_print_verify "${RUN_ID}"
