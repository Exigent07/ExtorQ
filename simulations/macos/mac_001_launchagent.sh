#!/usr/bin/env bash
# MAC-001 - LaunchAgent persistence on the macOS host (ExtorQ lab simulation, owner B3).
#
# Creates ~/Library/LaunchAgents/com.extorq.sim.<run_id>.plist (Label
# com.extorq.sim.<run_id>, ProgramArguments [/usr/bin/true], RunAtLoad false), waits until
# the macOS collector has stored persistence.launchd.item_created, then ALWAYS removes the
# file again and waits for persistence.launchd.item_deleted. Removal is guaranteed by an
# EXIT trap: it also runs on errors, Ctrl-C (INT), TERM and HUP. Only SIGKILL or a power
# loss can leave the file behind; --cleanup --run-id ID removes such a leftover.
# The job is NEVER loaded (this script never runs launchctl); even if it were loaded it
# would only execute /usr/bin/true. macOS may show a "Background Items Added"
# notification for the new file: that is expected.
#
# Usage: simulations/macos/mac_001_launchagent.sh [--run-id ID] [--wait SECONDS]
#        simulations/macos/mac_001_launchagent.sh [--run-id ID] --no-wait [--hold SECONDS]
#        simulations/macos/mac_001_launchagent.sh --cleanup --run-id ID [--wait SECONDS|--no-wait]
#   --wait S    wait up to S seconds (default 240) for each expected event in ClickHouse
#   --no-wait   do not query ClickHouse; keep the file --hold seconds (default 90: the
#               launchd source scans every 60 s) so the collector can observe it
# The macOS collector must be running to observe the change:
#        uv run extorq-collect run --only macos-workstation-01
# Environment: EXTORQ_SIM_RECORD=0 skips SimulationRun recording.
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
SCENARIO="MAC-001"
ASSET_ID="macos:workstation-01"
RECORD_SIMULATION="${EXTORQ_SIM_RECORD:-1}"
RUN_ID=""
CLEANUP=0
WAIT_SECONDS=240
HOLD_SECONDS=90

# Exit-trap state: the plist is removed on exit while CREATED=1 and CLEANED=0.
CREATED=0
CLEANED=0
REMOVED=0
TMP=""
CHILD=""

info() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --run-id) [ $# -ge 2 ] || die "--run-id needs a value"; RUN_ID="$2"; shift 2 ;;
    --cleanup) CLEANUP=1; shift ;;
    --wait) [ $# -ge 2 ] || die "--wait needs seconds"; WAIT_SECONDS="$2"; shift 2 ;;
    --no-wait) WAIT_SECONDS=0; shift ;;
    --hold) [ $# -ge 2 ] || die "--hold needs seconds"; HOLD_SECONDS="$2"; shift 2 ;;
    -h|--help) sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ "$(uname -s)" = "Darwin" ] || die "MAC-001 runs on the macOS host only"
printf '%s' "${WAIT_SECONDS}" | grep -Eq '^[0-9]{1,4}$' || die "--wait must be 0-9999 seconds"
printf '%s' "${HOLD_SECONDS}" | grep -Eq '^[0-9]{1,4}$' || die "--hold must be 0-9999 seconds"
if [ "${CLEANUP}" -eq 1 ] && [ -z "${RUN_ID}" ]; then
  die "--cleanup requires --run-id"
fi
if [ -z "${RUN_ID}" ]; then
  # 12 lower-case hex characters from the kernel CSPRNG.
  RUN_ID="$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
fi
printf '%s' "${RUN_ID}" | grep -Eq '^[a-z0-9]{8,32}$' \
  || die "invalid run id '${RUN_ID}' (8-32 lower-case alphanumerics)"

AGENTS_DIR="${HOME}/Library/LaunchAgents"
LABEL="com.extorq.sim.${RUN_ID}"
PLIST="${AGENTS_DIR}/${LABEL}.plist"

record() {  # record <status>
  local status="$1"
  if [ "${RECORD_SIMULATION}" != "1" ]; then
    info "SimulationRun not recorded (EXTORQ_SIM_RECORD=${RECORD_SIMULATION}): ${SCENARIO} ${status}"
    return 0
  fi
  if (cd "${REPO_ROOT}" && uv run --quiet extorq-collect sim-record \
      --scenario "${SCENARIO}" --asset "${ASSET_ID}" --status "${status}" --run-id "${RUN_ID}" \
      --description "LaunchAgent plist ${LABEL} created in ~/Library/LaunchAgents (never loaded; /usr/bin/true, RunAtLoad false)" \
      --note "expected telemetry: persistence.launchd.item_created then item_deleted (macos.launchd)"); then
    info "SimulationRun ${SCENARIO}/${RUN_ID} recorded: ${status}"
  else
    warn "recording SimulationRun ${SCENARIO}/${RUN_ID} status=${status} did not reach the gateway (kept buffered or failed)"
  fi
}

wait_child() {  # wait for $CHILD; signals interrupt the wait so the traps run promptly
  local rc=0
  wait "${CHILD}" || rc=$?
  CHILD=""
  return "${rc}"
}

wait_for() {  # wait_for <event_type> <since-iso>
  if [ "${WAIT_SECONDS}" -eq 0 ]; then
    info "not waiting for $1 (--no-wait)"
    return 0
  fi
  info "waiting up to ${WAIT_SECONDS}s for $1 from the macOS collector"
  (cd "${REPO_ROOT}" && exec uv run --quiet python simulations/macos/wait_event.py \
     --event-type "$1" --path "${PLIST}" --since "$2" --timeout "${WAIT_SECONDS}") &
  CHILD=$!
  wait_child
}

hold() {  # keep the file long enough for at least one launchd scan (--no-wait mode)
  info "keeping ${PLIST} for ${HOLD_SECONDS}s (--no-wait) so the collector can observe it"
  sleep "${HOLD_SECONDS}" &
  CHILD=$!
  wait_child
}

remove_plist() {  # remove this run's plist (only the regular file carrying LABEL) and verify
  if [ -L "${PLIST}" ]; then
    warn "${PLIST} is a symbolic link: not created by this scenario, refusing to delete"
    return 1
  fi
  if [ -e "${PLIST}" ]; then
    if [ ! -f "${PLIST}" ]; then
      warn "${PLIST} is not a regular file: refusing to delete"
      return 1
    fi
    if ! /usr/bin/plutil -extract Label raw -o - "${PLIST}" 2>/dev/null | grep -qx "${LABEL}"; then
      warn "${PLIST} does not carry Label ${LABEL}: refusing to delete"
      return 1
    fi
    rm -f -- "${PLIST}"
    REMOVED=1
    info "removed ${PLIST}"
  else
    info "${PLIST} is already absent"
  fi
  if [ -e "${PLIST}" ] || [ -L "${PLIST}" ]; then
    warn "cleanup failed: ${PLIST} still exists"
    return 1
  fi
  info "verified: ${PLIST} no longer exists"
  return 0
}

on_exit() {
  local status=$?
  trap - EXIT INT TERM HUP
  if [ -n "${CHILD}" ]; then
    kill "${CHILD}" 2>/dev/null || true
  fi
  if [ -n "${TMP}" ]; then
    rm -f -- "${TMP}"
  fi
  if [ "${CREATED}" -eq 1 ] && [ "${CLEANED}" -eq 0 ]; then
    warn "exiting before the scenario finished (status ${status}): removing ${PLIST}"
    if remove_plist; then
      CLEANED=1
      if [ "${REMOVED}" -eq 1 ]; then
        record cleaned_up
      fi
    else
      warn "automatic cleanup failed: run $0 --cleanup --run-id ${RUN_ID}"
      [ "${status}" -ne 0 ] || status=1
    fi
  fi
  exit "${status}"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if [ "${CLEANUP}" -eq 1 ]; then
  # Manual cleanup of a leftover from an interrupted run (e.g. SIGKILL).
  SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [ -e "${PLIST}" ] || [ -L "${PLIST}" ]; then
    remove_plist || die "cleanup refused or failed for ${PLIST}"
    record cleaned_up
    wait_for persistence.launchd.item_deleted "${SINCE}" || warn "item_deleted not observed yet"
  else
    remove_plist  # reports and verifies absence
    # Nothing was removed now, so no SimulationRun update (that would overwrite the real
    # cleanup time). Show the deletion the collector stored earlier, whenever it was.
    info "nothing to remove; looking for the earlier persistence.launchd.item_deleted"
    wait_for persistence.launchd.item_deleted "1970-01-01T00:00:00Z" \
      || warn "no item_deleted stored for ${PLIST} (was the collector running when it was removed?)"
  fi
  exit 0
fi

[ -d "${AGENTS_DIR}" ] || die "${AGENTS_DIR} does not exist"
[ ! -L "${AGENTS_DIR}" ] || die "${AGENTS_DIR} is a symbolic link: refusing to write"
if [ -e "${PLIST}" ] || [ -L "${PLIST}" ]; then
  die "${PLIST} already exists"
fi

SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
record started
TMP="$(mktemp "${AGENTS_DIR}/.extorq-sim.XXXXXX")"
cat >"${TMP}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>${LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/bin/true</string>
	</array>
	<key>RunAtLoad</key>
	<false/>
</dict>
</plist>
EOF
if ! /usr/bin/plutil -lint -s "${TMP}"; then
  record failed
  die "generated plist failed plutil -lint"
fi
chmod 0644 "${TMP}"
CREATED=1  # from here on the EXIT trap removes the plist
mv -- "${TMP}" "${PLIST}"
TMP=""
info "created ${PLIST} (not loaded; ProgramArguments=/usr/bin/true, RunAtLoad=false)"
record completed

cat <<EOF

MAC-001 run ${RUN_ID}: expected genuine telemetry on ${ASSET_ID} (macos.launchd, within one
launchd interval, 60 s by default):
  persistence.launchd.item_created  resource.path=${PLIST}
    attributes: label=${LABEL}, program=/usr/bin/true, run_at_load=false, scope=user, sha256
    simulation.run_id=${RUN_ID} (label form com.extorq.sim.<run_id> is the launchd marker)
  then, after the automatic removal: persistence.launchd.item_deleted (same path)
EOF
if [ "${WAIT_SECONDS}" -gt 0 ]; then
  wait_for persistence.launchd.item_created "${SINCE}" \
    || warn "item_created not observed within ${WAIT_SECONDS}s; removing the file anyway"
else
  hold
fi

DELETED_SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
remove_plist || die "cleanup refused or failed for ${PLIST}"
CLEANED=1
record cleaned_up
wait_for persistence.launchd.item_deleted "${DELETED_SINCE}" \
  || warn "item_deleted not observed yet (the collector reports it at its next launchd scan)"
info "MAC-001 run ${RUN_ID} finished; the LaunchAgent no longer exists"
