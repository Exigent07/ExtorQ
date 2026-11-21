#!/usr/bin/env bash
# MAC-001 - LaunchAgent persistence on the macOS host (ExtorQ lab simulation, owner B3).
#
# Creates ~/Library/LaunchAgents/com.extorq.sim.<run_id>.plist with Label
# com.extorq.sim.<run_id>, ProgramArguments [/usr/bin/true] and RunAtLoad false.
# The job is NEVER loaded (this script never runs launchctl); even if it were loaded it
# would only execute /usr/bin/true. macOS may show a "Background Items Added"
# notification for the new file: that is expected. --cleanup deletes the file (only if it
# is the regular file this scenario created) and verifies that it is gone.
#
# Usage: simulations/macos/mac_001_launchagent.sh [--run-id ID] [--wait SECONDS|--no-wait]
#        simulations/macos/mac_001_launchagent.sh --cleanup --run-id ID [--wait SECONDS|--no-wait]
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

info() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --run-id) [ $# -ge 2 ] || die "--run-id needs a value"; RUN_ID="$2"; shift 2 ;;
    --cleanup) CLEANUP=1; shift ;;
    --wait) [ $# -ge 2 ] || die "--wait needs seconds"; WAIT_SECONDS="$2"; shift 2 ;;
    --no-wait) WAIT_SECONDS=0; shift ;;
    -h|--help) sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ "$(uname -s)" = "Darwin" ] || die "MAC-001 runs on the macOS host only"
printf '%s' "${WAIT_SECONDS}" | grep -Eq '^[0-9]{1,4}$' || die "--wait must be 0-9999 seconds"
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

wait_for() {  # wait_for <event_type> <since-iso>
  if [ "${WAIT_SECONDS}" -eq 0 ]; then
    info "not waiting for $1 (--no-wait)"
    return 0
  fi
  info "waiting up to ${WAIT_SECONDS}s for $1 from the macOS collector"
  (cd "${REPO_ROOT}" && uv run --quiet python simulations/macos/wait_event.py \
     --event-type "$1" --path "${PLIST}" --since "$2" --timeout "${WAIT_SECONDS}")
}

if [ "${CLEANUP}" -eq 1 ]; then
  SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [ -L "${PLIST}" ]; then
    die "${PLIST} is a symbolic link: not created by this scenario, refusing to delete"
  fi
  if [ -e "${PLIST}" ]; then
    [ -f "${PLIST}" ] || die "${PLIST} is not a regular file: refusing to delete"
    /usr/bin/plutil -extract Label raw -o - "${PLIST}" 2>/dev/null | grep -qx "${LABEL}" \
      || die "${PLIST} does not carry Label ${LABEL}: refusing to delete"
    rm -f -- "${PLIST}"
    info "removed ${PLIST}"
  else
    info "${PLIST} is already absent"
  fi
  [ ! -e "${PLIST}" ] || die "cleanup failed: ${PLIST} still exists"
  info "verified: ${PLIST} no longer exists"
  record cleaned_up
  wait_for persistence.launchd.item_deleted "${SINCE}" || warn "item_deleted not observed yet"
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
trap 'rm -f -- "${TMP}"' EXIT
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
mv -- "${TMP}" "${PLIST}"
trap - EXIT
info "created ${PLIST} (not loaded; ProgramArguments=/usr/bin/true, RunAtLoad=false)"
record completed

cat <<EOF

MAC-001 run ${RUN_ID}: expected genuine telemetry on ${ASSET_ID} (macos.launchd, within one
launchd interval, 60 s by default):
  persistence.launchd.item_created  resource.path=${PLIST}
    attributes: label=${LABEL}, program=/usr/bin/true, run_at_load=false, scope=user, sha256
    simulation.run_id=${RUN_ID} (label form com.extorq.sim.<run_id> is the launchd marker)
  service.discovered (macos.inventory) for launchd job ${LABEL} (not loaded) at the next
    inventory cycle (300 s by default)
Cleanup: simulations/macos/mac_001_launchagent.sh --cleanup --run-id ${RUN_ID}
EOF
wait_for persistence.launchd.item_created "${SINCE}"
