#!/usr/bin/env bash
# GH-001 - GitHub Actions workflow permission escalation (ExtorQ lab simulation).
#
# Modifies the lab repository's CI workflow to an objectively excessive state:
#   * `permissions: write-all` (every GITHUB_TOKEN scope writable), and
#   * a `pull_request_target` trigger whose job checks out the pull request head
#     (`ref: ${{ github.event.pull_request.head.sha }}`, `allow-unsafe-pr-checkout: true`).
# The commit message carries `[extorq-sim <run_id>]`, so the genuine GitHub telemetry
# collected by ExtorQ is tagged as simulation traffic without being filtered out.
#
# Modes
#   --dry-run  (default) Build a throwaway local git repository from lab/github-repo,
#              apply the change there and run the ExtorQ workflow analyser offline on the
#              resulting diff (and on the cleanup diff). No network, no GitHub access.
#   --execute  Clone the lab repository into var/github/, commit the change, push it to the
#              default branch and record the SimulationRun. Run by the lead only, after
#              the user approved pushing to the lab repository.
#   --cleanup  Restore the least-privilege baseline workflow with a NEW commit (history
#              is never rewritten) and record the SimulationRun as cleaned_up.
#
# Safety: refuses repositories that are not private or whose name does not start with
# "extorq-lab"; never prints credentials; uses argument lists only.
set -euo pipefail

SCENARIO="GH-001"
WORKFLOW=".github/workflows/ci.yml"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LAB_DIR="$ROOT/lab/github-repo"
TEMPLATE="$SCRIPT_DIR/templates/ci-gh001.yml"

MODE="dry-run"
REPO=""
RUN_ID=""
ASSUME_YES=0
RECORD=1
KEEP_TMP=0

usage() {
  cat <<'EOF'
Usage: gh_001_workflow_permissions.sh --repo OWNER/extorq-lab [--dry-run|--execute|--cleanup]
                                      [--run-id ID] [--yes] [--no-record] [--keep]

  --repo OWNER/NAME  lab repository (must be private; name must start with "extorq-lab")
  --dry-run          offline rehearsal in a temporary local git repository (default)
  --execute          push the escalated workflow to the lab repository (lead only)
  --cleanup          restore the baseline workflow with a new commit (requires --run-id)
  --run-id ID        simulation run id, 8-32 lower-case alphanumerics (generated if omitted)
  --yes              do not ask for interactive confirmation
  --no-record        do not record the SimulationRun via `extorq-collect sim-record`
  --keep             dry run: keep the temporary repository for inspection
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) [ $# -ge 2 ] || die "--repo needs a value"; REPO="$2"; shift 2 ;;
    --dry-run) MODE="dry-run"; shift ;;
    --execute) MODE="execute"; shift ;;
    --cleanup) MODE="cleanup"; shift ;;
    --run-id) [ $# -ge 2 ] || die "--run-id needs a value"; RUN_ID="$2"; shift 2 ;;
    --yes) ASSUME_YES=1; shift ;;
    --no-record) RECORD=0; shift ;;
    --keep) KEEP_TMP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

[ -n "$REPO" ] || { usage >&2; die "--repo is required"; }
if [[ ! "$REPO" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$ ]]; then
  die "invalid --repo (expected OWNER/NAME)"
fi
REPO_NAME="${REPO#*/}"
case "$REPO_NAME" in
  extorq-lab*) ;;
  *) die "refusing: repository name must start with 'extorq-lab' (disposable lab repositories only)" ;;
esac
REPO_LC="$(printf '%s' "$REPO" | tr '[:upper:]' '[:lower:]')"
ASSET="github:${REPO_LC}"

if [ -z "$RUN_ID" ]; then
  [ "$MODE" != "cleanup" ] || die "--cleanup requires the --run-id of the simulation to revert"
  RUN_ID="$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 12 || true)"
fi
[[ "$RUN_ID" =~ ^[a-z0-9]{8,32}$ ]] || die "invalid --run-id (8-32 lower-case alphanumerics)"

[ -f "$TEMPLATE" ] || die "missing template $TEMPLATE"
[ -f "$LAB_DIR/$WORKFLOW" ] || die "missing baseline workflow $LAB_DIR/$WORKFLOW"
command -v git >/dev/null || die "git is required"
command -v uv >/dev/null || die "uv is required"

SIM_MESSAGE="ci: add PR preview job and broaden token permissions [extorq-sim ${RUN_ID}]"
SIM_DESCRIPTION="GH-001: CI workflow changed to permissions: write-all plus a pull_request_target job that checks out the PR head (lab repository only)"
CLEANUP_MESSAGE="ci: restore least-privilege CI workflow [extorq-sim ${RUN_ID} cleanup]"

analyse() {  # analyse <before-file> <after-file> <expectation-flag>
  (cd "$ROOT" && uv run --quiet python -m extorq_collectors.github.analyze \
    --path "$WORKFLOW" --before "$1" --after "$2" --repo-default read "$3")
}

confirm() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  [ -t 0 ] || die "not a terminal: re-run with --yes to confirm"
  local answer
  read -r -p "$1 [y/N] " answer
  case "$answer" in y|Y|yes|YES) return 0 ;; *) die "aborted" ;; esac
}

record() {  # record <status>
  if [ "$RECORD" -eq 0 ]; then
    info "SimulationRun recording skipped (--no-record): status=$1"
    return 0
  fi
  local rc=0
  (cd "$ROOT" && uv run --quiet extorq-collect sim-record \
    --scenario "$SCENARIO" --asset "$ASSET" --status "$1" --run-id "$RUN_ID" \
    --description "$SIM_DESCRIPTION" --expected-rules "$SCENARIO") || rc=$?
  case "$rc" in
    0) info "SimulationRun $RUN_ID recorded: $1" ;;
    75) info "SimulationRun $RUN_ID ($1) committed locally but not yet delivered;" \
            "it is sent by the next sim-record or 'uv run extorq-collect flush'" ;;
    *) die "sim-record failed (exit $rc) for status $1" ;;
  esac
}

print_expected() {  # print_expected <commit-sha>
  cat <<EOF

Expected genuine telemetry (within one or two collector intervals, default 120 s):
  github.commit.observed        asset=${ASSET} commit=$1 simulation.run_id=${RUN_ID}
  github.workflow.modified      path=${WORKFLOW} commit=$1
                                write_all_added=true, added_write_scopes=[actions, contents, ...],
                                triggers_added=[pull_request_target],
                                risk_flags include write_all_added,
                                dangerous_trigger_added:pull_request_target,
                                privileged_trigger_untrusted_checkout
  github.workflow_run.observed  "CI" run for head_sha=$1 (event=push), simulation.run_id=${RUN_ID}
  posture (extorq-posture-github) findings: github.workflow.write_all,
                                github.workflow.privileged_untrusted_checkout
Expected detection: GH-001 (grouped by repository, commit and workflow path).
Revert with: $0 --repo ${REPO} --cleanup --run-id ${RUN_ID}
EOF
}

# ── dry run ─────────────────────────────────────────────────────────────────────
if [ "$MODE" = "dry-run" ]; then
  TMP="$(mktemp -d "${TMPDIR:-/tmp}/extorq-gh001.XXXXXX")"
  if [ "$KEEP_TMP" -eq 0 ]; then trap 'rm -rf "$TMP"' EXIT; fi
  info "dry run (offline): temporary repository $TMP/repo"
  mkdir -p "$TMP/repo"
  cp -R "$LAB_DIR/." "$TMP/repo/"
  GIT_ID=(-c user.name="ExtorQ simulation (dry run)" -c user.email="dry-run@extorq.invalid" -c commit.gpgsign=false)
  git -C "$TMP/repo" init -q -b main
  git -C "$TMP/repo" add -A
  git -C "$TMP/repo" "${GIT_ID[@]}" commit -q -m "Initial lab baseline (dry run)"
  cp "$TEMPLATE" "$TMP/repo/$WORKFLOW"
  git -C "$TMP/repo" add "$WORKFLOW"
  git -C "$TMP/repo" "${GIT_ID[@]}" commit -q -m "$SIM_MESSAGE"
  git -C "$TMP/repo" show "HEAD~1:$WORKFLOW" >"$TMP/before.yml"
  git -C "$TMP/repo" show "HEAD:$WORKFLOW" >"$TMP/after.yml"
  info "simulated commit: $(git -C "$TMP/repo" log -1 --format='%h %s')"
  info "diff of $WORKFLOW:"
  git -C "$TMP/repo" --no-pager diff --stat HEAD~1 HEAD
  info "workflow analyser on the GH-001 diff (expect escalation):"
  analyse "$TMP/before.yml" "$TMP/after.yml" --expect-escalation
  marker="$(cd "$ROOT" && uv run --quiet python -c \
    'import sys; from extorq_collectors.github.records import simulation_run_id; print(simulation_run_id(sys.argv[1]))' \
    "$SIM_MESSAGE")"
  [ "$marker" = "$RUN_ID" ] || die "simulation marker not recognised in commit message (got '$marker')"
  info "simulation marker parsed from commit message: run_id=$marker"

  cp "$LAB_DIR/$WORKFLOW" "$TMP/repo/$WORKFLOW"
  git -C "$TMP/repo" add "$WORKFLOW"
  git -C "$TMP/repo" "${GIT_ID[@]}" commit -q -m "$CLEANUP_MESSAGE"
  git -C "$TMP/repo" show "HEAD~1:$WORKFLOW" >"$TMP/cleanup-before.yml"
  git -C "$TMP/repo" show "HEAD:$WORKFLOW" >"$TMP/cleanup-after.yml"
  info "workflow analyser on the cleanup diff (expect no escalation):"
  analyse "$TMP/cleanup-before.yml" "$TMP/cleanup-after.yml" --expect-no-escalation
  info "dry run OK (run_id=$RUN_ID). Nothing was pushed or recorded."
  [ "$KEEP_TMP" -eq 1 ] && info "kept $TMP"
  exit 0
fi

# ── execute / cleanup (network, outward-facing) ───────────────────────────────────
command -v gh >/dev/null || die "gh CLI is required"
gh auth status >/dev/null 2>&1 || die "gh CLI is not authenticated"
IS_PRIVATE="$(gh repo view "$REPO" --json isPrivate --jq .isPrivate)" || die "cannot read $REPO"
[ "$IS_PRIVATE" = "true" ] || die "refusing: $REPO is not private"
DEFAULT_BRANCH="$(gh repo view "$REPO" --json defaultBranchRef --jq .defaultBranchRef.name)"
git check-ref-format --branch "$DEFAULT_BRANCH" >/dev/null 2>&1 || die "unexpected default branch name"
GH_LOGIN="$(gh api user --jq .login)"
GH_USER_ID="$(gh api user --jq .id)"
[[ "$GH_LOGIN" =~ ^[A-Za-z0-9-]{1,39}$ && "$GH_USER_ID" =~ ^[0-9]+$ ]] || die "unexpected gh user identity"
GIT_ID=(-c user.name="${GH_LOGIN} (ExtorQ simulation)" -c user.email="${GH_USER_ID}+${GH_LOGIN}@users.noreply.github.com" -c commit.gpgsign=false)
# Authenticate git over HTTPS through the gh CLI for these commands only (no persistent
# git configuration change, no credential written to disk or printed).
GH_BIN="$(command -v gh)"
GIT_AUTH=(-c credential.helper= -c "credential.helper=!${GH_BIN} auth git-credential")
REMOTE_URL="https://github.com/${REPO}.git"

WORK_ROOT="$ROOT/var/github"
mkdir -p "$WORK_ROOT"
WORK="$WORK_ROOT/gh-001-${RUN_ID}-${MODE}"
[ ! -e "$WORK" ] || die "$WORK already exists (remove it or use another --run-id)"

if [ "$MODE" = "execute" ]; then
  confirm "Push the GH-001 escalated workflow to ${REPO}@${DEFAULT_BRANCH} (run_id=${RUN_ID})?"
  git "${GIT_AUTH[@]}" clone --quiet --branch "$DEFAULT_BRANCH" "$REMOTE_URL" "$WORK"
  if grep -Eq '^permissions:[[:space:]]*write-all' "$WORK/$WORKFLOW" 2>/dev/null; then
    die "$WORKFLOW already grants write-all: run --cleanup for the previous run first"
  fi
  record started
  cp "$TEMPLATE" "$WORK/$WORKFLOW"
  git -C "$WORK" add "$WORKFLOW"
  git -C "$WORK" "${GIT_ID[@]}" commit -q -m "$SIM_MESSAGE"
  SHA="$(git -C "$WORK" rev-parse HEAD)"
  if ! git -C "$WORK" "${GIT_AUTH[@]}" push -q origin "HEAD:${DEFAULT_BRANCH}"; then
    record failed || true
    die "push failed; nothing changed on GitHub"
  fi
  info "pushed $SHA to ${REPO}@${DEFAULT_BRANCH}"
  record completed
  print_expected "$SHA"
  exit 0
fi

# cleanup
confirm "Restore the baseline workflow on ${REPO}@${DEFAULT_BRANCH} (run_id=${RUN_ID})?"
git "${GIT_AUTH[@]}" clone --quiet --branch "$DEFAULT_BRANCH" "$REMOTE_URL" "$WORK"
cp "$LAB_DIR/$WORKFLOW" "$WORK/$WORKFLOW"
if git -C "$WORK" diff --quiet -- "$WORKFLOW"; then
  info "$WORKFLOW already matches the baseline; nothing to revert"
else
  git -C "$WORK" add "$WORKFLOW"
  git -C "$WORK" "${GIT_ID[@]}" commit -q -m "$CLEANUP_MESSAGE"
  git -C "$WORK" "${GIT_AUTH[@]}" push -q origin "HEAD:${DEFAULT_BRANCH}" || die "push failed"
  info "pushed cleanup commit $(git -C "$WORK" rev-parse HEAD)"
fi
record cleaned_up
info "cleanup complete; expect a github.workflow.modified event with write_all_added=false"
