#!/usr/bin/env bash
# Create the disposable, PRIVATE ExtorQ lab repository from lab/github-repo.
#
# FOR THE LEAD ONLY, after the user approved creating the repository (outward-facing
# action). The C1 agent never runs this script.
#
# Steps: verify gh authentication and that the repository does not exist yet; build a
# fresh local git repository from lab/github-repo (no ExtorQ history); `gh repo create
# --private --push`; optionally enable Dependabot alerts; print the read-only token and
# collector configuration steps. No credential is printed or written by this script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LAB_DIR="$ROOT/lab/github-repo"

REPO=""
ASSUME_YES=0
ENABLE_DEPENDABOT=0

usage() {
  cat <<'EOF'
Usage: create_lab_repo.sh --repo OWNER/extorq-lab [--enable-dependabot-alerts] [--yes]

  --repo OWNER/NAME           repository to create (name must start with "extorq-lab")
  --enable-dependabot-alerts  enable Dependabot alerts (PUT /repos/{repo}/vulnerability-alerts)
  --yes                       do not ask for interactive confirmation
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) [ $# -ge 2 ] || die "--repo needs a value"; REPO="$2"; shift 2 ;;
    --enable-dependabot-alerts) ENABLE_DEPENDABOT=1; shift ;;
    --yes) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

[ -n "$REPO" ] || { usage >&2; die "--repo is required"; }
[[ "$REPO" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$ ]] || die "invalid --repo"
case "${REPO#*/}" in
  extorq-lab*) ;;
  *) die "refusing: the lab repository name must start with 'extorq-lab'" ;;
esac
command -v gh >/dev/null || die "gh CLI is required"
command -v git >/dev/null || die "git is required"
[ -f "$LAB_DIR/.github/workflows/ci.yml" ] || die "lab content missing at $LAB_DIR"
gh auth status >/dev/null 2>&1 || die "gh CLI is not authenticated"
if gh repo view "$REPO" >/dev/null 2>&1; then
  die "$REPO already exists; refusing to modify an existing repository"
fi

if [ "$ASSUME_YES" -ne 1 ]; then
  [ -t 0 ] || die "not a terminal: re-run with --yes to confirm"
  read -r -p "Create PRIVATE repository $REPO and push the ExtorQ lab content? [y/N] " answer
  case "$answer" in y|Y|yes|YES) ;; *) die "aborted" ;; esac
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/extorq-lab-repo.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/repo"
cp -R "$LAB_DIR/." "$TMP/repo/"
find "$TMP/repo" \( -name '__pycache__' -o -name '.pytest_cache' -o -name '.ruff_cache' \) -prune -exec rm -rf {} +

GH_LOGIN="$(gh api user --jq .login)"
GH_USER_ID="$(gh api user --jq .id)"
[[ "$GH_LOGIN" =~ ^[A-Za-z0-9-]{1,39}$ && "$GH_USER_ID" =~ ^[0-9]+$ ]] || die "unexpected gh user identity"
git -C "$TMP/repo" init -q -b main
git -C "$TMP/repo" add -A
git -C "$TMP/repo" -c user.name="$GH_LOGIN" -c user.email="${GH_USER_ID}+${GH_LOGIN}@users.noreply.github.com" \
  -c commit.gpgsign=false commit -q -m "Initial commit: ExtorQ lab inventory service (disposable lab repository)"

info "creating private repository $REPO"
gh repo create "$REPO" --private --disable-wiki \
  --description "Disposable ExtorQ security lab repository (synthetic content, never deployed)" \
  --source "$TMP/repo" --remote origin --push

VISIBILITY="$(gh repo view "$REPO" --json visibility --jq .visibility)"
[ "$VISIBILITY" = "PRIVATE" ] || die "unexpected visibility '$VISIBILITY' for $REPO (expected PRIVATE)"

if [ "$ENABLE_DEPENDABOT" -eq 1 ]; then
  info "enabling Dependabot alerts"
  gh api -X PUT "repos/$REPO/vulnerability-alerts" --silent || info "could not enable Dependabot alerts (plan or permission)"
fi

REPO_LC="$(printf '%s' "$REPO" | tr '[:upper:]' '[:lower:]')"
cat <<EOF

Created ${REPO} (private). Next steps:

1. Token. config/collectors/github.yaml already lists ${REPO}. Either set
   gh_cli_token_fallback: true there (uses the gh CLI OAuth token, which is broader than
   needed; the collector reports token_source=gh_cli and a warning in its health) or,
   preferred, create a fine-grained personal access token (Settings > Developer settings > Fine-grained
   tokens), resource owner ${REPO%%/*}, repository access "Only select repositories" =
   ${REPO}, expiry <= 30 days, repository permissions (all READ-ONLY):
     Metadata: Read (mandatory), Contents: Read, Actions: Read,
     Administration: Read (branch protection, default workflow permissions, Dependabot
       alert status; without it these are reported as data gaps),
     Dependabot alerts: Read, Code scanning alerts: Read, Secret scanning alerts: Read
       (unavailable features are reported as data gaps, never as "no alerts").
   Store it in a file only you can read and point EXTORQ_GITHUB_TOKEN_FILE at it (a token
   file takes precedence over the gh CLI fallback).
2. Collect:  uv run extorq-collect run --only github-repos --once
   Asset id: github:${REPO_LC}
3. Rehearse GH-001 offline:  simulations/github/gh_001_workflow_permissions.sh --repo ${REPO}
EOF
