#!/usr/bin/env bash
# ExtorQ lab Kubernetes cluster lifecycle (owner: B2). See infra/kind/AGENTS.md.
#
#   infra/kind/kind.sh up           create cluster (if missing), verify audit logging,
#                                   apply namespaces/RBAC/workloads, deploy what is ready
#   infra/kind/kind.sh deploy       (re)apply manifests, secrets and workloads only
#   infra/kind/kind.sh down         delete the extorq-lab cluster (and only that cluster)
#   infra/kind/kind.sh status       cluster, node, workload and audit-log status
#   infra/kind/kind.sh load-images  build lab-portal and load images into the node
#   infra/kind/kind.sh token        mint a short-lived inventory token + kubeconfig (0600)
#   infra/kind/kind.sh netcheck     verify pods can reach the ingest gateway (TLS + CA)
#   infra/kind/kind.sh kubeconfig   print the PATH of the admin kubeconfig (never contents)
#
# Safety:
#   * Every kind call passes --name extorq-lab; every kubectl call passes
#     --kubeconfig var/kube/extorq-lab-admin.kubeconfig --context kind-extorq-lab.
#     The user's ~/.kube/config (and any other cluster, e.g. motorq-security) is
#     never read or modified.
#   * Secrets are passed by file path and never printed. Token/credential files are
#     created with umask 077 under var/ (gitignored).
set -Eeuo pipefail

readonly CLUSTER_NAME="extorq-lab"
readonly CONTEXT="kind-${CLUSTER_NAME}"
readonly NODE_CONTAINER="${CLUSTER_NAME}-control-plane"
readonly NODE_IMAGE="kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
readonly OTEL_IMAGE="otel/opentelemetry-collector-contrib:0.165.0@sha256:e40d61f10c9a617cca1ffd1be4d7e2b3a4b0f0001798ff07e58cabe82e618cea"
readonly POSTURE_LAB_IMAGE="alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"
readonly LAB_PORTAL_BASE_IMAGE="python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
readonly AUDIT_LOG="/var/log/kubernetes/audit/kube-apiserver-audit.log"
readonly OTEL_PRODUCER_ID="k8s-otel-extorq-lab"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
readonly SCRIPT_DIR REPO_ROOT
readonly MANIFESTS="${SCRIPT_DIR}/manifests"
readonly VAR_KIND="${REPO_ROOT}/var/kind"
readonly VAR_KUBE="${REPO_ROOT}/var/kube"
readonly ADMIN_KUBECONFIG="${VAR_KUBE}/extorq-lab-admin.kubeconfig"
readonly INVENTORY_TOKEN="${VAR_KUBE}/extorq-inventory.token"
readonly INVENTORY_KUBECONFIG="${VAR_KUBE}/extorq-inventory.kubeconfig"
readonly LAB_PORTAL_SECRET_DIR="${VAR_KUBE}/lab-portal"
readonly CA_FILE="${REPO_ROOT}/var/tls/ca.crt"
readonly OTEL_TOKEN_FILE="${REPO_ROOT}/var/secrets/tokens/${OTEL_PRODUCER_ID}.token"
readonly LAB_PORTAL_SRC="${REPO_ROOT}/lab/apps/lab-portal"
readonly LAB_PORTAL_DOCKERFILE="${SCRIPT_DIR}/apps/lab-portal/Dockerfile"
readonly GATEWAY_URL="${EXTORQ_K8S_GATEWAY_URL:-https://host.docker.internal:8443}"

log() { printf '[kind.sh] %s\n' "$*" >&2; }
die() { printf '[kind.sh] ERROR: %s\n' "$*" >&2; exit 1; }

kc() { kubectl --kubeconfig "${ADMIN_KUBECONFIG}" --context "${CONTEXT}" "$@"; }

require_tools() {
  local tool
  for tool in docker kind kubectl; do
    command -v "${tool}" >/dev/null 2>&1 || die "required tool not found: ${tool}"
  done
  docker info >/dev/null 2>&1 || die "docker daemon is not reachable"
}

# grep without -q reads all input: no SIGPIPE for the producer under pipefail.
cluster_exists() { kind get clusters 2>/dev/null | grep -x "${CLUSTER_NAME}" >/dev/null; }

ensure_dirs() {
  mkdir -p "${VAR_KIND}" "${VAR_KUBE}" "${LAB_PORTAL_SECRET_DIR}"
  chmod 700 "${VAR_KUBE}" "${LAB_PORTAL_SECRET_DIR}"
}

ensure_admin_kubeconfig() {
  cluster_exists || die "cluster ${CLUSTER_NAME} does not exist (run: infra/kind/kind.sh up)"
  if [[ ! -s "${ADMIN_KUBECONFIG}" ]]; then
    ensure_dirs
    (umask 077 && kind export kubeconfig --name "${CLUSTER_NAME}" --kubeconfig "${ADMIN_KUBECONFIG}" >/dev/null)
  fi
  chmod 600 "${ADMIN_KUBECONFIG}"
}

# Replace fixed placeholder tokens; values are produced by this script, never user input.
render() {
  local src="$1" dst="$2"
  shift 2
  cp "${src}" "${dst}.tmp"
  while (($# >= 2)); do
    local key="$1" value="$2"
    shift 2
    [[ "${key}" =~ ^__[A-Z0-9_]+__$ ]] || die "invalid placeholder ${key}"
    [[ "${value}" != *'|'* && "${value}" != *$'\n'* ]] || die "invalid value for ${key}"
    sed -i.bak "s|${key}|${value}|g" "${dst}.tmp" && rm -f "${dst}.tmp.bak"
  done
  if grep -q '__[A-Z0-9_]*__' "${dst}.tmp"; then
    die "unrendered placeholder left in ${src}"
  fi
  mv "${dst}.tmp" "${dst}"
}

wait_for_audit_log() {
  local i
  for i in $(seq 1 60); do
    if docker exec "${NODE_CONTAINER}" test -s "${AUDIT_LOG}"; then
      return 0
    fi
    sleep 2
  done
  return 1
}

verify_audit() {
  log "verifying kube-apiserver audit flags and audit log"
  local manifest=/etc/kubernetes/manifests/kube-apiserver.yaml flag
  for flag in "--audit-policy-file=/etc/kubernetes/policies/audit-policy.yaml" \
    "--audit-log-path=${AUDIT_LOG}" "--audit-log-maxsize=50" \
    "--audit-log-maxbackup=5" "--audit-log-maxage=7"; do
    docker exec "${NODE_CONTAINER}" grep -qF -- "${flag}" "${manifest}" \
      || die "kube-apiserver flag missing (${flag}): kubeadm patch not applied"
  done
  wait_for_audit_log || die "audit log ${AUDIT_LOG} not populated within 120 s"
  log "audit logging active: $(docker exec "${NODE_CONTAINER}" wc -l "${AUDIT_LOG}" 2>/dev/null || true)"
}

cmd_up() {
  require_tools
  ensure_dirs
  if cluster_exists; then
    log "cluster ${CLUSTER_NAME} already exists; reusing it"
  else
    if ! docker image inspect "${NODE_IMAGE}" >/dev/null 2>&1; then
      log "pulling node image ${NODE_IMAGE}"
      docker pull "${NODE_IMAGE}" >/dev/null
    fi
    local rendered="${VAR_KIND}/cluster.rendered.yaml"
    render "${SCRIPT_DIR}/cluster.yaml" "${rendered}" __EXTORQ_KIND_DIR__ "${SCRIPT_DIR}"
    log "creating cluster ${CLUSTER_NAME} (admin kubeconfig: ${ADMIN_KUBECONFIG})"
    (umask 077 && kind create cluster --name "${CLUSTER_NAME}" --config "${rendered}" \
      --kubeconfig "${ADMIN_KUBECONFIG}" --wait 180s)
  fi
  ensure_admin_kubeconfig
  kc wait --for=condition=Ready "node/${NODE_CONTAINER}" --timeout=180s >/dev/null
  verify_audit
  apply_base
  cmd_load_images
  deploy_workloads
  log "up complete; run: infra/kind/kind.sh status"
}

apply_base() {
  log "applying namespaces, RBAC and posture lab"
  kc apply -f "${MANIFESTS}/00-namespaces.yaml"
  kc apply -f "${MANIFESTS}/10-inventory-rbac.yaml"
  kc apply -f "${MANIFESTS}/20-otel-rbac.yaml"
  render "${MANIFESTS}/40-posture-lab.yaml" "${VAR_KIND}/40-posture-lab.yaml" \
    __POSTURE_LAB_IMAGE__ "${POSTURE_LAB_IMAGE}"
  kc apply -f "${VAR_KIND}/40-posture-lab.yaml"
}

lab_portal_version() {
  # Content hash of the app source + Dockerfile: a new image tag for every change.
  (cd "${REPO_ROOT}" && find lab/apps/lab-portal infra/kind/apps/lab-portal -type f \
    -not -path '*/__pycache__/*' -not -name '*.pyc' -print0 | LC_ALL=C sort -z \
    | xargs -0 shasum -a 256 | shasum -a 256 | cut -c1-12)
}

lab_portal_ready() { [[ -f "${LAB_PORTAL_SRC}/app.py" ]]; }

lab_portal_image() { printf 'extorq/lab-portal:%s' "$(lab_portal_version)"; }

# Public images are pulled by the node's containerd BY DIGEST (digest verified by
# containerd). `kind load docker-image` cannot be used for them: with Docker
# Desktop's containerd image store, `docker save` exports a multi-platform index
# whose other-platform blobs are absent and `ctr import --all-platforms` fails.
node_pull() {
  local image="$1" attempt
  if docker exec "${NODE_CONTAINER}" crictl inspecti "${image}" >/dev/null 2>&1; then
    return 0
  fi
  for attempt in 1 2 3 4; do
    if docker exec "${NODE_CONTAINER}" crictl pull "${image}" >/dev/null 2>&1; then
      log "node pulled ${image}"
      return 0
    fi
    log "node pull attempt ${attempt} failed for ${image}; retrying"
    sleep $((attempt * 5 + RANDOM % 3))
  done
  die "node could not pull ${image}"
}

cmd_load_images() {
  require_tools
  ensure_admin_kubeconfig
  local image
  for image in "${OTEL_IMAGE}" "${POSTURE_LAB_IMAGE}"; do
    node_pull "${image}"
  done
  if lab_portal_ready; then
    image="$(lab_portal_image)"
    if ! docker image inspect "${image}" >/dev/null 2>&1; then
      log "building ${image}"
      docker build --pull=false --provenance=false --sbom=false -f "${LAB_PORTAL_DOCKERFILE}" \
        --build-arg "BASE_IMAGE=${LAB_PORTAL_BASE_IMAGE}" \
        --label "org.opencontainers.image.version=$(lab_portal_version)" \
        -t "${image}" "${LAB_PORTAL_SRC}" >/dev/null
    fi
    log "loading ${image} into ${CLUSTER_NAME}"
    kind load docker-image --name "${CLUSTER_NAME}" "${image}" >/dev/null
  else
    log "lab-portal source not present yet (${LAB_PORTAL_SRC}); skipping image build"
  fi
}

apply_otel_secrets() {
  # CA certificate (public) and the producer token (secret, by file path only).
  kc -n extorq-system create configmap extorq-gateway-ca --from-file=ca.crt="${CA_FILE}" \
    --dry-run=client -o yaml | kc apply --server-side --field-manager=extorq-kind -f - >/dev/null
  # Server-side apply: no last-applied-configuration annotation duplicating the token.
  kc -n extorq-system create secret generic extorq-otel-token \
    --from-file=token="${OTEL_TOKEN_FILE}" --dry-run=client -o yaml \
    | kc apply --server-side --force-conflicts --field-manager=extorq-kind -f - >/dev/null
}

deploy_otel() {
  if [[ "${EXTORQ_K8S_SKIP_OTEL:-0}" == "1" ]]; then
    log "OTel collector NOT deployed (EXTORQ_K8S_SKIP_OTEL=1)"
    return 0
  fi
  if [[ ! -s "${CA_FILE}" || ! -s "${OTEL_TOKEN_FILE}" ]]; then
    log "OTel collector NOT deployed: ${CA_FILE#"${REPO_ROOT}"/} or the ${OTEL_PRODUCER_ID} token is missing (run make bootstrap)"
    return 0
  fi
  log "deploying OTel collector DaemonSet"
  apply_otel_secrets
  local config="${SCRIPT_DIR}/otel/collector.yaml" config_sha
  config_sha="$(shasum -a 256 "${config}" | cut -c1-16)"
  kc -n extorq-system create configmap extorq-otel-config --from-file=collector.yaml="${config}" \
    --dry-run=client -o yaml | kc apply --server-side --force-conflicts --field-manager=extorq-kind -f - >/dev/null
  render "${MANIFESTS}/21-otel-daemonset.yaml" "${VAR_KIND}/21-otel-daemonset.yaml" \
    __OTEL_IMAGE__ "${OTEL_IMAGE}" __OTEL_CONFIG_SHA__ "${config_sha}"
  kc apply -f "${VAR_KIND}/21-otel-daemonset.yaml"
  kc -n extorq-system rollout status ds/extorq-otel-collector --timeout=180s
}

ensure_lab_portal_secret() {
  # Random demo password generated locally (never committed). The plaintext stays in
  # var/kube/lab-portal/demo-password (0600) for the operator; the cluster only gets a
  # PBKDF2 hash, computed by the app itself inside its image (password on stdin).
  local pw_file="${LAB_PORTAL_SECRET_DIR}/demo-password"
  local hash_file="${LAB_PORTAL_SECRET_DIR}/demo-password.pbkdf2"
  if [[ ! -s "${pw_file}" ]]; then
    # 128 random bits as 32 hex characters (no pipeline: nothing can SIGPIPE).
    (umask 077 && openssl rand -hex 16 > "${pw_file}")
  fi
  chmod 600 "${pw_file}"
  [[ "$(wc -c < "${pw_file}" | tr -d ' ')" -ge 24 ]] || die "demo password file is too short"
  if [[ ! -s "${hash_file}" || "${pw_file}" -nt "${hash_file}" ]]; then
    local tmp
    tmp="$(mktemp "${LAB_PORTAL_SECRET_DIR}/.hash.XXXXXX")"
    chmod 600 "${tmp}"
    if ! docker run --rm -i --network none --read-only --cap-drop ALL \
      --security-opt no-new-privileges --name "extorq-b2-hash-$$" \
      "$(lab_portal_image)" --hash-password < "${pw_file}" > "${tmp}"; then
      rm -f "${tmp}"
      die "could not hash the lab-portal demo password"
    fi
    grep -q '^pbkdf2_sha256\$' "${tmp}" || { rm -f "${tmp}"; die "unexpected password hash format"; }
    mv -f "${tmp}" "${hash_file}"
  fi
  kc -n extorq-apps create secret generic lab-portal-demo-credentials \
    --from-file=password_hash="${hash_file}" --dry-run=client -o yaml \
    | kc apply --server-side --force-conflicts --field-manager=extorq-kind -f - >/dev/null
}

deploy_lab_portal() {
  if ! lab_portal_ready; then
    log "lab-portal NOT deployed: ${LAB_PORTAL_SRC} not present yet (owner: B1)"
    return 0
  fi
  log "deploying lab-portal"
  ensure_lab_portal_secret
  local cred_sha
  cred_sha="$(shasum -a 256 "${LAB_PORTAL_SECRET_DIR}/demo-password.pbkdf2" | cut -c1-16)"
  render "${MANIFESTS}/30-lab-portal.yaml" "${VAR_KIND}/30-lab-portal.yaml" \
    __LAB_PORTAL_IMAGE__ "$(lab_portal_image)" __LAB_PORTAL_CRED_SHA__ "${cred_sha}"
  kc apply -f "${VAR_KIND}/30-lab-portal.yaml"
  kc -n extorq-apps rollout status deploy/lab-portal --timeout=180s
}

deploy_workloads() {
  deploy_lab_portal
  deploy_otel
}

cmd_deploy() {
  require_tools
  ensure_dirs
  ensure_admin_kubeconfig
  apply_base
  cmd_load_images
  deploy_workloads
}

cmd_down() {
  require_tools
  if ! cluster_exists; then
    log "cluster ${CLUSTER_NAME} does not exist"
    return 0
  fi
  log "deleting cluster ${CLUSTER_NAME} (no other cluster is touched)"
  kind delete cluster --name "${CLUSTER_NAME}" --kubeconfig "${ADMIN_KUBECONFIG}"
  rm -f "${ADMIN_KUBECONFIG}" "${INVENTORY_TOKEN}" "${INVENTORY_KUBECONFIG}"
}

cmd_status() {
  require_tools
  if ! cluster_exists; then
    echo "cluster ${CLUSTER_NAME}: absent"
    return 0
  fi
  ensure_admin_kubeconfig
  echo "cluster ${CLUSTER_NAME}: present (context ${CONTEXT}, kubeconfig ${ADMIN_KUBECONFIG#"${REPO_ROOT}"/})"
  kc get nodes -o wide
  echo
  kc get pods -A -o wide --field-selector=metadata.namespace!=kube-system
  echo
  kc get ns -L pod-security.kubernetes.io/enforce,pod-security.kubernetes.io/warn,pod-security.kubernetes.io/audit
  echo
  echo "audit log (${AUDIT_LOG}):"
  docker exec "${NODE_CONTAINER}" sh -c "ls -l /var/log/kubernetes/audit/ && wc -l ${AUDIT_LOG}"
  if [[ -s "${INVENTORY_TOKEN}" ]]; then
    echo "inventory token: present (${INVENTORY_TOKEN#"${REPO_ROOT}"/}, mtime $(stat -f '%Sm' "${INVENTORY_TOKEN}"))"
  else
    echo "inventory token: absent (run: infra/kind/kind.sh token)"
  fi
  if curl -fsS -o /dev/null --max-time 3 http://127.0.0.1:8089/healthz 2>/dev/null; then
    echo "lab-portal: http://127.0.0.1:8089 reachable"
  else
    echo "lab-portal: http://127.0.0.1:8089 not reachable"
  fi
}

cmd_token() {
  require_tools
  ensure_dirs
  ensure_admin_kubeconfig
  local duration="${EXTORQ_K8S_TOKEN_DURATION:-24h}"
  [[ "${duration}" =~ ^[0-9]{1,3}[hm]$ ]] || die "invalid EXTORQ_K8S_TOKEN_DURATION (expected e.g. 24h)"
  local tmp server ca_data
  tmp="$(mktemp "${VAR_KUBE}/.inventory-token.XXXXXX")"
  chmod 600 "${tmp}"
  # TokenRequest API: audience-bound, time-limited, never stored in a Secret object.
  if ! kc -n extorq-system create token extorq-inventory --duration "${duration}" | tr -d '\n' > "${tmp}"; then
    rm -f "${tmp}"
    die "TokenRequest for extorq-system/extorq-inventory failed"
  fi
  [[ -s "${tmp}" ]] || { rm -f "${tmp}"; die "empty token returned"; }
  mv -f "${tmp}" "${INVENTORY_TOKEN}"
  server="$(kc config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
  [[ "${server}" =~ ^https://127\.0\.0\.1:[0-9]+$ ]] || die "unexpected API server URL: ${server}"
  # Public cluster CA certificate only (jsonpath selects nothing else).
  ca_data="$(kc config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"
  [[ -n "${ca_data}" ]] || die "could not read the cluster CA certificate"
  tmp="$(mktemp "${VAR_KUBE}/.inventory-kubeconfig.XXXXXX")"
  chmod 600 "${tmp}"
  cat > "${tmp}" <<EOF
# Generated by infra/kind/kind.sh token: read-only extorq-inventory identity.
apiVersion: v1
kind: Config
clusters:
  - name: ${CLUSTER_NAME}
    cluster:
      server: ${server}
      certificate-authority-data: ${ca_data}
users:
  - name: extorq-inventory
    user:
      tokenFile: ${INVENTORY_TOKEN}
contexts:
  - name: extorq-inventory@${CLUSTER_NAME}
    context:
      cluster: ${CLUSTER_NAME}
      user: extorq-inventory
current-context: extorq-inventory@${CLUSTER_NAME}
EOF
  mv -f "${tmp}" "${INVENTORY_KUBECONFIG}"
  log "inventory token (${duration}) -> ${INVENTORY_TOKEN#"${REPO_ROOT}"/}; kubeconfig -> ${INVENTORY_KUBECONFIG#"${REPO_ROOT}"/}"
}

cmd_netcheck() {
  require_tools
  ensure_admin_kubeconfig
  [[ -s "${CA_FILE}" ]] || die "missing ${CA_FILE} (run make bootstrap)"
  kc -n extorq-system create configmap extorq-gateway-ca --from-file=ca.crt="${CA_FILE}" \
    --dry-run=client -o yaml | kc apply --server-side --field-manager=extorq-kind -f - >/dev/null
  render "${MANIFESTS}/90-netcheck-pod.yaml" "${VAR_KIND}/90-netcheck-pod.yaml" \
    __NETCHECK_IMAGE__ "${LAB_PORTAL_BASE_IMAGE}" __GATEWAY_URL__ "${GATEWAY_URL}"
  kc -n extorq-system delete pod extorq-b2-netcheck --ignore-not-found --wait=true >/dev/null
  kc apply -f "${VAR_KIND}/90-netcheck-pod.yaml" >/dev/null
  local phase="" i
  for i in $(seq 1 90); do
    phase="$(kc -n extorq-system get pod extorq-b2-netcheck -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [[ "${phase}" == "Succeeded" || "${phase}" == "Failed" ]] && break
    sleep 2
  done
  kc -n extorq-system logs extorq-b2-netcheck || true
  kc -n extorq-system delete pod extorq-b2-netcheck --ignore-not-found --wait=false >/dev/null
  [[ "${phase}" == "Succeeded" ]] || die "netcheck failed (phase: ${phase:-unknown})"
}

main() {
  local cmd="${1:-}"
  case "${cmd}" in
    up) cmd_up ;;
    deploy) cmd_deploy ;;
    down) cmd_down ;;
    status) cmd_status ;;
    load-images) cmd_load_images ;;
    token) cmd_token ;;
    netcheck) cmd_netcheck ;;
    kubeconfig) echo "${ADMIN_KUBECONFIG}" ;;
    *)
      sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      [[ -n "${cmd}" ]] && die "unknown command: ${cmd}"
      exit 2
      ;;
  esac
}

main "$@"
