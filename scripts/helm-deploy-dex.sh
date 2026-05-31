#!/usr/bin/env bash
# Deploy (or upgrade) Dex as the e2e OIDC identity provider.
#
# Dex is reachable inside the cluster via:
#   http://dex.<namespace>.svc.cluster.local:5556
# and is not exposed externally — no HTTPRoute is created.
#
# Usage:
#   ./scripts/helm-deploy-dex.sh <namespace> [helm flags...]
#
# Optional env vars:
#   DEX_VERSION      — Dex chart version (default: 0.24.0)
#   DEX_HOSTNAME     — external hostname for Dex HTTPRoute (default: dex.dev.flipcloud.ai)
#   DRY_RUN          — set to "true" to run helm with --dry-run

set -euo pipefail

NAMESPACE="${1:?Usage: helm-deploy-dex.sh <namespace> [helm flags...]}"
shift
EXTRA_FLAGS=("$@")

DEX_VERSION="${DEX_VERSION:-0.24.0}"
DEX_HOSTNAME="${DEX_HOSTNAME:-dex.dev.flipcloud.ai}"
DRY_RUN="${DRY_RUN:-false}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
VALUES_FILE="${REPO_ROOT}/.ci/deploy/dev/dex-values.yaml"

DEX_ISSUER="http://dex.${NAMESPACE}.svc.cluster.local:5556"

log() { echo "[helm-deploy-dex] $*"; }

# ── Add / update dex helm repo ────────────────────────────────────────────────

helm repo add dex https://charts.dexidp.io 2>/dev/null || true
helm repo update dex

# ── Deploy ────────────────────────────────────────────────────────────────────

log "Deploying Dex ${DEX_VERSION} to namespace ${NAMESPACE}"
log "Issuer: ${DEX_ISSUER}"

HELM_FLAGS=(
  upgrade --install dex dex/dex
  --version "${DEX_VERSION}"
  --namespace "${NAMESPACE}"
  --create-namespace
  --values "${VALUES_FILE}"
  --set "config.issuer=${DEX_ISSUER}"
  --wait
  --timeout 3m
)

if [ "${DRY_RUN}" = "true" ]; then
  HELM_FLAGS+=(--dry-run)
fi

HELM_FLAGS+=("${EXTRA_FLAGS[@]}")

helm "${HELM_FLAGS[@]}"

# ── Create HTTPRoute so external-dns registers dex.dev.flipcloud.ai ───────────

if [ "${DRY_RUN}" != "true" ]; then
  log "Creating HTTPRoute for ${DEX_HOSTNAME}"
  kubectl apply -f - <<-EOF
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: dex
  namespace: ${NAMESPACE}
  annotations:
    external-dns.alpha.kubernetes.io/ttl: "60"
spec:
  parentRefs:
    - name: external
      namespace: nginx-gateway
      sectionName: https
  hostnames:
    - "${DEX_HOSTNAME}"
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: dex
          port: 5556
EOF
	fi

log "Dex deployed. Internal issuer: ${DEX_ISSUER}"
log "External hostname: https://${DEX_HOSTNAME}"
