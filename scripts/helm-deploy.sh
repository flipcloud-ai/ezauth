#!/usr/bin/env bash
# Deploy (or upgrade) the ezauth Helm chart.
#
# Usage:
#   ./scripts/helm-deploy.sh <release> <namespace> <values-file> [helm flags...]
#
# Required env vars:
#   AWS_REGION         — AWS region (used for Secrets Manager + EKS kubeconfig)
#   SECRET_NAME        — AWS Secrets Manager secret name for DB creds
#                        (JSON keys: host, port, dbname, username, password)
#
# Optional env vars:
#   IMAGE_TAG          — Docker image tag to deploy (default: latest)
#   AWS_PROFILE        — AWS CLI profile (default: default)
#   REDIS_SECRET_NAME  — AWS Secrets Manager secret name for Redis creds
#                        (JSON keys: host, port, auth_token)
#   GHCR_TOKEN         — GitHub PAT with read:packages scope (for private ghcr.io)
#   GHCR_USER          — GitHub username owning the PAT (default: flipcloud-ai)
#   CHART              — path to the Helm chart (default: deployment/charts/ezauth)
#   DRY_RUN            — set to "true" to run helm with --dry-run
#   TEMPLATE           — set to "true" to run helm template instead of upgrade
#   DEPLOY_DEX         — set to "true" to also deploy Dex into the same namespace

set -euo pipefail

RELEASE="${1:?Usage: helm-deploy.sh <release> <namespace> <values-file> [helm flags...]}"
NAMESPACE="${2:?Usage: helm-deploy.sh <release> <namespace> <values-file> [helm flags...]}"
VALUES_FILE="${3:?Usage: helm-deploy.sh <release> <namespace> <values-file> [helm flags...]}"
shift 3
EXTRA_FLAGS=("$@")

IMAGE_TAG="${IMAGE_TAG:-latest}"
: "${AWS_REGION:?AWS_REGION is required}"
: "${SECRET_NAME:?SECRET_NAME is required}"

AWS_PROFILE="${AWS_PROFILE:-default}"
CHART="${CHART:-deployment/charts/ezauth}"
DRY_RUN="${DRY_RUN:-false}"
TEMPLATE="${TEMPLATE:-false}"
DEPLOY_DEX="${DEPLOY_DEX:-false}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

log() { echo "[helm-deploy] $*"; }

# ── Pull secrets from AWS Secrets Manager ─────────────────────────────────────

log "Fetching secret ${SECRET_NAME}..."
SECRET_JSON=$(AWS_PROFILE="${AWS_PROFILE}" aws secretsmanager get-secret-value \
  --region "${AWS_REGION}" --secret-id "${SECRET_NAME}" \
  --query SecretString --output text)

DB_HOST=$(echo "${SECRET_JSON}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['host'])")
DB_PORT=$(echo "${SECRET_JSON}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('port',5432))")
DB_NAME=$(echo "${SECRET_JSON}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['dbname'])")
DB_USER=$(echo "${SECRET_JSON}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['username'])")
DB_PASS=$(echo "${SECRET_JSON}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['password'])")

REDIS_SECRET_NAME="${REDIS_SECRET_NAME:-}"
REDIS_ADDR=""
REDIS_PASS=""
if [ -n "${REDIS_SECRET_NAME}" ]; then
  log "Fetching Redis secret ${REDIS_SECRET_NAME}..."
  REDIS_JSON=$(AWS_PROFILE="${AWS_PROFILE}" aws secretsmanager get-secret-value \
    --region "${AWS_REGION}" --secret-id "${REDIS_SECRET_NAME}" \
    --query SecretString --output text)
  REDIS_HOST=$(echo "${REDIS_JSON}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['host'])")
  REDIS_PORT=$(echo "${REDIS_JSON}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('port',6379))")
  REDIS_PASS=$(echo "${REDIS_JSON}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('auth_token',''))")
  REDIS_ADDR="${REDIS_HOST}:${REDIS_PORT}"
fi

# ── GHCR image pull secret ────────────────────────────────────────────────────

if [ -n "${GHCR_TOKEN:-}" ]; then
  GHCR_USER="${GHCR_USER:-flipcloud-ai}"
  log "Creating/updating ghcr-pull-secret..."
  kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
  kubectl create secret docker-registry ghcr-pull-secret \
    --namespace "${NAMESPACE}" \
    --docker-server=ghcr.io \
    --docker-username="${GHCR_USER}" \
    --docker-password="${GHCR_TOKEN}" \
    --dry-run=client -o yaml | kubectl apply -f -
fi

# ── Helm upgrade --install ────────────────────────────────────────────────────

if [ "${TEMPLATE}" = "true" ]; then
  HELM_FLAGS=(
    template "${RELEASE}" "${REPO_ROOT}/${CHART}"
    --namespace "${NAMESPACE}"
    --values "${VALUES_FILE}"
    --set "image.tag=${IMAGE_TAG}"
    --set "config.database.hostname=${DB_HOST}"
    --set "config.database.port=${DB_PORT}"
    --set "config.database.database_name=${DB_NAME}"
    --set "config.database.user=${DB_USER}"
    --set "secrets.databasePassword=${DB_PASS}"
    --set "secrets.redisPassword=${REDIS_PASS}"
  )
else
  HELM_FLAGS=(
    upgrade --install "${RELEASE}" "${REPO_ROOT}/${CHART}"
    --namespace "${NAMESPACE}"
    --create-namespace
    --values "${VALUES_FILE}"
    --set "image.tag=${IMAGE_TAG}"
    --set "config.database.hostname=${DB_HOST}"
    --set "config.database.port=${DB_PORT}"
    --set "config.database.database_name=${DB_NAME}"
    --set "config.database.user=${DB_USER}"
    --set "secrets.databasePassword=${DB_PASS}"
    --set "secrets.redisPassword=${REDIS_PASS}"
    --wait
    --timeout 5m
  )
fi

if [ -n "${REDIS_ADDR}" ]; then
  HELM_FLAGS+=(--set "config.cache.redis.addr=${REDIS_ADDR}")
  HELM_FLAGS+=(--set "config.cache.redis.password=${REDIS_PASS}")
fi

if [ "${DRY_RUN}" = "true" ]; then
  HELM_FLAGS+=(--dry-run)
fi

if [ "${TEMPLATE}" = "true" ]; then
  log "Running: helm template ${RELEASE} ..."
else
  log "Running: helm upgrade --install ${RELEASE} ..."
fi

HELM_FLAGS+=("${EXTRA_FLAGS[@]}")

helm "${HELM_FLAGS[@]}"

if [ "${TEMPLATE}" != "true" ]; then
  log "Deploy complete: ${RELEASE} → ${NAMESPACE} @ ${IMAGE_TAG}"
fi

# ── Optional Dex deploy ───────────────────────────────────────────────────────

if [ "${DEPLOY_DEX}" = "true" ] && [ "${TEMPLATE}" != "true" ]; then
  log "DEPLOY_DEX=true — deploying Dex into namespace ${NAMESPACE}..."
  AWS_PROFILE="${AWS_PROFILE}" \
  DRY_RUN="${DRY_RUN}" \
    "${SCRIPT_DIR}/helm-deploy-dex.sh" "${NAMESPACE}"
fi
