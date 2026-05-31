#!/usr/bin/env bash
set -euo pipefail

CHART="${CHART:-deployment/charts/ezauth}"
PASS=0
FAIL=0

render() {
    local name="$1"
    shift
    if helm template test "$CHART" "$@" >/dev/null 2>&1; then
        echo "  PASS  $name"
        ((PASS++)) || true
    else
        echo "  FAIL  $name"
        helm template test "$CHART" "$@" 2>&1 | tail -5
        ((FAIL++)) || true
    fi
}

echo "Helm chart template tests — $CHART"
echo "=================================="

echo ""
echo "--- Basic --------------------------------------------------"
render "minimal defaults"

render "with secrets" \
    --set-string secrets.jwtSecret=test-jwt-key \
    --set-string secrets.databasePassword=test-db-pass \
    --set-string secrets.bootstrapRootSecret=test-bootstrap

echo ""
echo "--- Database -----------------------------------------------"
render "with database" \
    --set config.database.hostname=postgres.default.svc.cluster.local

render "with database + RBAC" \
    --set config.database.hostname=postgres.default.svc.cluster.local \
    --set config.access.rbac.enabled=true

echo ""
echo "--- Auth ---------------------------------------------------"
render "with OIDC providers" \
    --set config.auth.providers[0].name=oidc \
    --set config.auth.providers[0].type=oidc \
    --set config.auth.providers[0].client_id=test-client \
    --set config.auth.providers[0].issuer=https://accounts.google.com

render "with rate limiting" \
    --set config.auth.login_rate_limit.enabled=true \
    --set config.auth.oauth_rate_limit.enabled=true

echo ""
echo "--- Server features ----------------------------------------"
render "with metrics enabled" \
    --set config.server.metrics.enabled=true

render "with TLS enabled" \
    --set config.server.tls.enabled=true

echo ""
echo "--- Kubernetes resources -----------------------------------"
render "with ingress" \
    --set ingress.enabled=true

render "with PDB" \
    --set podDisruptionBudget.enabled=true

render "with ServiceMonitor" \
    --set serviceMonitor.enabled=true \
    --set config.server.metrics.enabled=true

render "with namespaceOverride" \
    --set namespaceOverride=custom-namespace

echo ""
echo "--- Cache --------------------------------------------------"
render "with Redis cache" \
    --set config.cache.redis.addr=redis.default.svc.cluster.local:6379

echo ""
echo "--- Production-like ----------------------------------------"
render "full production config" \
    --set-string secrets.jwtSecret=prod-jwt-key \
    --set-string secrets.databasePassword=prod-db-pass \
    --set config.log.level=info \
    --set config.server.port=8088 \
    --set config.server.upstream=http://app.default.svc.cluster.local:8080 \
    --set config.server.hostname=auth.example.com \
    --set config.server.trust_forwarded_headers=true \
    --set config.database.hostname=postgres.default.svc.cluster.local \
    --set config.database.database_name=ezauth \
    --set config.access.rbac.enabled=true \
    --set config.access.bootstrap.system_admin_group=system-admins \
    --set config.auth.providers[0].name=oidc \
    --set config.auth.providers[0].type=oidc \
    --set config.auth.providers[0].client_id=prod-client \
    --set config.auth.providers[0].issuer=https://accounts.google.com \
    --set config.auth.login_rate_limit.enabled=true \
    --set config.auth.oauth_rate_limit.enabled=true \
    --set config.server.metrics.enabled=true \
    --set config.audit.enabled=true \
    --set ingress.enabled=true \
    --set podDisruptionBudget.enabled=true \
    --set replicaCount=2

echo ""
echo "=================================="
echo "Results: $PASS passed, $FAIL failed"
echo "=================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
