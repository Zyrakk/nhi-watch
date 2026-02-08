#!/usr/bin/env bash
# setup-test-nhis.sh — Create intentionally "bad" NHIs for testing NHI-Watch.
#
# From the roadmap (Phase 0.3):
#   "Crear intencionalmente 2-3 NHIs 'malas' para validar la detección:
#    un ServiceAccount con cluster-admin que no se use, un Secret viejo
#    sin rotar, un RoleBinding sobredimensionado."
#
# Usage:
#   ./scripts/setup-test-nhis.sh        # create test resources
#   ./scripts/setup-test-nhis.sh clean   # remove test resources

set -euo pipefail

NAMESPACE="nhi-watch-test"

create() {
    echo "[*] Creating test namespace: ${NAMESPACE}"
    kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

    echo "[*] Creating SA with cluster-admin binding (should score CRITICAL)"
    kubectl -n "${NAMESPACE}" create serviceaccount overprivileged-sa --dry-run=client -o yaml | kubectl apply -f -
    cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: nhi-watch-test-cluster-admin
subjects:
  - kind: ServiceAccount
    name: overprivileged-sa
    namespace: ${NAMESPACE}
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF

    echo "[*] Creating old Secret without rotation (should score HIGH)"
    kubectl -n "${NAMESPACE}" create secret generic stale-api-key \
        --from-literal=api-key=sk-test-FAKE-KEY-DO-NOT-USE \
        --from-literal=password=hunter2 \
        --dry-run=client -o yaml | kubectl apply -f -

    echo "[*] Creating binding on default SA (should score HIGH)"
    cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: nhi-watch-test-default-sa-binding
  namespace: ${NAMESPACE}
subjects:
  - kind: ServiceAccount
    name: default
    namespace: ${NAMESPACE}
roleRef:
  kind: ClusterRole
  name: edit
  apiGroup: rbac.authorization.k8s.io
EOF

    echo "[*] Creating SA with wildcard permissions (should score HIGH)"
    kubectl -n "${NAMESPACE}" create serviceaccount wildcard-sa --dry-run=client -o yaml | kubectl apply -f -
    cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nhi-watch-test-wildcard
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: nhi-watch-test-wildcard
subjects:
  - kind: ServiceAccount
    name: wildcard-sa
    namespace: ${NAMESPACE}
roleRef:
  kind: ClusterRole
  name: nhi-watch-test-wildcard
  apiGroup: rbac.authorization.k8s.io
EOF

    echo ""
    echo "[✓] Test NHIs created. Run: ./bin/nhi-watch discover -n ${NAMESPACE}"
}

clean() {
    echo "[*] Cleaning up test resources..."
    kubectl delete clusterrolebinding nhi-watch-test-cluster-admin --ignore-not-found
    kubectl delete clusterrolebinding nhi-watch-test-wildcard --ignore-not-found
    kubectl delete clusterrole nhi-watch-test-wildcard --ignore-not-found
    kubectl delete namespace "${NAMESPACE}" --ignore-not-found
    echo "[✓] Cleanup complete."
}

case "${1:-create}" in
    create) create ;;
    clean)  clean ;;
    *)      echo "Usage: $0 [create|clean]"; exit 1 ;;
esac
