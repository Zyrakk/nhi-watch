#!/usr/bin/env bash
# setup-phase1-nhis.sh — Create test NHIs of EVERY type for Phase 1 validation.
#
# Creates:
#   - 3 ServiceAccounts (with different configs)
#   - 2 Opaque secrets with credential keys (1 stale, 1 fresh)
#   - 2 TLS secrets (1 valid, 1 expiring soon)
#   - 2 Legacy SA token secrets (1 stale)
#   - 1 Docker registry credential
#   - 2 cert-manager Certificates (requires cert-manager installed)
#   - 1 Opaque secret WITHOUT credential keys (should be SKIPPED)
#
# Usage:
#   ./scripts/setup-phase1-nhis.sh           # create everything
#   ./scripts/setup-phase1-nhis.sh clean     # remove everything
#   ./scripts/setup-phase1-nhis.sh no-cm     # create everything EXCEPT cert-manager

set -euo pipefail

NS="nhi-phase1-test"
SKIP_CERTMANAGER="${1:-}"

# ─── Colors ───
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── Helpers ───
header()  { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }
ok()      { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC} $1"; }

# ─── Generate self-signed TLS cert ───
generate_cert() {
    local cn="$1" days="$2" dir="$3"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${dir}/tls.key" -out "${dir}/tls.crt" \
        -days "$days" -nodes -subj "/CN=${cn}" \
        -addext "subjectAltName=DNS:${cn},DNS:*.${cn}" 2>/dev/null
}

# ═══════════════════════════════════════════════
#  CLEAN
# ═══════════════════════════════════════════════
clean() {
    header "Cleaning Phase 1 test resources"

    # Cluster-scoped resources
    kubectl delete clusterrolebinding nhi-p1-cluster-admin nhi-p1-wildcard --ignore-not-found 2>/dev/null
    kubectl delete clusterrole nhi-p1-wildcard --ignore-not-found 2>/dev/null

    # cert-manager certificates (ignore if CRD doesn't exist)
    kubectl -n "$NS" delete certificate web-cert internal-cert --ignore-not-found 2>/dev/null || true
    kubectl delete clusterissuer nhi-p1-selfsigned --ignore-not-found 2>/dev/null || true
    kubectl -n "$NS" delete issuer nhi-p1-ca-issuer --ignore-not-found 2>/dev/null || true

    # Namespace (deletes everything inside)
    kubectl delete namespace "$NS" --ignore-not-found

    ok "Cleanup complete"
}

# ═══════════════════════════════════════════════
#  CREATE
# ═══════════════════════════════════════════════
create() {
    header "Creating namespace: ${NS}"
    kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
    ok "Namespace ready"

    # ─── 1. ServiceAccounts ───
    header "ServiceAccounts (3)"

    # SA 1: cluster-admin binding (should score CRITICAL)
    kubectl -n "$NS" create serviceaccount overprivileged-sa --dry-run=client -o yaml | kubectl apply -f -
    cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: nhi-p1-cluster-admin
subjects:
  - kind: ServiceAccount
    name: overprivileged-sa
    namespace: ${NS}
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF
    ok "overprivileged-sa (cluster-admin binding)"

    # SA 2: wildcard permissions
    kubectl -n "$NS" create serviceaccount wildcard-sa --dry-run=client -o yaml | kubectl apply -f -
    cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nhi-p1-wildcard
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: nhi-p1-wildcard
subjects:
  - kind: ServiceAccount
    name: wildcard-sa
    namespace: ${NS}
roleRef:
  kind: ClusterRole
  name: nhi-p1-wildcard
  apiGroup: rbac.authorization.k8s.io
EOF
    ok "wildcard-sa (wildcard permissions)"

    # SA 3: secure SA with automount disabled
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secure-sa
  namespace: ${NS}
automountServiceAccountToken: false
EOF
    ok "secure-sa (automount=false)"

    # ─── 2. Opaque Secrets with credential keys ───
    header "Secret Credentials (2 + 1 non-credential)"

    # Fresh credential secret
    kubectl -n "$NS" create secret generic app-database-creds \
        --from-literal=db-password=FAKE-DO-NOT-USE \
        --from-literal=api-key=sk-test-FAKE \
        --from-literal=hostname=db.internal \
        --dry-run=client -o yaml | kubectl apply -f -
    ok "app-database-creds (fresh, keys: db-password, api-key)"

    # Stale credential secret (we'll backdate it with annotation since we can't change creationTimestamp)
    kubectl -n "$NS" create secret generic legacy-api-credentials \
        --from-literal=aws_access_key=AKIAIOSFODNN7FAKE \
        --from-literal=aws_secret_access_key=wJalrXUtnFEMI/FAKE \
        --from-literal=client_secret=cs-fake-old \
        --from-literal=connection-string=postgresql://fake \
        --dry-run=client -o yaml | kubectl apply -f -
    ok "legacy-api-credentials (keys: aws_access_key, aws_secret_access_key, client_secret, connection-string)"

    # Non-credential opaque secret (should be SKIPPED by discovery)
    kubectl -n "$NS" create secret generic app-config \
        --from-literal=config.yaml="log_level: debug" \
        --from-literal=hostname=app.internal \
        --from-literal=port=8080 \
        --dry-run=client -o yaml | kubectl apply -f -
    ok "app-config (no credential keys — should NOT appear in discover)"

    # ─── 3. TLS Secrets ───
    header "TLS Certificates (2)"

    TMPDIR=$(mktemp -d)

    # Valid TLS cert (1 year)
    generate_cert "app.example.com" 365 "$TMPDIR"
    kubectl -n "$NS" create secret tls valid-tls-cert \
        --cert="${TMPDIR}/tls.crt" --key="${TMPDIR}/tls.key" \
        --dry-run=client -o yaml | kubectl apply -f -
    ok "valid-tls-cert (CN=app.example.com, expires in 365d)"

    # Expiring-soon TLS cert (7 days)
    generate_cert "expiring.example.com" 7 "$TMPDIR"
    kubectl -n "$NS" create secret tls expiring-tls-cert \
        --cert="${TMPDIR}/tls.crt" --key="${TMPDIR}/tls.key" \
        --dry-run=client -o yaml | kubectl apply -f -
    ok "expiring-tls-cert (CN=expiring.example.com, expires in 7d ⚠)"

    rm -rf "$TMPDIR"

    # ─── 4. Legacy SA Token Secrets ───
    header "SA Token Secrets (2)"

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: legacy-sa-token-fresh
  namespace: ${NS}
  annotations:
    kubernetes.io/service-account.name: overprivileged-sa
type: kubernetes.io/service-account-token
data:
  token: $(echo -n "fake-token-data" | base64)
  ca.crt: $(echo -n "fake-ca-cert" | base64)
  namespace: $(echo -n "${NS}" | base64)
EOF
    ok "legacy-sa-token-fresh (linked to overprivileged-sa)"

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: legacy-sa-token-old
  namespace: ${NS}
  annotations:
    kubernetes.io/service-account.name: wildcard-sa
type: kubernetes.io/service-account-token
data:
  token: $(echo -n "fake-old-token" | base64)
  ca.crt: $(echo -n "fake-ca" | base64)
  namespace: $(echo -n "${NS}" | base64)
EOF
    ok "legacy-sa-token-old (linked to wildcard-sa)"

    # ─── 5. Registry Credential ───
    header "Registry Credentials (1)"

    kubectl -n "$NS" create secret docker-registry fake-registry-cred \
        --docker-server=registry.example.com \
        --docker-username=ci-robot \
        --docker-password=FAKE-PASS-DO-NOT-USE \
        --docker-email=ci@example.com \
        --dry-run=client -o yaml | kubectl apply -f -
    ok "fake-registry-cred (registry.example.com)"

    # ─── 6. cert-manager Certificates ───
    if [[ "$SKIP_CERTMANAGER" == "no-cm" ]]; then
        warn "Skipping cert-manager resources (no-cm flag)"
    else
        header "cert-manager Certificates (2)"

        # Check if cert-manager is installed
        if kubectl get crd certificates.cert-manager.io &>/dev/null; then
            # Create a self-signed ClusterIssuer for testing
            cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: nhi-p1-selfsigned
spec:
  selfSigned: {}
EOF
            ok "ClusterIssuer: nhi-p1-selfsigned"

            # Certificate 1: web cert with multiple SANs
            cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: web-cert
  namespace: ${NS}
spec:
  secretName: web-cert-tls
  issuerRef:
    name: nhi-p1-selfsigned
    kind: ClusterIssuer
  duration: 8760h   # 1 year
  renewBefore: 720h  # 30 days
  dnsNames:
    - web.example.com
    - www.example.com
    - api.example.com
EOF
            ok "web-cert (3 SANs, ClusterIssuer:nhi-p1-selfsigned)"

            # Certificate 2: internal short-lived cert
            cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: internal-cert
  namespace: ${NS}
spec:
  secretName: internal-cert-tls
  issuerRef:
    name: nhi-p1-selfsigned
    kind: ClusterIssuer
  duration: 168h    # 7 days
  renewBefore: 24h  # 1 day
  dnsNames:
    - internal.svc.cluster.local
EOF
            ok "internal-cert (short-lived, 7d duration)"

            # Wait a few seconds for cert-manager to issue
            echo -e "\n  Waiting 10s for cert-manager to issue certificates..."
            sleep 10

            # Check status
            for cert in web-cert internal-cert; do
                ready=$(kubectl -n "$NS" get certificate "$cert" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
                if [[ "$ready" == "True" ]]; then
                    ok "$cert → Ready"
                else
                    warn "$cert → Not ready yet (status: $ready). cert-manager may still be processing."
                fi
            done
        else
            warn "cert-manager not installed — skipping Certificate resources"
            warn "Install with: kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml"
        fi
    fi

    # ─── Summary ───
    header "Done! Test NHIs created in namespace: ${NS}"
    echo ""
    echo "  Run these commands to validate:"
    echo ""
    echo "  # All NHIs"
    echo "  ./bin/nhi-watch discover -n ${NS} -v"
    echo ""
    echo "  # By type"
    echo "  ./bin/nhi-watch discover -n ${NS} --type service-account"
    echo "  ./bin/nhi-watch discover -n ${NS} --type secret-credential"
    echo "  ./bin/nhi-watch discover -n ${NS} --type tls-certificate"
    echo "  ./bin/nhi-watch discover -n ${NS} --type sa-token"
    echo "  ./bin/nhi-watch discover -n ${NS} --type registry-credential"
    echo "  ./bin/nhi-watch discover -n ${NS} --type cert-manager-certificate"
    echo ""
    echo "  # Stale filter"
    echo "  ./bin/nhi-watch discover -n ${NS} --stale"
    echo ""
    echo "  # JSON output"
    echo "  ./bin/nhi-watch discover -n ${NS} -o json | jq '.identities | group_by(.type) | map({type: .[0].type, count: length})'"
    echo ""
    echo "  # Expected totals:"
    echo "    service-account            4  (3 created + 1 default)"
    echo "    secret-credential          2"
    echo "    tls-certificate            2  (+2 if cert-manager issued its TLS secrets)"
    echo "    sa-token                   2"
    echo "    registry-credential        1"
    echo "    cert-manager-certificate   2  (if cert-manager installed)"
    echo "    ---"
    echo "    TOTAL                     ~13-15"
    echo ""
    echo "  # Cleanup when done:"
    echo "  ./scripts/setup-phase1-nhis.sh clean"
}

# ─── Dispatch ───
case "${1:-create}" in
    create) create ;;
    no-cm)  create ;;
    clean)  clean ;;
    *)      echo "Usage: $0 [create|clean|no-cm]"; exit 1 ;;
esac
