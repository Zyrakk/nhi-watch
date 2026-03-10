# NHI-Watch

**Discover, audit, and score Non-Human Identities in Kubernetes & OpenShift.**

NHI-Watch is a security CLI that enumerates all Non-Human Identities (NHIs) in your cluster, analyzes their RBAC permissions, and assigns a deterministic risk score mapped to CIS Kubernetes Benchmarks.

Non-Human Identities include ServiceAccounts, Secrets (API keys, tokens, passwords), TLS certificates, cert-manager Certificates, registry credentials, and agent/cloud provider credentials. NHIs outnumber human identities 17:1 in large organizations and are the fastest-growing attack vector in cloud-native environments.

## Quick Start

### Install from Binary

```bash
curl -sSL https://raw.githubusercontent.com/Zyrakk/nhi-watch/main/scripts/install.sh | bash
```

Or specify a version:

```bash
curl -sSL https://raw.githubusercontent.com/Zyrakk/nhi-watch/main/scripts/install.sh | bash -s v1.0.0
```

### Docker

```bash
docker run --rm -v ~/.kube/config:/home/nonroot/.kube/config:ro \
  ghcr.io/zyrakk/nhi-watch:latest audit -o json
```

### Helm

```bash
helm install nhi-watch charts/nhi-watch \
  --set audit.failOn=critical \
  --set schedule="0 2 * * *"
```

The Helm chart deploys a CronJob that runs `nhi-watch audit` on a schedule. See `charts/nhi-watch/values.yaml` for all options.

### Build from Source

```bash
git clone https://github.com/Zyrakk/nhi-watch.git
cd nhi-watch
make build    # binary at ./bin/nhi-watch
```

## Commands

### discover

Enumerate all NHIs across the cluster.

```bash
nhi-watch discover                          # All NHIs, all namespaces
nhi-watch discover -n kube-system           # Single namespace
nhi-watch discover --type service-account   # Filter by NHI type
nhi-watch discover --stale                  # Credentials > 90 days old
nhi-watch discover -o json                  # JSON output
```

NHI types: `service-account`, `secret-credential`, `tls-certificate`, `cert-manager-cert`, `registry-credential`, `legacy-sa-token`.

### permissions

Analyze RBAC bindings, scope, and overprivilege flags for ServiceAccounts.

```bash
nhi-watch permissions                           # All ServiceAccounts
nhi-watch permissions traefik -n kube-system    # Single SA detail view
nhi-watch permissions --overprivileged          # Only flagged SAs
nhi-watch permissions --scope cluster-wide      # Filter by scope
nhi-watch permissions -o json                   # JSON output
```

**Overprivilege flags:**

| Flag | Description |
|------|-------------|
| `CLUSTER_ADMIN` | Bound to cluster-admin ClusterRole |
| `WILDCARD_VERBS` | Rule with `*` in verbs |
| `WILDCARD_RESOURCES` | Rule with `*` in resources |
| `WILDCARD_APIGROUPS` | Rule with `*` in apiGroups |
| `SECRET_ACCESS_CLUSTER_WIDE` | Can read Secrets via ClusterRoleBinding |
| `DEFAULT_SA_HAS_BINDINGS` | Default SA has non-default bindings |
| `CROSS_NAMESPACE_SECRET_ACCESS` | Can read Secrets outside its namespace |

**Scope classification:** `CLUSTER-WIDE` | `NAMESPACE-SCOPED` | `MINIMAL` | `NONE`

### audit

Full security audit with risk scoring, CIS Benchmark mapping, and remediation hints.

```bash
nhi-watch audit                             # Table output to terminal
nhi-watch audit -o json                     # JSON for SIEM/jq
nhi-watch audit -o sarif                    # SARIF for GitHub Security tab
nhi-watch audit --severity high             # Only HIGH and CRITICAL
nhi-watch audit --type service-account      # Filter by NHI type
```

### remediate

Generate least-privilege RBAC YAML proposals for known workloads.

```bash
nhi-watch remediate traefik -n kube-system              # Single workload
nhi-watch remediate --all                               # All known workloads
nhi-watch remediate --all --output-dir=./fixes/          # Write files
nhi-watch remediate traefik --dry-run=false --output-dir=./fixes/
```

Supported workloads: **Traefik** (ingress controller), **cert-manager** (certificate management). Generated YAML is marked as PROPOSAL and must be reviewed before applying.

### policy export

Generate OPA/Gatekeeper ConstraintTemplates from scoring rules for admission-time enforcement.

```bash
nhi-watch policy export                             # All templates to stdout
nhi-watch policy export --format=gatekeeper         # Explicit format
nhi-watch policy export --output-dir=./policies/    # Write individual files
```

Exported rules:

| Rule | CIS Control | What it blocks |
|------|-------------|----------------|
| `CLUSTER_ADMIN_BINDING` | 5.1.1 | cluster-admin bindings |
| `WILDCARD_PERMISSIONS` | 5.1.3 | Wildcard verb/resource permissions |
| `DEFAULT_SA_HAS_BINDINGS` | 5.1.5 | Bindings to default ServiceAccount |
| `SECRET_ACCESS_CLUSTER_WIDE` | 5.1.2 | Cluster-wide secret access |
| `AUTOMOUNT_TOKEN_ENABLED` | 5.1.6 | Automounted SA tokens |

## Output Formats

| Format | Flag | Use case |
|--------|------|----------|
| Table | `-o table` (default) | Terminal display with severity grouping |
| JSON | `-o json` | jq, SIEM pipelines, CI/CD integration |
| SARIF | `-o sarif` | GitHub Code Scanning / Security tab |

### SARIF Upload to GitHub

```yaml
# .github/workflows/nhi-audit.yml
- name: Run NHI-Watch audit
  run: nhi-watch audit -o sarif > nhi-watch.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: nhi-watch.sarif
```

## CI/CD Integration

### Pipeline Gating with --fail-on

Exit code 2 when findings meet or exceed a severity threshold:

```bash
nhi-watch audit --fail-on=high -o json      # Fail on HIGH or CRITICAL
nhi-watch audit --fail-on=critical -o json   # Fail on CRITICAL only
```

### Baseline Tracking

Save a baseline, then only fail on new or regressed findings:

```bash
# Save initial baseline
nhi-watch audit --save-baseline=baseline.json -o json

# CI pipeline: compare against baseline
nhi-watch audit --baseline=baseline.json --fail-on=high -o json
```

Using `--baseline` with `--fail-on` only triggers a failure for findings that are new or have regressed since the baseline was captured. Unchanged findings are ignored.

### GitHub Actions Example

```yaml
jobs:
  nhi-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install nhi-watch
        run: curl -sSL https://raw.githubusercontent.com/Zyrakk/nhi-watch/main/scripts/install.sh | bash

      - name: Run audit
        run: |
          nhi-watch audit --fail-on=high \
            --baseline=baseline.json \
            --save-baseline=baseline.json \
            -o sarif > nhi-watch.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: nhi-watch.sarif
```

## Risk Scoring

16 deterministic rules applied to every NHI. No AI/ML — pure deterministic, reproducible, and auditable. Each rule produces a score from 0-100; the final score is the maximum of all matching rules, adjusted by a pod security posture multiplier.

### Severity Levels

| Severity | Score Range |
|----------|-------------|
| CRITICAL | 80-100 |
| HIGH | 60-79 |
| MEDIUM | 40-59 |
| LOW | 20-39 |
| INFO | 0-19 |

### Scoring Rules

**ServiceAccount rules:**

| Rule ID | CIS | Score | Description |
|---------|-----|-------|-------------|
| `CLUSTER_ADMIN_BINDING` | 5.1.1 | 95 | SA bound to cluster-admin |
| `DEFAULT_SA_HAS_BINDINGS` | 5.1.5 | 85 | Default SA has additional bindings |
| `WILDCARD_PERMISSIONS` | 5.1.3 | 80 | Wildcard (`*`) in verbs or resources |
| `SECRET_ACCESS_CLUSTER_WIDE` | 5.1.2 | 70 | Can read Secrets cluster-wide |
| `CROSS_NAMESPACE_SECRET_ACCESS` | — | 65 | Can read Secrets outside its namespace |
| `AUTOMOUNT_TOKEN_ENABLED` | 5.1.6 | 30 | automountServiceAccountToken not disabled |
| `NO_BINDINGS_BUT_AUTOMOUNT` | — | 20 | No bindings but automount is on |

**Secret rules:**

| Rule ID | Score | Description |
|---------|-------|-------------|
| `TLS_CERT_EXPIRED` | 95 | TLS certificate is expired |
| `SECRET_NOT_ROTATED_180D` | 90 | Secret not rotated in 180+ days |
| `SECRET_NOT_ROTATED_90D` | 75 | Secret not rotated in 90+ days |
| `TLS_CERT_EXPIRES_30D` | 75 | TLS certificate expires within 30 days |
| `CONTAINS_PRIVATE_KEY` | 60 | Secret contains a private key |
| `TLS_CERT_EXPIRES_90D` | 45 | TLS certificate expires within 90 days |

**cert-manager rules:**

| Rule ID | Score | Description |
|---------|-------|-------------|
| `CERT_NOT_READY` | 80 | Certificate is not in Ready state |
| `CERT_EXPIRES_30D` | 70 | Certificate expires within 30 days |
| `CERT_EXPIRES_90D` | 40 | Certificate expires within 90 days |

### CIS Kubernetes Benchmark Mapping

Rules are mapped to CIS Kubernetes Benchmark v1.8 controls where applicable. CIS control IDs appear in JSON/SARIF output and in Gatekeeper policy annotations.

### Pod Security Posture Multiplier

NHI-Watch discovers pod security context for ServiceAccounts and applies a risk multiplier when insecure settings are found:

| Posture Signal | Effect |
|----------------|--------|
| Privileged containers | Increases risk score |
| hostNetwork / hostPID / hostIPC | Increases risk score |
| Running as root | Increases risk score |
| No security context | Increases risk score |

The multiplier adjusts the base score: `final_score = min(base_score * multiplier, 100)`. In JSON output, findings include `base_score`, `posture_multiplier`, and `final_score` fields.

## OpenShift Support

NHI-Watch detects OpenShift clusters and discovers SecurityContextConstraints (SCC) assigned to ServiceAccounts. SCC names appear in pod posture data when running on OpenShift.

On non-OpenShift clusters (Kubernetes, k3s), SCC fields are omitted.

## Project Structure

```
nhi-watch/
├── cmd/nhi-watch/main.go           # Entry point
├── internal/
│   ├── cli/                        # Cobra command tree
│   │   ├── root.go                 #   Root + global flags
│   │   ├── discover.go             #   discover command
│   │   ├── permissions.go          #   permissions command
│   │   ├── audit.go                #   audit command
│   │   ├── remediate.go            #   remediate command
│   │   ├── policy.go               #   policy export command
│   │   └── version.go              #   version command
│   ├── k8s/                        # Shared Kubernetes client
│   ├── models/                     # Shared types
│   ├── discovery/                  # NHI enumeration
│   ├── permissions/                # RBAC analysis
│   ├── scoring/                    # Risk scoring engine + rules
│   ├── reporter/                   # Table / JSON / SARIF output
│   ├── baseline/                   # Baseline save/load/diff
│   ├── remediation/                # YAML remediation generation
│   └── policy/                     # Gatekeeper ConstraintTemplate export
├── charts/nhi-watch/               # Helm chart
├── scripts/install.sh              # Install script
├── Dockerfile                      # Multi-stage distroless image
├── .goreleaser.yml                 # GoReleaser configuration
├── .github/workflows/
│   ├── ci.yml                      # CI (lint + test)
│   └── release.yml                 # Release workflow
├── Makefile
└── go.mod
```

## Compatibility

| Platform | Status |
|----------|--------|
| Kubernetes | Supported |
| k3s | Supported |
| OpenShift | Supported (core/v1 + rbac/v1 + security.openshift.io/v1) |

## Required ClusterRole

NHI-Watch requires read-only access. No write verbs needed.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nhi-watch-reader
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts", "secrets", "pods"]
    verbs: ["get", "list"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings", "clusterrolebindings", "roles", "clusterroles"]
    verbs: ["get", "list"]
  - apiGroups: ["cert-manager.io"]
    resources: ["certificates", "certificaterequests"]
    verbs: ["get", "list"]
  - apiGroups: ["security.openshift.io"]
    resources: ["securitycontextconstraints"]
    verbs: ["get", "list"]
```

## Development

```bash
make build     # Compile binary to ./bin/nhi-watch
make test      # Run all tests with race detection
make lint      # Run golangci-lint
make fmt       # Format all Go source files
make vet       # Run go vet
make clean     # Remove build artifacts
```

## License

Copyright 2026 Stefan Contreras

Licensed under the Apache License, Version 2.0
