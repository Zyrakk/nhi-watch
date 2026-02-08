# NHI-Watch

**Discover, audit, and score Non-Human Identities in Kubernetes & OpenShift.**

NHI-Watch is a security CLI that enumerates all Non-Human Identities in your cluster, analyzes their RBAC permissions, and assigns a deterministic risk score to help you harden your workload identity posture.

A Non-Human Identity (NHI) is any credential that allows a process, service, or machine to authenticate and perform actions without human intervention. In Kubernetes this includes:

- **ServiceAccounts** — automatic identities assigned to every pod. Helm charts and operators create them with frequently excessive permissions that nobody audits post-install.
- **Secrets with credentials** — API keys, tokens, database passwords, registry credentials stored as Kubernetes Secrets, often in plaintext (base64 is not encryption) and without rotation policies.
- **TLS certificates** — issued by cert-manager or other mechanisms; each certificate is an identity with private keys in Secrets and expiration dates that must be monitored.
- **Agent identities** — credentials used by monitoring agents (Wazuh, Falco, Datadog), network agents (WireGuard), or remote management tools (ZCloud device keys, JWT tokens).
- **Cloud credentials** — instance principals, cloud provider API keys (AWS, OCI, Azure) stored in the cluster for integrations.

NHIs outnumber human identities 17:1 in large organizations and are the fastest-growing attack vector in cloud-native environments.

## Current Status

**Phase 2 — RBAC Permission Resolution** ✅

| Phase | Description | Status |
|-------|-------------|--------|
| **Phase 0** | Project structure, CLI skeleton, SA discovery PoC | ✅ Done |
| **Phase 1** | Full NHI discovery (Secrets, TLS certs, cert-manager) | ✅ Done |
| **Phase 2** | RBAC permission mapping and scope analysis | ✅ Current |
| Phase 3 | Risk scoring engine (deterministic, YAML-configurable) | 🔜 Next |
| Phase 4 | Audit log usage analysis (permissions vs actual use) | Planned |
| Phase 5 | Assisted remediation (minimal RBAC generation, dry-run) | Planned |
| Phase 6 | OpenShift extensions, Goreleaser, Helm chart | Planned |

## Quick Start

### Prerequisites

- Go 1.22+
- Access to a Kubernetes, k3s, or OpenShift cluster (`~/.kube/config`)

### Install from Source

```bash
git clone https://github.com/Zyrakk/nhi-watch.git
cd nhi-watch
go mod tidy
make build
```

The binary is placed in `./bin/nhi-watch`.

### Usage

```bash
# Discover all NHIs across the cluster
./bin/nhi-watch discover

# Filter by namespace
./bin/nhi-watch discover -n kube-system

# Filter by NHI type
./bin/nhi-watch discover --type tls-certificate

# Show only stale credentials (> 90 days without rotation)
./bin/nhi-watch discover --stale

# JSON output (pipe to jq, feed to SIEM, etc.)
./bin/nhi-watch discover -o json

# Analyze RBAC permissions for all ServiceAccounts
./bin/nhi-watch permissions

# Detail view for a specific ServiceAccount
./bin/nhi-watch permissions traefik -n kube-system

# Show only overprivileged ServiceAccounts
./bin/nhi-watch permissions --overprivileged

# Filter by permission scope
./bin/nhi-watch permissions --scope cluster-wide

# Permissions as JSON
./bin/nhi-watch permissions -o json

# Use a specific kubeconfig or context
./bin/nhi-watch discover --kubeconfig /path/to/config --context my-cluster

# Verbose mode
./bin/nhi-watch discover -v
```

### Example Output — Discovery

```
Cluster: zcloud-k3s
Scan time: 2026-02-08T15:30:00Z

NAMESPACE        NAME                    TYPE                        SOURCE                  DETAIL                          AGE
kube-system      default                 service-account             unknown                 automount=default (true)        180d
kube-system      traefik                 service-account             helm-chart:traefik-39   automount=false                 180d
kube-system      coredns                 service-account             Helm:coredns            automount=false                 180d
production       app-backend             service-account             argocd                  automount=false                 45d
cert-manager     letsencrypt-prod-tls    tls-certificate             cert-manager            CN=*.example.com expires=89d    30d
monitoring       wazuh-api-key           secret-credential           unknown                 keys=[api-key] stale ⚠          120d
ci               registry-creds          registry-credential         unknown                 stale ⚠                         200d

  service-account              4
  tls-certificate              1
  secret-credential            1
  registry-credential          1
  ---
  TOTAL NHIs                   7
  STALE (>90d)                 2 ⚠
```

### Example Output — Permissions

```
Cluster: zcloud-k3s

NAMESPACE        NAME                            SCOPE         BINDINGS  FLAGS
cert-manager     cert-manager                    cluster-wide  9         SECRET_ACCESS_CLUSTER_WIDE, CROSS_NAMESPACE_SECRET_ACCESS
kube-system      generic-garbage-collector       cluster-wide  2         WILDCARD_RESOURCES, WILDCARD_APIGROUPS
kube-system      local-path-provisioner-sa       cluster-wide  2         WILDCARD_VERBS
kube-system      traefik                         cluster-wide  2         SECRET_ACCESS_CLUSTER_WIDE, CROSS_NAMESPACE_SECRET_ACCESS
kube-system      default                         cluster-wide  1         DEFAULT_SA_HAS_BINDINGS
monitoring       kube-state-metrics              cluster-wide  2         SECRET_ACCESS_CLUSTER_WIDE, CROSS_NAMESPACE_SECRET_ACCESS

  cluster-wide             6
  ---
  TOTAL                    6
  FLAGGED                  6
```

### Example Output — Permission Detail

```
ServiceAccount: traefik (kube-system)
Created: 2026-02-05
Source: helm-chart:traefik-39.0.0

RBAC Bindings:
  ClusterRoleBinding "traefik-kube-system" → ClusterRole "traefik-kube-system"
    - configmaps, nodes, services: [get, list, watch]
    - endpointslices: [list, watch]
    - pods: [get]
    - secrets: [get, list, watch]     ⚠ cluster-wide secret access
    - ingressclasses, ingresses: [get, list, watch]
    - ingresses/status: [update]
    - namespaces: [list, watch]
    - ingressroutes, middlewares, ...: [get, list, watch]

Scope: CLUSTER-WIDE
Flags: SECRET_ACCESS_CLUSTER_WIDE, CROSS_NAMESPACE_SECRET_ACCESS
```

## Commands

| Command       | Status      | Description                                       |
|---------------|-------------|---------------------------------------------------|
| `discover`    | ✅ Working  | Enumerate all NHIs (SAs, Secrets, TLS, cert-manager) |
| `permissions` | ✅ Working  | Resolve RBAC bindings, scope, and overprivilege flags |
| `audit`       | 🔜 Phase 3  | Full audit with risk scoring and remediation hints |
| `version`     | ✅ Working  | Print version info                                 |

## Overprivilege Detection

The `permissions` command detects 7 overprivilege patterns:

| Flag | Description |
|------|-------------|
| `CLUSTER_ADMIN` | ServiceAccount bound to the `cluster-admin` ClusterRole |
| `WILDCARD_VERBS` | Rule with `*` in verbs (full CRUD on resources) |
| `WILDCARD_RESOURCES` | Rule with `*` in resources (access to all resource types) |
| `WILDCARD_APIGROUPS` | Rule with `*` in apiGroups (access across all API groups) |
| `SECRET_ACCESS_CLUSTER_WIDE` | Can read Secrets via ClusterRoleBinding (all namespaces) |
| `DEFAULT_SA_HAS_BINDINGS` | Default ServiceAccount has non-default bindings |
| `CROSS_NAMESPACE_SECRET_ACCESS` | Can read Secrets outside its own namespace |

Scope classification:

| Scope | Meaning |
|-------|---------|
| `CLUSTER-WIDE` | Has ClusterRoleBinding with non-view verbs |
| `NAMESPACE-SCOPED` | Only RoleBindings with non-view verbs |
| `MINIMAL` | Only view verbs (get, list, watch) |
| `NONE` | No bindings found |

## Project Structure

```
nhi-watch/
├── cmd/nhi-watch/
│   └── main.go                      # Entry point
├── internal/
│   ├── cli/                         # Cobra command tree
│   │   ├── root.go                  #   Root command + global flags
│   │   ├── discover.go              #   discover subcommand
│   │   ├── permissions.go           #   permissions subcommand
│   │   ├── audit.go                 #   audit subcommand (stub)
│   │   └── version.go               #   version subcommand
│   ├── k8s/                         # Shared Kubernetes client
│   │   └── client.go                #   kubeconfig / in-cluster / context
│   ├── models/                      # Shared types across packages
│   │   └── permissions.go           #   PermissionSet, BindingRef, ResolvedRule
│   ├── discovery/                   # NHI enumeration logic
│   │   ├── types.go                 #   NonHumanIdentity model + NHI types
│   │   ├── serviceaccounts.go       #   SA discovery with source detection
│   │   ├── serviceaccounts_test.go  #   Tests with fake clientset
│   │   ├── secrets.go               #   Secret discovery (credentials, TLS, tokens)
│   │   └── certificates.go          #   cert-manager Certificate discovery
│   ├── permissions/                 # RBAC analysis (Phase 2)
│   │   ├── resolver.go              #   RBAC cache + binding resolution
│   │   ├── resolver_test.go         #   11 tests (direct, group, multi-binding)
│   │   ├── analyzer.go              #   7 overprivilege flag detectors + scope
│   │   └── analyzer_test.go         #   16 tests (each flag + scope classification)
│   ├── scoring/                     # Risk scoring engine (Phase 3)
│   │   └── scoring.go               #   Severity levels, rule IDs, Finding
│   └── reporter/                    # Report generation (future)
│       └── reporter.go
├── configs/
│   └── scoring-rules.yaml           # Deterministic scoring rules (Phase 3)
├── scripts/                         # Helper scripts
├── .github/workflows/ci.yml         # GitHub Actions CI (lint + test)
├── .golangci.yml                    # Linter configuration
├── Makefile                         # build, test, lint, run, clean
└── go.mod
```

## Development

```bash
make build     # Compile binary to ./bin/nhi-watch
make test      # Run all tests with race detection
make lint      # Run golangci-lint (requires golangci-lint installed)
make fmt       # Format all Go source files
make vet       # Run go vet
make run       # Build + run discover against current kubeconfig
make run-json  # Same as run, JSON output
make clean     # Remove build artifacts
```

## Compatibility

| Platform   | Status |
|------------|--------|
| Kubernetes | ✅ Compatible |
| k3s        | ✅ Compatible |
| OpenShift  | ✅ Compatible (core/v1 + rbac/v1 APIs) |

NHI-Watch uses standard Kubernetes APIs and does not require cluster-admin for basic discovery. A read-only ClusterRole is sufficient:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nhi-watch-reader
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts", "secrets"]
    verbs: ["get", "list"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings", "clusterrolebindings", "roles", "clusterroles"]
    verbs: ["get", "list"]
  - apiGroups: ["cert-manager.io"]
    resources: ["certificates", "certificaterequests"]
    verbs: ["get", "list"]
```

## Why NHI-Watch?

| Aspect | HashiCorp Vault | Commercial (Astrix, Oasis) | NHI-Watch |
|--------|----------------|---------------------------|-----------|
| Secure secret storage | ✅ Core | ❌ Not focus | ❌ Not focus |
| NHI discovery in K8s | ❌ No | ✅ Yes | ✅ Yes |
| RBAC permission resolution | ❌ No | ⚠️ Partial | ✅ Full chain |
| Configurable risk scoring | ❌ No | ✅ Proprietary | ✅ Open (YAML) |
| Usage analysis | ❌ No | ✅ Yes | ✅ Via audit logs |
| Open source | ✅ Yes | ❌ No | ✅ Yes |
| Kubernetes-native | ❌ Generic | ⚠️ Multi-cloud | ✅ K8s-native |

NHI-Watch doesn't replace Vault — it covers the gap that neither Vault nor commercial solutions fill: discovery and auditing of NHIs natively in Kubernetes, with a deterministic, open-source, and auditable approach.

## Related Projects

- [ZCloud](https://github.com/Zyrakk/zcloud) — Human identity management for k3s remote access. NHI-Watch is an independent project with optional ZCloud integration planned for Phase 6.

## License

MIT