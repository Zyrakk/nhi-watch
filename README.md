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

**Phase 0 — Foundation & Proof of Concept** ✅

| Phase | Description | Status |
|-------|-------------|--------|
| **Phase 0** | Project structure, CLI skeleton, SA discovery PoC | ✅ Current |
| Phase 1 | Full NHI discovery (Secrets, certs, agents) | 🔜 Next |
| Phase 2 | RBAC permission mapping and scope analysis | Planned |
| Phase 3 | Risk scoring engine (deterministic, YAML-configurable) | Planned |
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
# Discover all ServiceAccounts across the cluster
./bin/nhi-watch discover

# Filter by namespace
./bin/nhi-watch discover -n kube-system

# JSON output (pipe to jq, feed to SIEM, etc.)
./bin/nhi-watch discover -o json

# Use a specific kubeconfig or context
./bin/nhi-watch discover --kubeconfig /path/to/config --context my-cluster

# Verbose mode
./bin/nhi-watch discover -v
```

### Example Output

```
Cluster: zcloud-k3s
Scan time: 2026-02-08T15:30:00Z

NAMESPACE        NAME                    TYPE              SOURCE                  AUTOMOUNT    AGE
kube-system      default                 service-account   unknown                 default (true)  180d
kube-system      traefik                 service-account   helm-chart:traefik-25   false        180d
kube-system      coredns                 service-account   Helm:coredns            false        180d
production       app-backend             service-account   argocd                  false        45d
production       default                 service-account   unknown                 default (true)  90d
ci               jenkins-deployer        service-account   unknown                 true         30d
monitoring       wazuh-agent             service-account   Helm:wazuh              true         60d

  service-account          7
  ---
  TOTAL NHIs               7
```

## Commands

| Command       | Status      | Description                                       |
|---------------|-------------|---------------------------------------------------|
| `discover`    | ✅ Working  | Enumerate NHIs (Phase 0: ServiceAccounts)          |
| `permissions` | 🔜 Phase 2  | Resolve RBAC bindings and effective permissions    |
| `audit`       | 🔜 Phase 3  | Full audit with risk scoring and remediation hints |
| `version`     | ✅ Working  | Print version info                                 |

## Project Structure

```
nhi-watch/
├── cmd/nhi-watch/
│   └── main.go                      # Entry point
├── internal/
│   ├── cli/                         # Cobra command tree
│   │   ├── root.go                  #   Root command + global flags
│   │   ├── discover.go              #   discover subcommand (working)
│   │   ├── permissions.go           #   permissions subcommand (stub)
│   │   ├── audit.go                 #   audit subcommand (stub)
│   │   └── version.go               #   version subcommand
│   ├── k8s/                         # Shared Kubernetes client
│   │   └── client.go                #   kubeconfig / in-cluster / context
│   ├── discovery/                   # NHI enumeration logic
│   │   ├── types.go                 #   NonHumanIdentity model + NHI types
│   │   ├── serviceaccounts.go       #   SA discovery with source detection
│   │   └── serviceaccounts_test.go  #   Tests with fake clientset
│   ├── permissions/                 # RBAC analysis (Phase 2)
│   │   └── permissions.go           #   Types: Scope, PolicyRule, BindingRef
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
