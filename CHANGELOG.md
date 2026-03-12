# Changelog

All notable changes to NHI-Watch will be documented in this file.

## [v2.0.0] - 2026-03-12

### Features

- **Real-Time Controller**: Watch API-based controller with client-go informers for continuous NHI monitoring (ServiceAccounts, Secrets, RoleBindings, ClusterRoleBindings)
- **Drift Detection**: Automatic detection of new, resolved, regressed, and improved NHI findings between scan cycles
- **ConfigMap State Store**: Persistent NHI snapshot storage for drift detection without external dependencies
- **Audit Webhook (Layer 2)**: HTTP receiver for Kubernetes API server audit events to build per-NHI usage profiles
- **Usage Profiling**: Track ServiceAccount API calls with confidence-based assertions (none/medium/high)
- **Inactive NHI Detection**: Two new scoring rules (INACTIVE_NHI_HIGH, INACTIVE_NHI_MEDIUM) for ServiceAccounts with zero observed API calls
- **NetworkPolicy Egress Awareness**: Discover egress restrictions and apply +0.10 risk multiplier for unrestricted pods
- **Usage-Based RBAC Generation**: Generate least-privilege ClusterRole/ClusterRoleBinding from observed API calls with reduction percentage
- **Audit Policy Generator**: Generate optimized Kubernetes audit policy YAML (95%+ volume reduction)
- **Controller CLI**: `controller start`, `controller status`, and `controller audit-policy` subcommands
- **Helm Controller Support**: Conditional Deployment, Service, and ConfigMap templates with `controller.enabled=true`

### Scoring Rules

- Added: `INACTIVE_NHI_HIGH` (score 55, MEDIUM) — inactive SA with high-confidence observation
- Added: `INACTIVE_NHI_MEDIUM` (score 25, LOW) — inactive SA with medium-confidence observation
- Total rules: 18 (16 original + 2 new)

### Architecture

- Two-layer architecture: Layer 1 (Watch API via informers) + Layer 2 (Audit Webhook for usage profiling)
- Pluggable `UsageDataSource` interface for future data sources (Wazuh, Falco)
- Debounced re-scan with configurable interval (default 5s)

## [v1.0.0] - 2026-03-10

### Features

- **NHI Discovery**: Enumerate ServiceAccounts, Secrets (credentials, TLS, registry, tokens), and cert-manager Certificates across all namespaces
- **RBAC Permission Analysis**: Full binding resolution (RoleBindings, ClusterRoleBindings), scope classification, and 7 overprivilege flags
- **Risk Scoring Engine**: 16 deterministic rules with CIS Kubernetes Benchmark mapping and severity levels (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- **Pod Security Posture**: Discover pod security context (privileged, hostNetwork, hostPID, runAsRoot) with risk score multiplier
- **OpenShift SCC Support**: Detect SecurityContextConstraints on OpenShift clusters
- **Output Formats**: Table (terminal), JSON (machine-readable), SARIF v2.1.0 (GitHub Security tab)
- **CI/CD Integration**: `--fail-on` flag for pipeline gating with exit code 2; `--save-baseline` / `--baseline` for tracking regressions
- **Remediation**: Generate least-privilege RBAC YAML proposals for Traefik and cert-manager workloads
- **Gatekeeper Policy Export**: Generate OPA/Gatekeeper ConstraintTemplates from scoring rules for admission-time enforcement
- **Packaging**: Dockerfile (distroless), Helm chart, install script, GitHub Actions release workflow with GoReleaser

### Supported Platforms

- Kubernetes
- k3s
- OpenShift (core/v1, rbac/v1, security.openshift.io/v1)
