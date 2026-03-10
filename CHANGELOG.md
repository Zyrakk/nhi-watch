# Changelog

All notable changes to NHI-Watch will be documented in this file.

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
