# NHI-Watch Revised Vision Design

**Date:** 2026-03-10
**Status:** Approved

## Project Identity

Open-source, Kubernetes-native security tool (Go, Apache 2.0) that discovers, audits, scores, and enforces governance of Non-Human Identities in Kubernetes and OpenShift clusters.

**Target audience:** K8s platform teams, security engineers, compliance auditors.

**Differentiators:**
- Full RBAC chain resolution (SA → Binding → Role → verbs+resources)
- Deterministic scoring with CIS Kubernetes Benchmark mapping
- Pod security posture as risk multiplier
- Gatekeeper ConstraintTemplate export (detection → prevention)
- Usage-based least-privilege enforcement from observed behavior (v2.0)

## Core Principles

1. **Zero false positives.** Every finding backed by observable data. Insufficient data = explicit "low confidence," not a guess.
2. **Deterministic scoring.** Same cluster state = same results. No AI in scoring. Rules are human-readable YAML. Auditors can verify.
3. **Minimum privilege for itself.** CLI = read-only. Controller = read + write to own ConfigMap. No cluster-admin, ever.
4. **Kubernetes-native depth.** Full RBAC chain, pod security context, SCC analysis, cert-manager CRDs. Deeper than any multi-cloud platform.

---

## v1.0 — The Auditor

**Timeline:** 3-4 months (spare time)

### Data Pipeline

```
Discover NHIs ──→ Resolve RBAC ──→ Enrich Workload Posture ──→ Score ──→ Report
     │                                        ▲
     │                                        │
     └──── Discover Pods (SA refs) ───────────┘
           + securityContext inspection
           + SCC resolution (OpenShift)
```

Scoring receives two inputs:
- **Permission scope** — what can this identity do? (RBAC chain resolution)
- **Workload posture** — how dangerous is the runtime context? (pod security context, SCC)

Workload posture acts as a risk multiplier: cluster-admin in a restricted pod is CRITICAL; the same SA in a privileged pod with hostPID is CRITICAL+URGENT.

### Feature Set

| Component | Scope |
|-----------|-------|
| **NHI Discovery** | ServiceAccounts, Secrets (API keys, tokens, passwords), TLS certificates (x509 parsing), cert-manager CRDs, registry credentials, legacy SA tokens |
| **Pod posture discovery** | Resolve SA → Pod references. Inspect securityContext: privileged, runAsRoot, hostPath, hostNetwork, hostPID. Risk multiplier for scoring. |
| **RBAC resolution** | Full chain: SA → RoleBindings/ClusterRoleBindings → Roles/ClusterRoles → verbs + resources. 7 overprivilege patterns (cluster-admin, wildcards, cluster-wide secret access, cross-namespace, default SA with bindings). |
| **Scoring engine** | Deterministic rules (YAML-configurable). Pod security multiplier. CIS Kubernetes Benchmark control mapping on every rule (e.g., 5.1.2, 5.1.6). Score 0-100, severity CRITICAL/HIGH/MEDIUM/LOW/INFO. |
| **OpenShift support** | Auto-detect via API discovery (route.openshift.io / config.openshift.io). SCC analysis as extension of pod posture — which SCC the pod runs under, whether it allows privileged/root/hostPath. |
| **Reporting** | 3 formats: Table (terminal), JSON (automation/SIEM), SARIF (GitHub Security tab). |
| **CI/CD integration** | `--fail-on=critical\|high\|medium` with exit codes. Baseline save/load/diff for incremental adoption — only fail on new/regressed findings, not pre-existing debt. |
| **Remediation** | Enhanced text recommendations (specific + actionable, e.g., "replace ClusterRoleBinding X with scoped ClusterRole granting [get,list,watch] on [pods,services]"). YAML generation only for Traefik + cert-manager (personally verified on k3s). `--dry-run=true` default. All YAML marked as "proposal." |
| **Policy export** | `nhi-watch policy export --format=gatekeeper` — generates OPA/Gatekeeper ConstraintTemplates from scoring rules. Detection → prevention via ecosystem tooling. |
| **Packaging** | Binary (linux/darwin, amd64/arm64), Docker image (distroless, <30MB), Helm chart (CronJob), install script. |

### What's NOT in v1.0

- HTML/Markdown reports (same data, different rendering — zero architectural interest)
- Workload templates beyond Traefik + cert-manager (unverified = liability)
- OpenShift Routes/OLM operator discovery (scope expansion, not risk model improvement)
- Admission webhook (Gatekeeper policy export achieves prevention via ecosystem)
- Monitoring controller (v2.0)

---

## v2.0 — The Behavioral Engine

**The fundamental advance:** v1.0 shows what NHIs are *allowed* to do. v2.0 shows what they *actually* do. The delta is excess privilege to remove.

### Architecture — Two Layers

**Layer 1 (Watch API)** — runs out of the box, no extra configuration. Kubernetes Deployment using client-go informers. Watches for mutations to NHI-related resources: ServiceAccount created, Secret modified, RoleBinding changed, certificate expired. Real-time detection of configuration drift.

**Layer 2 (Usage Profiling)** — requires audit event data. Opt-in. The controller receives audit events via webhook endpoint (`/webhook/audit`). Over time, builds per-NHI usage profiles: "traefik reads services and ingresses 12,000 times/day but has never touched secrets." Stores only aggregated profiles, not raw events. Generates optimized audit policies to reduce volume by 95%+.

### Feature Set

| Component | Description |
|-----------|-------------|
| **Controller (Layer 1)** | Real-time detection of NHI mutations via client-go informers. Zero extra config. |
| **Usage profiling (Layer 2)** | Audit webhook receiver. Builds per-NHI usage profiles. Opt-in. |
| **Precise remediation** | `nhi-watch remediate <sa> -n <ns>` generates ClusterRole based on observed usage over N days. Shows current vs proposed with reduction percentage. |
| **Inactive NHI detection** | SAs with 0 API calls over 30+ days flagged for cleanup. Confidence-based: "unused (30d observed, high confidence)" vs "insufficient data (3d, low confidence)." |
| **NetworkPolicy awareness** | Scoring considers whether NHI pods have egress restrictions. Unrestricted egress to API server = higher risk multiplier. |
| **Real-time drift** | Webhook/alert when risk regresses from controller observations. |

**Packaging:** Same Helm chart, `controller.enabled=true`. Adds Deployment + ConfigMap for state. Slightly broader RBAC (read + write to own ConfigMap).

---

## v3.0 — The Integrator

### Theme A: Enterprise Observability Stack

| Integration | Value |
|-------------|-------|
| **Wazuh** | Alternative UsageDataSource. Query Wazuh API for identity usage data instead of requiring audit webhook. Zero new infrastructure for Wazuh-deployed environments. Banking/healthcare adoption accelerator. |
| **Falco** | Subscribe to Falco gRPC output for identity-related events. Enables anomaly detection (SA used from unexpected pod/IP). Enriches risk scoring. |
| **Prometheus** | `/metrics` endpoint with standard gauges: NHI counts, findings by severity, risk scores, usage gaps, controller health. Pre-built Grafana dashboard JSON ships with Helm chart. |
| **Webhooks** | Slack, PagerDuty, generic HTTP. Notify when findings change — new critical risk, finding resolved, severity escalated. |

### Theme B: Platform Completeness

| Feature | Value |
|---------|-------|
| **OpenShift Routes + OLM** | Discover Route-exposed NHIs, OLM operator identities, Projects vs namespaces. |
| **Kyverno policy export** | `nhi-watch policy export --format=kyverno` — broader policy-as-code alongside Gatekeeper. |
| **RBAC visualization** | `nhi-watch visualize --output=rbac-map.html` — self-contained interactive HTML graph: SA → Bindings → Roles → Permissions, color-coded by risk. For auditor presentations. |
| **Multi-cluster** | Aggregate summaries across clusters. |

---

## What's NOT in the Public Roadmap

- ZCloud integration (private module, built separately if needed for internal demos)
- Custom admission webhook (Gatekeeper/Kyverno policy export covers prevention)
- AI-based scoring or analysis (deterministic rules only)

---

## Market Context

The NHI security market has $400M+ in venture funding (Astrix $85M, Oasis $75M, Silverfort $223M, PlainID $100M) — all proprietary, closed-source, enterprise SaaS. None is Kubernetes-native. None provides deep RBAC chain resolution. NHI-Watch fills the open-source, Kubernetes-depth gap.

They are not competitors — they serve different markets. An enterprise with 50 SaaS integrations needs Astrix. A team running Kubernetes clusters that needs PCI-DSS audits needs NHI-Watch. Some organizations will use both.

## Design Decisions Log

| Decision | Rationale |
|----------|-----------|
| Pod security context as risk multiplier, not separate finding | Same identity, compounded risk — architecturally cleaner than separate scoring |
| CIS mapping as metadata on existing rules, not a separate mode | Low effort, high audit credibility. Every rule gets a CISControl field. |
| 3 report formats (Table/JSON/SARIF), not 5 | HTML/Markdown are rendering variations. SARIF demonstrates CI/CD security pipeline maturity. |
| Gatekeeper policy export instead of custom admission webhook | Leverages ecosystem tooling. "Why not Gatekeeper?" has an answer: we generate the policies FOR Gatekeeper. |
| Remediation YAML only for verified workloads (Traefik, cert-manager) | Two verified templates > four guesses. Unknown workloads get text recommendations. |
| Baselines in v1.0, not v2.0 | Without baselines, `--fail-on` blocks on pre-existing debt. Baselines make CI/CD adoption real, not theoretical. |
| ZCloud as private module, not public roadmap | Niche product with zero portfolio/GitHub value. Private module for internal demos only. |
| OpenShift SCC in v1.0, Routes/OLM in v3.0 | SCC analysis extends pod posture (risk model improvement). Routes/OLM are discovery scope expansions. |
