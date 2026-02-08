// Package permissions analyzes RBAC bindings and effective permissions
// for Non-Human Identities discovered in the cluster.
//
// Phase 0: Stub — types and structure only.
//
// Phase 2 will implement:
//   - Resolve chain: ServiceAccount → RoleBinding/ClusterRoleBinding → Role/ClusterRole → verbs + resources
//   - Effective permission matrix per NHI
//   - Scope classification: cluster-wide, namespace-scoped, minimal
//   - Detection of overly-permissive patterns:
//   - cluster-admin binding
//   - Wildcard (*) in verbs or resources
//   - Default SA with any additional binding
//   - Cross-namespace Secret access
//   - OpenShift SCC (Security Context Constraints) analysis
package permissions

// Scope classifies how wide an NHI's permissions reach.
type Scope string

const (
	ScopeClusterWide     Scope = "CLUSTER-WIDE"
	ScopeNamespaceScoped Scope = "NAMESPACE-SCOPED"
	ScopeMinimal         Scope = "MINIMAL"
)

// PolicyRule mirrors a single RBAC rule (verbs + resources).
type PolicyRule struct {
	APIGroups     []string `json:"api_groups"`
	Resources     []string `json:"resources"`
	ResourceNames []string `json:"resource_names,omitempty"`
	Verbs         []string `json:"verbs"`
}

// BindingRef references a RoleBinding or ClusterRoleBinding.
type BindingRef struct {
	Name           string       `json:"name"`
	Kind           string       `json:"kind"` // "RoleBinding" or "ClusterRoleBinding"
	Namespace      string       `json:"namespace,omitempty"`
	RoleRef        string       `json:"role_ref"`
	EffectiveRules []PolicyRule `json:"effective_rules"`
}

// PermissionSummary holds the complete RBAC analysis for a single NHI.
type PermissionSummary struct {
	ServiceAccount    string       `json:"service_account"`
	Namespace         string       `json:"namespace"`
	Scope             Scope        `json:"scope"`
	Bindings          []BindingRef `json:"bindings"`
	IsClusterAdmin    bool         `json:"is_cluster_admin"`
	HasWildcardAccess bool         `json:"has_wildcard_access"`
	HasSecretAccess   bool         `json:"has_secret_access"`
}