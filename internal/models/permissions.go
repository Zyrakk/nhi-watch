// Package models defines shared data structures used across NHI-Watch.
package models

// PermissionScope classifies how wide an NHI's permissions reach.
type PermissionScope string

const (
	// ScopeClusterWide means the NHI has at least one ClusterRoleBinding
	// with significant access (not just view).
	ScopeClusterWide PermissionScope = "cluster-wide"

	// ScopeNamespaced means the NHI only has RoleBindings, limited to
	// specific namespaces.
	ScopeNamespaced PermissionScope = "namespace-scoped"

	// ScopeMinimal means the NHI only has basic permissions
	// (e.g. get in its own namespace).
	ScopeMinimal PermissionScope = "minimal"

	// ScopeNone means the NHI has no bindings at all.
	ScopeNone PermissionScope = "none"
)

// PermissionSet holds the complete RBAC analysis for a single NHI.
type PermissionSet struct {
	// Bindings lists all RoleBindings and ClusterRoleBindings that apply.
	Bindings []BindingRef `json:"bindings"`

	// Rules contains the effective RBAC rules resolved from all bindings.
	Rules []ResolvedRule `json:"rules"`

	// Scope classifies the reach of the permissions.
	Scope PermissionScope `json:"scope"`

	// Flags lists risk patterns detected (e.g. CLUSTER_ADMIN, WILDCARD_VERBS).
	Flags []string `json:"flags"`
}

// BindingRef references a RoleBinding or ClusterRoleBinding that applies
// to a given ServiceAccount.
type BindingRef struct {
	// Name of the binding object.
	Name string `json:"name"`

	// Kind is "RoleBinding" or "ClusterRoleBinding".
	Kind string `json:"kind"`

	// Namespace of the binding ("" for ClusterRoleBinding).
	Namespace string `json:"namespace,omitempty"`

	// RoleRef is the name of the referenced Role or ClusterRole.
	RoleRef string `json:"role_ref"`

	// RoleKind is "Role" or "ClusterRole".
	RoleKind string `json:"role_kind"`
}

// ResolvedRule represents a single effective RBAC rule after resolving
// the full binding → role chain.
type ResolvedRule struct {
	// APIGroups this rule applies to ("" = core, "*" = all).
	APIGroups []string `json:"api_groups"`

	// Resources this rule applies to (e.g. "pods", "secrets", "*").
	Resources []string `json:"resources"`

	// Verbs allowed (e.g. "get", "list", "watch", "create", "delete", "*").
	Verbs []string `json:"verbs"`

	// ResourceNames restricts the rule to specific named resources.
	ResourceNames []string `json:"resource_names,omitempty"`

	// Source is the name of the Role/ClusterRole this rule came from.
	Source string `json:"source"`
}
