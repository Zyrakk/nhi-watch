package permissions

import (
	"github.com/Zyrakk/nhi-watch/internal/models"
)

// Risk flag constants detected by the analyzer.
const (
	FlagClusterAdmin               = "CLUSTER_ADMIN"
	FlagWildcardVerbs              = "WILDCARD_VERBS"
	FlagWildcardResources          = "WILDCARD_RESOURCES"
	FlagWildcardAPIGroups          = "WILDCARD_APIGROUPS"
	FlagSecretAccessClusterWide    = "SECRET_ACCESS_CLUSTER_WIDE"
	FlagDefaultSAHasBindings       = "DEFAULT_SA_HAS_BINDINGS"
	FlagCrossNamespaceSecretAccess = "CROSS_NAMESPACE_SECRET_ACCESS"
)

// Analyze examines a PermissionSet for overprivilege patterns and
// populates its Flags and Scope fields. saName and saNamespace are
// used for SA-specific checks (e.g. default SA detection).
func Analyze(ps *models.PermissionSet, saName, saNamespace string) {
	ps.Flags = make([]string, 0)

	detectClusterAdmin(ps)
	detectWildcardVerbs(ps)
	detectWildcardResources(ps)
	detectWildcardAPIGroups(ps)
	detectSecretAccessClusterWide(ps)
	detectDefaultSAHasBindings(ps, saName)
	detectCrossNamespaceSecretAccess(ps, saNamespace)
	classifyScope(ps)
}

// detectClusterAdmin checks if any binding references the cluster-admin ClusterRole.
func detectClusterAdmin(ps *models.PermissionSet) {
	for _, b := range ps.Bindings {
		if b.RoleRef == "cluster-admin" && b.RoleKind == "ClusterRole" {
			ps.Flags = append(ps.Flags, FlagClusterAdmin)
			return
		}
	}
}

// detectWildcardVerbs checks for "*" in verbs across all rules.
func detectWildcardVerbs(ps *models.PermissionSet) {
	for _, rule := range ps.Rules {
		if containsWildcard(rule.Verbs) {
			ps.Flags = append(ps.Flags, FlagWildcardVerbs)
			return
		}
	}
}

// detectWildcardResources checks for "*" in resources across all rules.
func detectWildcardResources(ps *models.PermissionSet) {
	for _, rule := range ps.Rules {
		if containsWildcard(rule.Resources) {
			ps.Flags = append(ps.Flags, FlagWildcardResources)
			return
		}
	}
}

// detectWildcardAPIGroups checks for "*" in apiGroups across all rules.
func detectWildcardAPIGroups(ps *models.PermissionSet) {
	for _, rule := range ps.Rules {
		if containsWildcard(rule.APIGroups) {
			ps.Flags = append(ps.Flags, FlagWildcardAPIGroups)
			return
		}
	}
}

// detectSecretAccessClusterWide checks if the SA can read secrets
// at cluster scope (via a ClusterRoleBinding).
func detectSecretAccessClusterWide(ps *models.PermissionSet) {
	// Build a set of role sources that come from ClusterRoleBindings.
	clusterWideSources := make(map[string]bool)
	for _, b := range ps.Bindings {
		if b.Kind == "ClusterRoleBinding" {
			clusterWideSources[b.RoleRef] = true
		}
	}

	if len(clusterWideSources) == 0 {
		return
	}

	secretReadVerbs := map[string]bool{"get": true, "list": true, "watch": true, "*": true}

	for _, rule := range ps.Rules {
		if !clusterWideSources[rule.Source] {
			continue
		}
		if !ruleTargetsSecrets(rule) {
			continue
		}
		for _, v := range rule.Verbs {
			if secretReadVerbs[v] {
				ps.Flags = append(ps.Flags, FlagSecretAccessClusterWide)
				return
			}
		}
	}
}

// detectDefaultSAHasBindings flags if the SA is named "default" and has
// any bindings at all.
func detectDefaultSAHasBindings(ps *models.PermissionSet, saName string) {
	if saName == "default" && len(ps.Bindings) > 0 {
		ps.Flags = append(ps.Flags, FlagDefaultSAHasBindings)
	}
}

// detectCrossNamespaceSecretAccess checks if the SA can read secrets in
// namespaces other than its own. This happens when:
//   - A ClusterRoleBinding grants cluster-wide secret access, OR
//   - A RoleBinding in a different namespace grants secret access.
func detectCrossNamespaceSecretAccess(ps *models.PermissionSet, saNamespace string) {
	secretReadVerbs := map[string]bool{"get": true, "list": true, "watch": true, "*": true}

	for _, b := range ps.Bindings {
		hasSecretAccess := false

		for _, rule := range ps.Rules {
			if rule.Source != b.RoleRef {
				continue
			}
			if !ruleTargetsSecrets(rule) {
				continue
			}
			for _, v := range rule.Verbs {
				if secretReadVerbs[v] {
					hasSecretAccess = true
					break
				}
			}
			if hasSecretAccess {
				break
			}
		}

		if !hasSecretAccess {
			continue
		}

		// ClusterRoleBinding = cluster-wide = cross-namespace by definition.
		if b.Kind == "ClusterRoleBinding" {
			ps.Flags = append(ps.Flags, FlagCrossNamespaceSecretAccess)
			return
		}

		// RoleBinding in a different namespace = cross-namespace.
		if b.Kind == "RoleBinding" && b.Namespace != saNamespace {
			ps.Flags = append(ps.Flags, FlagCrossNamespaceSecretAccess)
			return
		}
	}
}

// classifyScope determines the PermissionScope based on bindings and rules.
func classifyScope(ps *models.PermissionSet) {
	if len(ps.Bindings) == 0 {
		ps.Scope = models.ScopeNone
		return
	}

	hasClusterRoleBinding := false
	hasSignificantClusterAccess := false

	viewOnlyVerbs := map[string]bool{"get": true, "list": true, "watch": true}

	for _, b := range ps.Bindings {
		if b.Kind == "ClusterRoleBinding" {
			hasClusterRoleBinding = true

			// Check if the cluster-wide access is more than just view.
			for _, rule := range ps.Rules {
				if rule.Source != b.RoleRef {
					continue
				}
				for _, v := range rule.Verbs {
					if !viewOnlyVerbs[v] {
						hasSignificantClusterAccess = true
						break
					}
				}
				if hasSignificantClusterAccess {
					break
				}
			}
		}
	}

	if hasSignificantClusterAccess {
		ps.Scope = models.ScopeClusterWide
		return
	}

	if hasClusterRoleBinding {
		// Has CRB but only view-level access — still cluster-wide
		// because the scope is cluster, even if permissions are limited.
		ps.Scope = models.ScopeClusterWide
		return
	}

	// Only RoleBindings — check if permissions are minimal.
	isMinimal := true
	for _, rule := range ps.Rules {
		for _, v := range rule.Verbs {
			if !viewOnlyVerbs[v] {
				isMinimal = false
				break
			}
		}
		if !isMinimal {
			break
		}
	}

	if isMinimal {
		ps.Scope = models.ScopeMinimal
		return
	}

	ps.Scope = models.ScopeNamespaced
}

// ruleTargetsSecrets checks if a resolved rule applies to the "secrets"
// resource in the core API group.
func ruleTargetsSecrets(rule models.ResolvedRule) bool {
	hasSecretResource := false
	for _, res := range rule.Resources {
		if res == "secrets" || res == "*" {
			hasSecretResource = true
			break
		}
	}
	if !hasSecretResource {
		return false
	}

	for _, ag := range rule.APIGroups {
		if ag == "" || ag == "*" {
			return true
		}
	}
	return false
}

// containsWildcard checks if a string slice contains "*".
func containsWildcard(ss []string) bool {
	for _, s := range ss {
		if s == "*" {
			return true
		}
	}
	return false
}
