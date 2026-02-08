// Package permissions implements RBAC resolution and analysis for
// Non-Human Identities discovered in the cluster.
//
// Phase 2: Full RBAC resolution chain:
//
//	ServiceAccount → RoleBinding/ClusterRoleBinding → Role/ClusterRole → verbs + resources
package permissions

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/Zyrakk/nhi-watch/internal/models"
)

// RBACCache holds all RBAC objects fetched once from the cluster.
// This avoids making N queries per ServiceAccount.
type RBACCache struct {
	// Roles indexed by namespace → name → Role.
	Roles map[string]map[string]rbacv1.Role

	// ClusterRoles indexed by name.
	ClusterRoles map[string]rbacv1.ClusterRole

	// RoleBindings indexed by namespace.
	RoleBindings map[string][]rbacv1.RoleBinding

	// ClusterRoleBindings (cluster-scoped, single list).
	ClusterRoleBindings []rbacv1.ClusterRoleBinding
}

// Resolver resolves RBAC permissions for ServiceAccounts.
type Resolver struct {
	cache *RBACCache
}

// NewResolver creates a Resolver and loads all RBAC objects into the cache.
func NewResolver(ctx context.Context, client kubernetes.Interface) (*Resolver, error) {
	cache, err := buildCache(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("building RBAC cache: %w", err)
	}
	return &Resolver{cache: cache}, nil
}

// NewResolverFromCache creates a Resolver from a pre-built cache.
// This is primarily useful for testing.
func NewResolverFromCache(cache *RBACCache) *Resolver {
	return &Resolver{cache: cache}
}

// ResolveServiceAccount resolves the full permission set for a single
// ServiceAccount identified by name and namespace.
func (r *Resolver) ResolveServiceAccount(saName, saNamespace string) *models.PermissionSet {
	ps := &models.PermissionSet{
		Bindings: make([]models.BindingRef, 0),
		Rules:    make([]models.ResolvedRule, 0),
		Flags:    make([]string, 0),
	}

	// 1. Find RoleBindings in the SA's namespace that reference this SA.
	if rbs, ok := r.cache.RoleBindings[saNamespace]; ok {
		for i := range rbs {
			rb := &rbs[i]
			if r.bindingMatchesSA(rb.Subjects, saName, saNamespace) {
				ref := models.BindingRef{
					Name:      rb.Name,
					Kind:      "RoleBinding",
					Namespace: rb.Namespace,
					RoleRef:   rb.RoleRef.Name,
					RoleKind:  rb.RoleRef.Kind,
				}
				ps.Bindings = append(ps.Bindings, ref)

				rules := r.resolveRoleRef(rb.RoleRef, rb.Namespace)
				ps.Rules = append(ps.Rules, rules...)
			}
		}
	}

	// 2. Find ClusterRoleBindings that reference this SA.
	for i := range r.cache.ClusterRoleBindings {
		crb := &r.cache.ClusterRoleBindings[i]
		if r.bindingMatchesSA(crb.Subjects, saName, saNamespace) {
			ref := models.BindingRef{
				Name:     crb.Name,
				Kind:     "ClusterRoleBinding",
				RoleRef:  crb.RoleRef.Name,
				RoleKind: crb.RoleRef.Kind,
			}
			ps.Bindings = append(ps.Bindings, ref)

			rules := r.resolveRoleRef(crb.RoleRef, "")
			ps.Rules = append(ps.Rules, rules...)
		}
	}

	return ps
}

// FindSAsWithSecretAccess returns a list of "namespace/name" strings for
// ServiceAccounts that can read Secrets in the given target namespace.
// This resolves which SAs have get/list/watch on secrets either via
// a RoleBinding in the target namespace or via a ClusterRoleBinding.
func (r *Resolver) FindSAsWithSecretAccess(targetNamespace string) []string {
	result := make([]string, 0)
	seen := make(map[string]bool)

	secretVerbs := map[string]bool{"get": true, "list": true, "watch": true, "*": true}

	// Check ClusterRoleBindings — these give cluster-wide access.
	for i := range r.cache.ClusterRoleBindings {
		crb := &r.cache.ClusterRoleBindings[i]
		rules := r.resolveRoleRef(crb.RoleRef, "")
		if rulesIncludeSecretAccess(rules, secretVerbs) {
			for _, subj := range crb.Subjects {
				if subj.Kind == rbacv1.ServiceAccountKind {
					key := subj.Namespace + "/" + subj.Name
					if !seen[key] {
						seen[key] = true
						result = append(result, key)
					}
				}
			}
		}
	}

	// Check RoleBindings in the target namespace.
	if rbs, ok := r.cache.RoleBindings[targetNamespace]; ok {
		for i := range rbs {
			rb := &rbs[i]
			rules := r.resolveRoleRef(rb.RoleRef, rb.Namespace)
			if rulesIncludeSecretAccess(rules, secretVerbs) {
				for _, subj := range rb.Subjects {
					if subj.Kind == rbacv1.ServiceAccountKind {
						ns := subj.Namespace
						if ns == "" {
							ns = targetNamespace
						}
						key := ns + "/" + subj.Name
						if !seen[key] {
							seen[key] = true
							result = append(result, key)
						}
					}
				}
			}
		}
	}

	return result
}

// bindingMatchesSA checks if any subject in the list matches the given SA.
// It checks direct SA references and group-based references:
//   - system:serviceaccounts (all SAs in all namespaces)
//   - system:serviceaccounts:<namespace> (all SAs in a namespace)
func (r *Resolver) bindingMatchesSA(subjects []rbacv1.Subject, saName, saNamespace string) bool {
	for _, subj := range subjects {
		switch subj.Kind {
		case rbacv1.ServiceAccountKind:
			if subj.Name == saName && subj.Namespace == saNamespace {
				return true
			}
		case rbacv1.GroupKind:
			if subj.Name == "system:serviceaccounts" {
				return true
			}
			if subj.Name == "system:serviceaccounts:"+saNamespace {
				return true
			}
		}
	}
	return false
}

// resolveRoleRef resolves the rules from a RoleRef. For RoleBindings that
// reference a Role, the namespace is used to look up the Role. For
// ClusterRoleBindings (or RoleBindings referencing a ClusterRole), the
// ClusterRole is used.
func (r *Resolver) resolveRoleRef(ref rbacv1.RoleRef, namespace string) []models.ResolvedRule {
	var policyRules []rbacv1.PolicyRule
	roleName := ref.Name

	switch ref.Kind {
	case "Role":
		if nsRoles, ok := r.cache.Roles[namespace]; ok {
			if role, ok := nsRoles[ref.Name]; ok {
				policyRules = role.Rules
			}
		}
	case "ClusterRole":
		if cr, ok := r.cache.ClusterRoles[ref.Name]; ok {
			policyRules = cr.Rules
		}
	}

	resolved := make([]models.ResolvedRule, 0, len(policyRules))
	for _, pr := range policyRules {
		resolved = append(resolved, models.ResolvedRule{
			APIGroups:     copyStrings(pr.APIGroups),
			Resources:     copyStrings(pr.Resources),
			Verbs:         copyStrings(pr.Verbs),
			ResourceNames: copyStrings(pr.ResourceNames),
			Source:        roleName,
		})
	}

	return resolved
}

// rulesIncludeSecretAccess checks if any resolved rule grants access to secrets.
func rulesIncludeSecretAccess(rules []models.ResolvedRule, secretVerbs map[string]bool) bool {
	for _, rule := range rules {
		hasSecretResource := false
		for _, res := range rule.Resources {
			if res == "secrets" || res == "*" {
				hasSecretResource = true
				break
			}
		}
		if !hasSecretResource {
			continue
		}

		hasCoreGroup := false
		for _, ag := range rule.APIGroups {
			if ag == "" || ag == "*" {
				hasCoreGroup = true
				break
			}
		}
		if !hasCoreGroup {
			continue
		}

		for _, v := range rule.Verbs {
			if secretVerbs[v] {
				return true
			}
		}
	}
	return false
}

// buildCache fetches all RBAC objects from the cluster and indexes them.
func buildCache(ctx context.Context, client kubernetes.Interface) (*RBACCache, error) {
	cache := &RBACCache{
		Roles:        make(map[string]map[string]rbacv1.Role),
		ClusterRoles: make(map[string]rbacv1.ClusterRole),
		RoleBindings: make(map[string][]rbacv1.RoleBinding),
	}

	// Fetch all Roles.
	roleList, err := client.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}
	for i := range roleList.Items {
		role := roleList.Items[i]
		if cache.Roles[role.Namespace] == nil {
			cache.Roles[role.Namespace] = make(map[string]rbacv1.Role)
		}
		cache.Roles[role.Namespace][role.Name] = role
	}

	// Fetch all ClusterRoles.
	crList, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing cluster roles: %w", err)
	}
	for i := range crList.Items {
		cache.ClusterRoles[crList.Items[i].Name] = crList.Items[i]
	}

	// Fetch all RoleBindings.
	rbList, err := client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing role bindings: %w", err)
	}
	for i := range rbList.Items {
		rb := rbList.Items[i]
		cache.RoleBindings[rb.Namespace] = append(cache.RoleBindings[rb.Namespace], rb)
	}

	// Fetch all ClusterRoleBindings.
	crbList, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing cluster role bindings: %w", err)
	}
	cache.ClusterRoleBindings = crbList.Items

	return cache, nil
}

// copyStrings returns a copy of a string slice.
func copyStrings(s []string) []string {
	if s == nil {
		return nil
	}
	c := make([]string, len(s))
	copy(c, s)
	return c
}
