package permissions

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNewResolver_BuildsCache(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "view"},
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
			},
		},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-reader", Namespace: "default"},
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			},
		},
	)

	resolver, err := NewResolver(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := resolver.cache.ClusterRoles["view"]; !ok {
		t.Error("expected ClusterRole 'view' in cache")
	}
	if roles, ok := resolver.cache.Roles["default"]; !ok || roles["pod-reader"].Name == "" {
		t.Error("expected Role 'pod-reader' in cache")
	}
}

func TestResolveServiceAccount_NoBindings(t *testing.T) {
	cache := &RBACCache{
		Roles:               make(map[string]map[string]rbacv1.Role),
		ClusterRoles:        make(map[string]rbacv1.ClusterRole),
		RoleBindings:        make(map[string][]rbacv1.RoleBinding),
		ClusterRoleBindings: nil,
	}
	resolver := NewResolverFromCache(cache)

	ps := resolver.ResolveServiceAccount("my-sa", "default")

	if len(ps.Bindings) != 0 {
		t.Errorf("expected 0 bindings, got %d", len(ps.Bindings))
	}
	if len(ps.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(ps.Rules))
	}
}

func TestResolveServiceAccount_RoleBinding(t *testing.T) {
	cache := &RBACCache{
		Roles: map[string]map[string]rbacv1.Role{
			"production": {
				"pod-reader": {
					ObjectMeta: metav1.ObjectMeta{Name: "pod-reader", Namespace: "production"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
					},
				},
			},
		},
		ClusterRoles: make(map[string]rbacv1.ClusterRole),
		RoleBindings: map[string][]rbacv1.RoleBinding{
			"production": {
				{
					ObjectMeta: metav1.ObjectMeta{Name: "read-pods", Namespace: "production"},
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Name: "app-sa", Namespace: "production"},
					},
					RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "pod-reader", APIGroup: "rbac.authorization.k8s.io"},
				},
			},
		},
		ClusterRoleBindings: nil,
	}
	resolver := NewResolverFromCache(cache)

	ps := resolver.ResolveServiceAccount("app-sa", "production")

	if len(ps.Bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(ps.Bindings))
	}
	if ps.Bindings[0].Kind != "RoleBinding" {
		t.Errorf("expected RoleBinding, got %s", ps.Bindings[0].Kind)
	}
	if ps.Bindings[0].RoleRef != "pod-reader" {
		t.Errorf("expected role ref 'pod-reader', got %s", ps.Bindings[0].RoleRef)
	}
	if len(ps.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(ps.Rules))
	}
	if ps.Rules[0].Source != "pod-reader" {
		t.Errorf("expected source 'pod-reader', got %s", ps.Rules[0].Source)
	}
}

func TestResolveServiceAccount_ClusterRoleBinding(t *testing.T) {
	cache := &RBACCache{
		Roles: make(map[string]map[string]rbacv1.Role),
		ClusterRoles: map[string]rbacv1.ClusterRole{
			"cluster-admin": {
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
				},
			},
		},
		RoleBindings: make(map[string][]rbacv1.RoleBinding),
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "test-admin-binding"},
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.ServiceAccountKind, Name: "admin-sa", Namespace: "kube-system"},
				},
				RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin", APIGroup: "rbac.authorization.k8s.io"},
			},
		},
	}
	resolver := NewResolverFromCache(cache)

	ps := resolver.ResolveServiceAccount("admin-sa", "kube-system")

	if len(ps.Bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(ps.Bindings))
	}
	if ps.Bindings[0].Kind != "ClusterRoleBinding" {
		t.Errorf("expected ClusterRoleBinding, got %s", ps.Bindings[0].Kind)
	}
	if len(ps.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(ps.Rules))
	}
	if ps.Rules[0].Verbs[0] != "*" {
		t.Error("expected wildcard verb")
	}
}

func TestResolveServiceAccount_GroupMatch_AllServiceAccounts(t *testing.T) {
	cache := &RBACCache{
		Roles: make(map[string]map[string]rbacv1.Role),
		ClusterRoles: map[string]rbacv1.ClusterRole{
			"basic-view": {
				ObjectMeta: metav1.ObjectMeta{Name: "basic-view"},
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get"}},
				},
			},
		},
		RoleBindings: make(map[string][]rbacv1.RoleBinding),
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "all-sa-view"},
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.GroupKind, Name: "system:serviceaccounts"},
				},
				RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "basic-view", APIGroup: "rbac.authorization.k8s.io"},
			},
		},
	}
	resolver := NewResolverFromCache(cache)

	// Any SA in any namespace should match.
	ps := resolver.ResolveServiceAccount("random-sa", "random-ns")

	if len(ps.Bindings) != 1 {
		t.Fatalf("expected 1 binding via group match, got %d", len(ps.Bindings))
	}
}

func TestResolveServiceAccount_GroupMatch_NamespaceServiceAccounts(t *testing.T) {
	cache := &RBACCache{
		Roles: make(map[string]map[string]rbacv1.Role),
		ClusterRoles: map[string]rbacv1.ClusterRole{
			"ns-viewer": {
				ObjectMeta: metav1.ObjectMeta{Name: "ns-viewer"},
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
				},
			},
		},
		RoleBindings: make(map[string][]rbacv1.RoleBinding),
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "ns-sa-view"},
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.GroupKind, Name: "system:serviceaccounts:production"},
				},
				RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "ns-viewer", APIGroup: "rbac.authorization.k8s.io"},
			},
		},
	}
	resolver := NewResolverFromCache(cache)

	// SA in "production" should match.
	ps1 := resolver.ResolveServiceAccount("my-sa", "production")
	if len(ps1.Bindings) != 1 {
		t.Errorf("expected 1 binding for production SA, got %d", len(ps1.Bindings))
	}

	// SA in "staging" should NOT match.
	ps2 := resolver.ResolveServiceAccount("my-sa", "staging")
	if len(ps2.Bindings) != 0 {
		t.Errorf("expected 0 bindings for staging SA, got %d", len(ps2.Bindings))
	}
}

func TestResolveServiceAccount_MultipleBindings(t *testing.T) {
	cache := &RBACCache{
		Roles: map[string]map[string]rbacv1.Role{
			"production": {
				"pod-reader": {
					ObjectMeta: metav1.ObjectMeta{Name: "pod-reader", Namespace: "production"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
					},
				},
			},
		},
		ClusterRoles: map[string]rbacv1.ClusterRole{
			"secret-reader": {
				ObjectMeta: metav1.ObjectMeta{Name: "secret-reader"},
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list", "watch"}},
				},
			},
		},
		RoleBindings: map[string][]rbacv1.RoleBinding{
			"production": {
				{
					ObjectMeta: metav1.ObjectMeta{Name: "read-pods-rb", Namespace: "production"},
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Name: "worker", Namespace: "production"},
					},
					RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "pod-reader", APIGroup: "rbac.authorization.k8s.io"},
				},
			},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "secret-reader-crb"},
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.ServiceAccountKind, Name: "worker", Namespace: "production"},
				},
				RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "secret-reader", APIGroup: "rbac.authorization.k8s.io"},
			},
		},
	}
	resolver := NewResolverFromCache(cache)

	ps := resolver.ResolveServiceAccount("worker", "production")

	if len(ps.Bindings) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(ps.Bindings))
	}
	if len(ps.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(ps.Rules))
	}
}

func TestResolveServiceAccount_RoleBindingRefClusterRole(t *testing.T) {
	// A RoleBinding can reference a ClusterRole, scoping it to the namespace.
	cache := &RBACCache{
		Roles: make(map[string]map[string]rbacv1.Role),
		ClusterRoles: map[string]rbacv1.ClusterRole{
			"edit": {
				ObjectMeta: metav1.ObjectMeta{Name: "edit"},
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"pods", "services"}, Verbs: []string{"get", "list", "create", "update", "delete"}},
				},
			},
		},
		RoleBindings: map[string][]rbacv1.RoleBinding{
			"staging": {
				{
					ObjectMeta: metav1.ObjectMeta{Name: "edit-rb", Namespace: "staging"},
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Name: "deployer", Namespace: "staging"},
					},
					RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "edit", APIGroup: "rbac.authorization.k8s.io"},
				},
			},
		},
		ClusterRoleBindings: nil,
	}
	resolver := NewResolverFromCache(cache)

	ps := resolver.ResolveServiceAccount("deployer", "staging")

	if len(ps.Bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(ps.Bindings))
	}
	if ps.Bindings[0].RoleKind != "ClusterRole" {
		t.Errorf("expected RoleKind=ClusterRole, got %s", ps.Bindings[0].RoleKind)
	}
	if ps.Bindings[0].Kind != "RoleBinding" {
		t.Errorf("expected Kind=RoleBinding, got %s", ps.Bindings[0].Kind)
	}
	if len(ps.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(ps.Rules))
	}
}

func TestResolveServiceAccount_DoesNotMatchOtherSA(t *testing.T) {
	cache := &RBACCache{
		Roles: make(map[string]map[string]rbacv1.Role),
		ClusterRoles: map[string]rbacv1.ClusterRole{
			"admin": {
				ObjectMeta: metav1.ObjectMeta{Name: "admin"},
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
				},
			},
		},
		RoleBindings: make(map[string][]rbacv1.RoleBinding),
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "specific-admin"},
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.ServiceAccountKind, Name: "admin-sa", Namespace: "kube-system"},
				},
				RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "admin", APIGroup: "rbac.authorization.k8s.io"},
			},
		},
	}
	resolver := NewResolverFromCache(cache)

	// Different SA should not get the binding.
	ps := resolver.ResolveServiceAccount("other-sa", "kube-system")
	if len(ps.Bindings) != 0 {
		t.Errorf("expected 0 bindings for non-matching SA, got %d", len(ps.Bindings))
	}

	// Same name but different namespace should not match.
	ps2 := resolver.ResolveServiceAccount("admin-sa", "production")
	if len(ps2.Bindings) != 0 {
		t.Errorf("expected 0 bindings for wrong namespace, got %d", len(ps2.Bindings))
	}
}

func TestFindSAsWithSecretAccess_ClusterWide(t *testing.T) {
	cache := &RBACCache{
		Roles: make(map[string]map[string]rbacv1.Role),
		ClusterRoles: map[string]rbacv1.ClusterRole{
			"secret-reader": {
				ObjectMeta: metav1.ObjectMeta{Name: "secret-reader"},
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}},
				},
			},
		},
		RoleBindings: make(map[string][]rbacv1.RoleBinding),
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "secret-crb"},
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.ServiceAccountKind, Name: "traefik", Namespace: "kube-system"},
				},
				RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "secret-reader", APIGroup: "rbac.authorization.k8s.io"},
			},
		},
	}
	resolver := NewResolverFromCache(cache)

	sas := resolver.FindSAsWithSecretAccess("production")

	if len(sas) != 1 {
		t.Fatalf("expected 1 SA with secret access, got %d", len(sas))
	}
	if sas[0] != "kube-system/traefik" {
		t.Errorf("expected kube-system/traefik, got %s", sas[0])
	}
}

func TestFindSAsWithSecretAccess_NamespaceScoped(t *testing.T) {
	cache := &RBACCache{
		Roles: map[string]map[string]rbacv1.Role{
			"production": {
				"secret-manager": {
					ObjectMeta: metav1.ObjectMeta{Name: "secret-manager", Namespace: "production"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list", "create"}},
					},
				},
			},
		},
		ClusterRoles: make(map[string]rbacv1.ClusterRole),
		RoleBindings: map[string][]rbacv1.RoleBinding{
			"production": {
				{
					ObjectMeta: metav1.ObjectMeta{Name: "secret-rb", Namespace: "production"},
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Name: "app-sa", Namespace: "production"},
					},
					RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "secret-manager", APIGroup: "rbac.authorization.k8s.io"},
				},
			},
		},
		ClusterRoleBindings: nil,
	}
	resolver := NewResolverFromCache(cache)

	sas := resolver.FindSAsWithSecretAccess("production")
	if len(sas) != 1 {
		t.Fatalf("expected 1, got %d", len(sas))
	}
	if sas[0] != "production/app-sa" {
		t.Errorf("expected production/app-sa, got %s", sas[0])
	}

	// Different namespace should return empty.
	sas2 := resolver.FindSAsWithSecretAccess("staging")
	if len(sas2) != 0 {
		t.Errorf("expected 0 for staging, got %d", len(sas2))
	}
}

func TestResolveServiceAccount_MissingRole(t *testing.T) {
	// Binding references a role that doesn't exist — should produce 0 rules.
	cache := &RBACCache{
		Roles:        make(map[string]map[string]rbacv1.Role),
		ClusterRoles: make(map[string]rbacv1.ClusterRole),
		RoleBindings: map[string][]rbacv1.RoleBinding{
			"default": {
				{
					ObjectMeta: metav1.ObjectMeta{Name: "orphan-rb", Namespace: "default"},
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Name: "test-sa", Namespace: "default"},
					},
					RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "nonexistent", APIGroup: "rbac.authorization.k8s.io"},
				},
			},
		},
		ClusterRoleBindings: nil,
	}
	resolver := NewResolverFromCache(cache)

	ps := resolver.ResolveServiceAccount("test-sa", "default")

	if len(ps.Bindings) != 1 {
		t.Errorf("expected 1 binding, got %d", len(ps.Bindings))
	}
	if len(ps.Rules) != 0 {
		t.Errorf("expected 0 rules (orphan binding), got %d", len(ps.Rules))
	}
}
