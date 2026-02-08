package permissions

import (
	"testing"

	"github.com/Zyrakk/nhi-watch/internal/models"
)

func TestAnalyze_ClusterAdmin(t *testing.T) {
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "admin-crb", Kind: "ClusterRoleBinding", RoleRef: "cluster-admin", RoleKind: "ClusterRole"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}, Source: "cluster-admin"},
		},
	}

	Analyze(ps, "admin-sa", "kube-system")

	assertHasFlag(t, ps, FlagClusterAdmin)
	assertHasFlag(t, ps, FlagWildcardVerbs)
	assertHasFlag(t, ps, FlagWildcardResources)
	assertHasFlag(t, ps, FlagWildcardAPIGroups)
	assertHasFlag(t, ps, FlagSecretAccessClusterWide)

	if ps.Scope != models.ScopeClusterWide {
		t.Errorf("expected scope cluster-wide, got %s", ps.Scope)
	}
}

func TestAnalyze_WildcardVerbs(t *testing.T) {
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "test-rb", Kind: "RoleBinding", Namespace: "default", RoleRef: "all-verbs", RoleKind: "Role"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}, Source: "all-verbs"},
		},
	}

	Analyze(ps, "test-sa", "default")

	assertHasFlag(t, ps, FlagWildcardVerbs)
	assertNotHasFlag(t, ps, FlagWildcardResources)
	assertNotHasFlag(t, ps, FlagClusterAdmin)
}

func TestAnalyze_WildcardResources(t *testing.T) {
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "test-rb", Kind: "RoleBinding", Namespace: "default", RoleRef: "all-res", RoleKind: "Role"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get", "list"}, Source: "all-res"},
		},
	}

	Analyze(ps, "test-sa", "default")

	assertHasFlag(t, ps, FlagWildcardResources)
	assertNotHasFlag(t, ps, FlagWildcardVerbs)
}

func TestAnalyze_WildcardAPIGroups(t *testing.T) {
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "test-crb", Kind: "ClusterRoleBinding", RoleRef: "wide-role", RoleKind: "ClusterRole"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{"*"}, Resources: []string{"pods"}, Verbs: []string{"get"}, Source: "wide-role"},
		},
	}

	Analyze(ps, "test-sa", "default")

	assertHasFlag(t, ps, FlagWildcardAPIGroups)
}

func TestAnalyze_SecretAccessClusterWide(t *testing.T) {
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "traefik-crb", Kind: "ClusterRoleBinding", RoleRef: "traefik-role", RoleKind: "ClusterRole"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list", "watch"}, Source: "traefik-role"},
			{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"get", "list"}, Source: "traefik-role"},
		},
	}

	Analyze(ps, "traefik", "kube-system")

	assertHasFlag(t, ps, FlagSecretAccessClusterWide)
	assertHasFlag(t, ps, FlagCrossNamespaceSecretAccess)
}

func TestAnalyze_SecretAccessClusterWide_NotTriggeredForRoleBinding(t *testing.T) {
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "secret-rb", Kind: "RoleBinding", Namespace: "production", RoleRef: "secret-reader", RoleKind: "Role"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}, Source: "secret-reader"},
		},
	}

	Analyze(ps, "my-sa", "production")

	assertNotHasFlag(t, ps, FlagSecretAccessClusterWide)
	assertNotHasFlag(t, ps, FlagCrossNamespaceSecretAccess)
}

func TestAnalyze_DefaultSAHasBindings(t *testing.T) {
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "default-edit-rb", Kind: "RoleBinding", Namespace: "production", RoleRef: "edit", RoleKind: "ClusterRole"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "create"}, Source: "edit"},
		},
	}

	Analyze(ps, "default", "production")

	assertHasFlag(t, ps, FlagDefaultSAHasBindings)
}

func TestAnalyze_DefaultSANoBindings(t *testing.T) {
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{},
		Rules:    []models.ResolvedRule{},
	}

	Analyze(ps, "default", "production")

	assertNotHasFlag(t, ps, FlagDefaultSAHasBindings)
}

func TestAnalyze_CrossNamespaceSecretAccess_ViaRoleBinding(t *testing.T) {
	// SA in "ci" has a RoleBinding in "production" that grants secret access.
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "cross-ns-rb", Kind: "RoleBinding", Namespace: "production", RoleRef: "secret-reader", RoleKind: "Role"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}, Source: "secret-reader"},
		},
	}

	Analyze(ps, "ci-sa", "ci")

	assertHasFlag(t, ps, FlagCrossNamespaceSecretAccess)
}

func TestAnalyze_NoCrossNamespace_SameNamespace(t *testing.T) {
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "local-rb", Kind: "RoleBinding", Namespace: "production", RoleRef: "secret-reader", RoleKind: "Role"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}, Source: "secret-reader"},
		},
	}

	Analyze(ps, "app-sa", "production")

	assertNotHasFlag(t, ps, FlagCrossNamespaceSecretAccess)
}

func TestAnalyze_ScopeNone(t *testing.T) {
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{},
		Rules:    []models.ResolvedRule{},
	}

	Analyze(ps, "unused-sa", "default")

	if ps.Scope != models.ScopeNone {
		t.Errorf("expected scope none, got %s", ps.Scope)
	}
}

func TestAnalyze_ScopeClusterWide(t *testing.T) {
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "crb", Kind: "ClusterRoleBinding", RoleRef: "editor", RoleKind: "ClusterRole"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create", "delete"}, Source: "editor"},
		},
	}

	Analyze(ps, "editor-sa", "default")

	if ps.Scope != models.ScopeClusterWide {
		t.Errorf("expected scope cluster-wide, got %s", ps.Scope)
	}
}

func TestAnalyze_ScopeClusterWide_ViewOnly(t *testing.T) {
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "view-crb", Kind: "ClusterRoleBinding", RoleRef: "view-only", RoleKind: "ClusterRole"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}, Source: "view-only"},
		},
	}

	Analyze(ps, "viewer-sa", "default")

	// Even view-only via CRB is still cluster-wide scope.
	if ps.Scope != models.ScopeClusterWide {
		t.Errorf("expected scope cluster-wide, got %s", ps.Scope)
	}
}

func TestAnalyze_ScopeNamespaced(t *testing.T) {
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "edit-rb", Kind: "RoleBinding", Namespace: "production", RoleRef: "edit", RoleKind: "ClusterRole"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create", "update", "delete"}, Source: "edit"},
		},
	}

	Analyze(ps, "deployer", "production")

	if ps.Scope != models.ScopeNamespaced {
		t.Errorf("expected scope namespace-scoped, got %s", ps.Scope)
	}
}

func TestAnalyze_ScopeMinimal(t *testing.T) {
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "view-rb", Kind: "RoleBinding", Namespace: "production", RoleRef: "viewer", RoleKind: "Role"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}, Source: "viewer"},
		},
	}

	Analyze(ps, "app-sa", "production")

	if ps.Scope != models.ScopeMinimal {
		t.Errorf("expected scope minimal, got %s", ps.Scope)
	}
}

func TestAnalyze_WildcardResource_WithSecretInCore(t *testing.T) {
	// Wildcard resources in core API group — should flag secret access.
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "wide-crb", Kind: "ClusterRoleBinding", RoleRef: "wide-role", RoleKind: "ClusterRole"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get", "list"}, Source: "wide-role"},
		},
	}

	Analyze(ps, "wide-sa", "default")

	assertHasFlag(t, ps, FlagWildcardResources)
	assertHasFlag(t, ps, FlagSecretAccessClusterWide)
}

func TestAnalyze_NoFalsePositive_NonCoreAPIGroup(t *testing.T) {
	// "secrets" in a non-core API group should NOT trigger secret access flags.
	ps := &models.PermissionSet{
		Bindings: []models.BindingRef{
			{Name: "custom-crb", Kind: "ClusterRoleBinding", RoleRef: "custom-role", RoleKind: "ClusterRole"},
		},
		Rules: []models.ResolvedRule{
			{APIGroups: []string{"custom.io"}, Resources: []string{"secrets"}, Verbs: []string{"get"}, Source: "custom-role"},
		},
	}

	Analyze(ps, "custom-sa", "default")

	assertNotHasFlag(t, ps, FlagSecretAccessClusterWide)
}

// --- helpers ---

func assertHasFlag(t *testing.T, ps *models.PermissionSet, flag string) {
	t.Helper()
	for _, f := range ps.Flags {
		if f == flag {
			return
		}
	}
	t.Errorf("expected flag %q, flags are: %v", flag, ps.Flags)
}

func assertNotHasFlag(t *testing.T, ps *models.PermissionSet, flag string) {
	t.Helper()
	for _, f := range ps.Flags {
		if f == flag {
			t.Errorf("did not expect flag %q, flags are: %v", flag, ps.Flags)
			return
		}
	}
}
