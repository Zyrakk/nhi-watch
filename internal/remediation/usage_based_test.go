package remediation

import (
	"strings"
	"testing"
	"time"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
	"github.com/Zyrakk/nhi-watch/internal/models"
	"github.com/Zyrakk/nhi-watch/internal/usage"
)

func TestRenderFromUsage_BasicOutput(t *testing.T) {
	nhi := &discovery.NonHumanIdentity{
		Name:      "traefik",
		Namespace: "kube-system",
		Type:      discovery.NHITypeServiceAccount,
		Permissions: &models.PermissionSet{
			Rules: []models.ResolvedRule{
				{
					APIGroups: []string{""},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
					Source:    "cluster-admin",
				},
			},
		},
		UsageProfile: &usage.UsageProfile{
			ServiceAccount:  "traefik",
			Namespace:       "kube-system",
			ObservationDays: 30,
			TotalCalls:      1500,
			FirstSeen:       time.Now().AddDate(0, -1, 0),
			LastUpdated:     time.Now(),
			Records: []usage.UsageRecord{
				{Verb: "get", Resource: "services", APIGroup: "", Count: 500, LastSeen: time.Now()},
				{Verb: "list", Resource: "services", APIGroup: "", Count: 400, LastSeen: time.Now()},
				{Verb: "get", Resource: "endpoints", APIGroup: "", Count: 300, LastSeen: time.Now()},
				{Verb: "list", Resource: "ingresses", APIGroup: "networking.k8s.io", Count: 300, LastSeen: time.Now()},
			},
		},
	}

	yaml, err := renderFromUsage(nhi)
	if err != nil {
		t.Fatal(err)
	}

	checks := []struct {
		substr string
		desc   string
	}{
		{"PROPOSAL", "output must contain PROPOSAL marker"},
		{"services", "output must contain services resource"},
		{"endpoints", "output must contain endpoints resource"},
		{"ingresses", "output must contain ingresses resource"},
		{"reduction", "output must contain reduction percentage"},
		{"ClusterRole", "output must contain ClusterRole"},
		{"ClusterRoleBinding", "output must contain ClusterRoleBinding"},
		{"traefik-observed-usage", "role name must follow naming convention"},
		{"kube-system", "output must reference namespace"},
	}
	for _, c := range checks {
		if !strings.Contains(yaml, c.substr) {
			t.Errorf("%s: %q not found in output", c.desc, c.substr)
		}
	}
}

func TestRenderFromUsage_GroupsByAPIGroup(t *testing.T) {
	nhi := &discovery.NonHumanIdentity{
		Name:      "cert-manager",
		Namespace: "cert-manager",
		Type:      discovery.NHITypeServiceAccount,
		Permissions: &models.PermissionSet{
			Rules: []models.ResolvedRule{
				{
					APIGroups: []string{"", "cert-manager.io"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
					Source:    "cluster-admin",
				},
			},
		},
		UsageProfile: &usage.UsageProfile{
			ServiceAccount:  "cert-manager",
			Namespace:       "cert-manager",
			ObservationDays: 14,
			TotalCalls:      800,
			Records: []usage.UsageRecord{
				{Verb: "get", Resource: "secrets", APIGroup: "", Count: 200},
				{Verb: "list", Resource: "secrets", APIGroup: "", Count: 200},
				{Verb: "get", Resource: "certificates", APIGroup: "cert-manager.io", Count: 200},
				{Verb: "list", Resource: "certificates", APIGroup: "cert-manager.io", Count: 200},
			},
		},
	}

	yaml, err := renderFromUsage(nhi)
	if err != nil {
		t.Fatal(err)
	}

	// Both API groups must appear
	if !strings.Contains(yaml, `""`) {
		t.Error("output must contain core API group (empty string)")
	}
	if !strings.Contains(yaml, "cert-manager.io") {
		t.Error("output must contain cert-manager.io API group")
	}

	// Each group should have its own rule block
	count := strings.Count(yaml, "apiGroups:")
	if count != 2 {
		t.Errorf("expected 2 apiGroups rules, got %d", count)
	}

	// With Permissions present, reduction line should appear
	if !strings.Contains(yaml, "reduction") {
		t.Error("output must contain reduction percentage when Permissions is set")
	}
}

func TestRenderFromUsage_NoUsageData(t *testing.T) {
	nhi := &discovery.NonHumanIdentity{
		Name:         "my-sa",
		Namespace:    "default",
		Type:         discovery.NHITypeServiceAccount,
		UsageProfile: nil,
	}

	yaml, err := renderFromUsage(nhi)
	if err != nil {
		t.Fatal(err)
	}
	if yaml != "" {
		t.Error("expected empty string for nil UsageProfile")
	}
}

func TestRenderFromUsage_EmptyRecords(t *testing.T) {
	nhi := &discovery.NonHumanIdentity{
		Name:      "my-sa",
		Namespace: "default",
		Type:      discovery.NHITypeServiceAccount,
		UsageProfile: &usage.UsageProfile{
			ServiceAccount:  "my-sa",
			Namespace:       "default",
			ObservationDays: 10,
			TotalCalls:      0,
			Records:         nil,
		},
	}

	yaml, err := renderFromUsage(nhi)
	if err != nil {
		t.Fatal(err)
	}
	if yaml != "" {
		t.Error("expected empty string for UsageProfile with nil Records")
	}
}

func TestCalculateReduction(t *testing.T) {
	t.Run("wildcard_verbs_explicit_resources", func(t *testing.T) {
		// Current: 4 explicit resources with wildcard verbs = 4 * 6 = 24 pairs
		current := []models.ResolvedRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "services", "endpoints", "secrets"},
				Verbs:     []string{"*"},
				Source:    "some-role",
			},
		}

		// Observed: only 2 verb+resource pairs
		observed := []usage.UsageRecord{
			{Verb: "get", Resource: "services", APIGroup: ""},
			{Verb: "list", Resource: "endpoints", APIGroup: ""},
		}

		reduction := calculateReduction(current, observed)

		// 24 total pairs, 2 observed -> 22 unused -> 22/24*100 = 91%
		if reduction <= 0 {
			t.Errorf("expected positive reduction, got %d", reduction)
		}

		expected := 91
		if reduction != expected {
			t.Errorf("expected reduction of %d%%, got %d%%", expected, reduction)
		}
	})

	t.Run("explicit_verbs_explicit_resources", func(t *testing.T) {
		// Current: 3 resources with 2 explicit verbs = 6 pairs
		current := []models.ResolvedRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "services", "secrets"},
				Verbs:     []string{"get", "list"},
				Source:    "read-role",
			},
		}

		// Observed: 2 of the 6 pairs
		observed := []usage.UsageRecord{
			{Verb: "get", Resource: "pods", APIGroup: ""},
			{Verb: "list", Resource: "services", APIGroup: ""},
		}

		reduction := calculateReduction(current, observed)

		// 6 total, 2 matched -> 4 unused -> 4/6*100 = 66%
		expected := 66
		if reduction != expected {
			t.Errorf("expected reduction of %d%%, got %d%%", expected, reduction)
		}
	})

	t.Run("wildcard_resources_matches_observed", func(t *testing.T) {
		// Current: wildcard resources with wildcard verbs -> 6 wildcard-verb entries
		current := []models.ResolvedRule{
			{
				APIGroups: []string{""},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
				Source:    "cluster-admin",
			},
		}

		// Observed: get and list used -> 2 of 6 wildcard verbs matched
		observed := []usage.UsageRecord{
			{Verb: "get", Resource: "services", APIGroup: ""},
			{Verb: "list", Resource: "endpoints", APIGroup: ""},
		}

		reduction := calculateReduction(current, observed)

		// 6 wildcard verbs total, 2 matched -> 4 unused -> 4/6*100 = 66%
		expected := 66
		if reduction != expected {
			t.Errorf("expected reduction of %d%%, got %d%%", expected, reduction)
		}

		// Verify it's a positive, meaningful reduction (not 100% like the old bug)
		if reduction >= 100 {
			t.Errorf("wildcard resources should not produce 100%% reduction when verbs are observed, got %d%%", reduction)
		}
	})
}
