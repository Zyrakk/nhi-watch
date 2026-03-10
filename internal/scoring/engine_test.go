package scoring

import (
	"testing"
	"time"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
	"github.com/Zyrakk/nhi-watch/internal/models"
)

// ── Helpers ───────────────────────────────────────────────────────────

func makeTestSA(name, namespace string, flags []string, bindings []models.BindingRef) discovery.NonHumanIdentity {
	ps := &models.PermissionSet{
		Bindings: bindings,
		Rules:    make([]models.ResolvedRule, 0),
		Flags:    flags,
		Scope:    models.ScopeNone,
	}
	return discovery.NonHumanIdentity{
		ID:          "test-" + name,
		Type:        discovery.NHITypeServiceAccount,
		Name:        name,
		Namespace:   namespace,
		CreatedAt:   time.Now().Add(-24 * time.Hour),
		Metadata:    map[string]string{"automount_token": "default (true)"},
		Permissions: ps,
	}
}

func makeTestSecret(name, namespace string, createdDaysAgo int, keys []string) discovery.NonHumanIdentity {
	return discovery.NonHumanIdentity{
		ID:        "test-" + name,
		Type:      discovery.NHITypeSecretCredential,
		Name:      name,
		Namespace: namespace,
		CreatedAt: time.Now().Add(-time.Duration(createdDaysAgo) * 24 * time.Hour),
		Stale:     createdDaysAgo > 90,
		Keys:      keys,
		Metadata: map[string]string{
			"credential_keys": "api-key, password",
		},
	}
}

// ── Engine tests ──────────────────────────────────────────────────────

func TestScore_FinalScoreIsMax(t *testing.T) {
	rules := []Rule{
		{
			ID: "LOW_RULE", Severity: SeverityLow, Score: 20,
			AppliesTo: []discovery.NHIType{discovery.NHITypeServiceAccount},
			Evaluate:  func(nhi *discovery.NonHumanIdentity) (bool, string) { return true, "low" },
		},
		{
			ID: "HIGH_RULE", Severity: SeverityHigh, Score: 70,
			AppliesTo: []discovery.NHIType{discovery.NHITypeServiceAccount},
			Evaluate:  func(nhi *discovery.NonHumanIdentity) (bool, string) { return true, "high" },
		},
	}

	engine := NewEngine(rules)
	nhi := makeTestSA("test", "default", nil, nil)
	result := engine.Score(&nhi)

	if result.FinalScore != 70 {
		t.Errorf("expected max score 70, got %d", result.FinalScore)
	}
	if result.BaseScore != 70 {
		t.Errorf("expected base score 70, got %d", result.BaseScore)
	}
	if result.PostureMultiplier != 1.0 {
		t.Errorf("expected posture multiplier 1.0 (no pods), got %f", result.PostureMultiplier)
	}
	if result.FinalSeverity != SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", result.FinalSeverity)
	}
	if len(result.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(result.Results))
	}
}

func TestScore_NoMatchingRules(t *testing.T) {
	rules := []Rule{
		{
			ID: "NEVER_MATCH", Severity: SeverityCritical, Score: 95,
			AppliesTo: []discovery.NHIType{discovery.NHITypeServiceAccount},
			Evaluate:  func(nhi *discovery.NonHumanIdentity) (bool, string) { return false, "" },
		},
	}

	engine := NewEngine(rules)
	nhi := makeTestSA("clean", "default", nil, nil)
	result := engine.Score(&nhi)

	if result.FinalScore != 0 {
		t.Errorf("expected score 0, got %d", result.FinalScore)
	}
	if result.FinalSeverity != SeverityInfo {
		t.Errorf("expected INFO severity, got %s", result.FinalSeverity)
	}
	if len(result.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(result.Results))
	}
}

func TestScore_RuleTypeFiltering(t *testing.T) {
	rules := []Rule{
		{
			ID: "SA_ONLY", Severity: SeverityHigh, Score: 70,
			AppliesTo: []discovery.NHIType{discovery.NHITypeServiceAccount},
			Evaluate:  func(nhi *discovery.NonHumanIdentity) (bool, string) { return true, "sa" },
		},
	}

	engine := NewEngine(rules)

	// SA should match.
	sa := makeTestSA("sa", "default", nil, nil)
	saResult := engine.Score(&sa)
	if len(saResult.Results) != 1 {
		t.Errorf("expected SA to match, got %d results", len(saResult.Results))
	}

	// Secret should NOT match (wrong type).
	secret := makeTestSecret("s", "default", 10, nil)
	secretResult := engine.Score(&secret)
	if len(secretResult.Results) != 0 {
		t.Errorf("expected Secret not to match, got %d results", len(secretResult.Results))
	}
}

func TestScoreAll_SortedByScoreDesc(t *testing.T) {
	rules := []Rule{
		{
			ID: "SCORE_BY_NAME", Severity: SeverityInfo, Score: 10,
			Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) { return true, "" },
		},
		{
			ID: "CRITICAL", Severity: SeverityCritical, Score: 95,
			AppliesTo: []discovery.NHIType{discovery.NHITypeServiceAccount},
			Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
				return nhi.Name == "admin", ""
			},
		},
	}

	engine := NewEngine(rules)
	nhis := []discovery.NonHumanIdentity{
		makeTestSecret("low-secret", "default", 10, nil),
		makeTestSA("admin", "default", nil, nil),
		makeTestSA("viewer", "default", nil, nil),
	}

	results := engine.ScoreAll(nhis)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].Name != "admin" {
		t.Errorf("expected 'admin' first, got %q", results[0].Name)
	}
	if results[0].FinalScore < results[1].FinalScore {
		t.Error("results not sorted by score descending")
	}
}

func TestScore_GeneratesRecommendation(t *testing.T) {
	rules := DefaultRules()
	engine := NewEngine(rules)

	nhi := makeTestSA("admin-sa", "default",
		[]string{"CLUSTER_ADMIN"},
		[]models.BindingRef{
			{Name: "admin-crb", Kind: "ClusterRoleBinding", RoleRef: "cluster-admin", RoleKind: "ClusterRole"},
		},
	)

	result := engine.Score(&nhi)

	if result.Recommendation == "" {
		t.Error("expected non-empty recommendation for cluster-admin SA")
	}
}

// ── Filter and count tests ────────────────────────────────────────────

func TestFilterBySeverity(t *testing.T) {
	results := []ScoringResult{
		{Name: "a", FinalSeverity: SeverityCritical, FinalScore: 95},
		{Name: "b", FinalSeverity: SeverityHigh, FinalScore: 70},
		{Name: "c", FinalSeverity: SeverityMedium, FinalScore: 50},
		{Name: "d", FinalSeverity: SeverityLow, FinalScore: 20},
		{Name: "e", FinalSeverity: SeverityInfo, FinalScore: 0},
	}

	filtered := FilterBySeverity(results, SeverityHigh)
	if len(filtered) != 2 {
		t.Errorf("expected 2 results >= HIGH, got %d", len(filtered))
	}

	filtered = FilterBySeverity(results, SeverityCritical)
	if len(filtered) != 1 {
		t.Errorf("expected 1 CRITICAL result, got %d", len(filtered))
	}

	filtered = FilterBySeverity(results, SeverityInfo)
	if len(filtered) != 5 {
		t.Errorf("expected all 5 results >= INFO, got %d", len(filtered))
	}
}

func TestFilterByType(t *testing.T) {
	results := []ScoringResult{
		{Name: "a", Type: "service-account"},
		{Name: "b", Type: "service-account"},
		{Name: "c", Type: "secret-credential"},
	}

	filtered := FilterByType(results, "service-account")
	if len(filtered) != 2 {
		t.Errorf("expected 2 service-account results, got %d", len(filtered))
	}

	filtered = FilterByType(results, "tls-cert")
	if len(filtered) != 0 {
		t.Errorf("expected 0 tls-cert results, got %d", len(filtered))
	}
}

func TestCountBySeverity(t *testing.T) {
	results := []ScoringResult{
		{FinalSeverity: SeverityCritical},
		{FinalSeverity: SeverityCritical},
		{FinalSeverity: SeverityHigh},
		{FinalSeverity: SeverityInfo},
	}

	counts := CountBySeverity(results)
	if counts[SeverityCritical] != 2 {
		t.Errorf("expected 2 critical, got %d", counts[SeverityCritical])
	}
	if counts[SeverityHigh] != 1 {
		t.Errorf("expected 1 high, got %d", counts[SeverityHigh])
	}
}

func TestCountByTypeAndSeverity(t *testing.T) {
	results := []ScoringResult{
		{Type: "service-account", FinalSeverity: SeverityCritical},
		{Type: "service-account", FinalSeverity: SeverityHigh},
		{Type: "secret-credential", FinalSeverity: SeverityHigh},
	}

	counts := CountByTypeAndSeverity(results)
	if counts["service-account"][SeverityCritical] != 1 {
		t.Error("expected 1 critical SA")
	}
	if counts["service-account"][SeverityHigh] != 1 {
		t.Error("expected 1 high SA")
	}
	if counts["secret-credential"][SeverityHigh] != 1 {
		t.Error("expected 1 high secret")
	}
}

// ── Severity tests ────────────────────────────────────────────────────

func TestSeverityFromScore(t *testing.T) {
	tests := []struct {
		score    int
		expected Severity
	}{
		{100, SeverityCritical},
		{95, SeverityCritical},
		{80, SeverityCritical},
		{79, SeverityHigh},
		{70, SeverityHigh},
		{60, SeverityHigh},
		{59, SeverityMedium},
		{40, SeverityMedium},
		{39, SeverityLow},
		{20, SeverityLow},
		{19, SeverityInfo},
		{0, SeverityInfo},
	}

	for _, tt := range tests {
		got := SeverityFromScore(tt.score)
		if got != tt.expected {
			t.Errorf("SeverityFromScore(%d) = %s, want %s", tt.score, got, tt.expected)
		}
	}
}

func TestSeverityMeetsThreshold(t *testing.T) {
	if !SeverityMeetsThreshold(SeverityCritical, SeverityHigh) {
		t.Error("CRITICAL should meet HIGH threshold")
	}
	if SeverityMeetsThreshold(SeverityLow, SeverityHigh) {
		t.Error("LOW should not meet HIGH threshold")
	}
	if !SeverityMeetsThreshold(SeverityHigh, SeverityHigh) {
		t.Error("HIGH should meet HIGH threshold (equal)")
	}
}

func TestSeverityRank(t *testing.T) {
	if SeverityRank(SeverityCritical) <= SeverityRank(SeverityHigh) {
		t.Error("CRITICAL should rank higher than HIGH")
	}
	if SeverityRank(SeverityInfo) >= SeverityRank(SeverityLow) {
		t.Error("INFO should rank lower than LOW")
	}
}

// ── Posture multiplier integration with engine ───────────────────────

func TestScore_PostureMultiplierBoostsScore(t *testing.T) {
	rules := []Rule{
		{
			ID: "HIGH_RULE", Severity: SeverityHigh, Score: 70,
			AppliesTo: []discovery.NHIType{discovery.NHITypeServiceAccount},
			Evaluate:  func(nhi *discovery.NonHumanIdentity) (bool, string) { return true, "high" },
		},
	}

	engine := NewEngine(rules)
	nhi := makeTestSA("priv-sa", "default", nil, nil)
	nhi.PodPostures = []discovery.PodPosture{
		{PodName: "priv-pod", Namespace: "default", Privileged: true, HostPID: true},
	}
	result := engine.Score(&nhi)

	if result.BaseScore != 70 {
		t.Errorf("expected base score 70, got %d", result.BaseScore)
	}
	if result.PostureMultiplier <= 1.0 {
		t.Errorf("expected posture multiplier > 1.0, got %f", result.PostureMultiplier)
	}
	if result.FinalScore <= 70 {
		t.Errorf("expected final score > 70 (posture boosted), got %d", result.FinalScore)
	}
}

func TestScore_PostureMultiplierNoPodsSameScore(t *testing.T) {
	rules := []Rule{
		{
			ID: "MEDIUM_RULE", Severity: SeverityMedium, Score: 50,
			AppliesTo: []discovery.NHIType{discovery.NHITypeServiceAccount},
			Evaluate:  func(nhi *discovery.NonHumanIdentity) (bool, string) { return true, "medium" },
		},
	}

	engine := NewEngine(rules)
	nhi := makeTestSA("normal-sa", "default", nil, nil)
	result := engine.Score(&nhi)

	if result.BaseScore != result.FinalScore {
		t.Errorf("expected BaseScore == FinalScore when no pods, got base=%d final=%d",
			result.BaseScore, result.FinalScore)
	}
	if result.PostureMultiplier != 1.0 {
		t.Errorf("expected posture multiplier 1.0, got %f", result.PostureMultiplier)
	}
}

func TestScore_PostureSeverityEscalation(t *testing.T) {
	rules := []Rule{
		{
			ID: "HIGH_RULE", Severity: SeverityHigh, Score: 70,
			AppliesTo: []discovery.NHIType{discovery.NHITypeServiceAccount},
			Evaluate:  func(nhi *discovery.NonHumanIdentity) (bool, string) { return true, "high" },
		},
	}

	engine := NewEngine(rules)
	nhi := makeTestSA("risky-sa", "default", nil, nil)
	nhi.PodPostures = []discovery.PodPosture{
		{PodName: "priv-pod", Namespace: "default", Privileged: true, HostPID: true},
	}
	result := engine.Score(&nhi)

	// 70 * 1.30 = 91 → CRITICAL
	if result.FinalScore < 80 {
		t.Errorf("expected final score >= 80 (CRITICAL threshold), got %d", result.FinalScore)
	}
	if result.FinalSeverity != SeverityCritical {
		t.Errorf("expected CRITICAL severity after posture boost, got %s", result.FinalSeverity)
	}
}

func TestIntegration_ClusterAdminWithPrivilegedPod(t *testing.T) {
	engine := NewEngine(DefaultRules())

	nhi := discovery.NonHumanIdentity{
		ID: "sa-admin-priv", Type: discovery.NHITypeServiceAccount,
		Name: "admin-priv-sa", Namespace: "kube-system",
		CreatedAt: time.Now().Add(-30 * 24 * time.Hour),
		Metadata:  map[string]string{"automount_token": "default (true)"},
		Permissions: &models.PermissionSet{
			Bindings: []models.BindingRef{
				{Name: "admin-crb", Kind: "ClusterRoleBinding", RoleRef: "cluster-admin", RoleKind: "ClusterRole"},
			},
			Flags: []string{"CLUSTER_ADMIN", "WILDCARD_VERBS", "WILDCARD_RESOURCES", "WILDCARD_APIGROUPS",
				"SECRET_ACCESS_CLUSTER_WIDE", "CROSS_NAMESPACE_SECRET_ACCESS"},
		},
		PodPostures: []discovery.PodPosture{
			{PodName: "admin-pod", Namespace: "kube-system", Privileged: true, HostPID: true},
		},
	}

	result := engine.Score(&nhi)

	if result.BaseScore != 95 {
		t.Errorf("expected base score 95, got %d", result.BaseScore)
	}
	if result.FinalScore <= 95 {
		t.Errorf("expected final score > 95 with privileged pod, got %d", result.FinalScore)
	}
	if result.FinalScore > 100 {
		t.Errorf("expected final score <= 100, got %d", result.FinalScore)
	}
	if result.FinalSeverity != SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", result.FinalSeverity)
	}
}
