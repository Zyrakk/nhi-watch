package scoring

import (
	"testing"
	"time"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
	"github.com/Zyrakk/nhi-watch/internal/models"
)

// ══════════════════════════════════════════════════════════════════════
//  Test helpers
// ══════════════════════════════════════════════════════════════════════

func saWithFlags(name, namespace string, flags []string, bindings []models.BindingRef) *discovery.NonHumanIdentity {
	return &discovery.NonHumanIdentity{
		ID:        "test-" + name,
		Type:      discovery.NHITypeServiceAccount,
		Name:      name,
		Namespace: namespace,
		CreatedAt: time.Now().Add(-24 * time.Hour),
		Metadata:  map[string]string{"automount_token": "default (true)"},
		Permissions: &models.PermissionSet{
			Bindings: bindings,
			Rules:    make([]models.ResolvedRule, 0),
			Flags:    flags,
			Scope:    models.ScopeNone,
		},
	}
}

func saNoPermissions(name, namespace string) *discovery.NonHumanIdentity {
	return &discovery.NonHumanIdentity{
		ID:        "test-" + name,
		Type:      discovery.NHITypeServiceAccount,
		Name:      name,
		Namespace: namespace,
		CreatedAt: time.Now(),
		Metadata:  map[string]string{"automount_token": "default (true)"},
	}
}

func secretCredential(name, namespace string, createdDaysAgo int, keys []string, credKeys string) *discovery.NonHumanIdentity {
	return &discovery.NonHumanIdentity{
		ID:        "test-" + name,
		Type:      discovery.NHITypeSecretCredential,
		Name:      name,
		Namespace: namespace,
		CreatedAt: time.Now().Add(-time.Duration(createdDaysAgo) * 24 * time.Hour),
		Stale:     createdDaysAgo > 90,
		Keys:      keys,
		Metadata: map[string]string{
			"credential_keys": credKeys,
		},
	}
}

func tlsCert(name, namespace string, expiresIn time.Duration, subject string) *discovery.NonHumanIdentity {
	nhi := &discovery.NonHumanIdentity{
		ID:        "test-" + name,
		Type:      discovery.NHITypeTLSCert,
		Name:      name,
		Namespace: namespace,
		CreatedAt: time.Now().Add(-30 * 24 * time.Hour),
		ExpiresAt: time.Now().Add(expiresIn),
		Metadata:  map[string]string{},
	}
	if subject != "" {
		nhi.Metadata["subject"] = subject
	}
	return nhi
}

func certManagerCert(name, namespace string, ready string, expiresIn time.Duration, issuer string) *discovery.NonHumanIdentity {
	nhi := &discovery.NonHumanIdentity{
		ID:        "test-" + name,
		Type:      discovery.NHITypeCertManagerCertificate,
		Name:      name,
		Namespace: namespace,
		CreatedAt: time.Now().Add(-10 * 24 * time.Hour),
		Issuer:    issuer,
		Metadata:  map[string]string{},
	}
	if ready != "" {
		nhi.Metadata["ready"] = ready
	}
	if expiresIn != 0 {
		nhi.ExpiresAt = time.Now().Add(expiresIn)
	}
	return nhi
}

// ══════════════════════════════════════════════════════════════════════
//  ServiceAccount rule tests
// ══════════════════════════════════════════════════════════════════════

func TestRule_ClusterAdminBinding_Match(t *testing.T) {
	rule := ruleClusterAdminBinding()
	nhi := saWithFlags("admin-sa", "kube-system",
		[]string{"CLUSTER_ADMIN"},
		[]models.BindingRef{
			{Name: "admin-crb", Kind: "ClusterRoleBinding", RoleRef: "cluster-admin", RoleKind: "ClusterRole"},
		},
	)

	matched, detail := rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match for cluster-admin SA")
	}
	if detail == "" {
		t.Error("expected non-empty detail")
	}
}

func TestRule_ClusterAdminBinding_NoMatch(t *testing.T) {
	rule := ruleClusterAdminBinding()

	// SA without cluster-admin flag.
	nhi := saWithFlags("normal-sa", "default", []string{"WILDCARD_VERBS"}, nil)
	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match SA without CLUSTER_ADMIN flag")
	}

	// SA with nil permissions.
	nhi2 := saNoPermissions("no-perms", "default")
	matched, _ = rule.Evaluate(nhi2)
	if matched {
		t.Error("should not match SA with nil permissions")
	}
}

func TestRule_WildcardPermissions_Match(t *testing.T) {
	rule := ruleWildcardPermissions()

	tests := []struct {
		name  string
		flags []string
	}{
		{"wildcard verbs", []string{"WILDCARD_VERBS"}},
		{"wildcard resources", []string{"WILDCARD_RESOURCES"}},
		{"wildcard apigroups", []string{"WILDCARD_APIGROUPS"}},
		{"multiple wildcards", []string{"WILDCARD_VERBS", "WILDCARD_RESOURCES", "WILDCARD_APIGROUPS"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nhi := saWithFlags("wild-sa", "default", tt.flags, nil)
			matched, detail := rule.Evaluate(nhi)
			if !matched {
				t.Fatalf("expected match for %s", tt.name)
			}
			if detail == "" {
				t.Error("expected non-empty detail")
			}
		})
	}
}

func TestRule_WildcardPermissions_NoMatch(t *testing.T) {
	rule := ruleWildcardPermissions()
	nhi := saWithFlags("clean-sa", "default", []string{"SECRET_ACCESS_CLUSTER_WIDE"}, nil)
	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match SA without wildcard flags")
	}
}

func TestRule_DefaultSAHasBindings_Match(t *testing.T) {
	rule := ruleDefaultSAHasBindings()
	nhi := saWithFlags("default", "production", nil,
		[]models.BindingRef{
			{Name: "edit-rb", Kind: "RoleBinding", Namespace: "production", RoleRef: "edit", RoleKind: "ClusterRole"},
		},
	)

	matched, detail := rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match for default SA with bindings")
	}
	if detail == "" {
		t.Error("expected non-empty detail")
	}
}

func TestRule_DefaultSAHasBindings_NoMatch(t *testing.T) {
	rule := ruleDefaultSAHasBindings()

	// Non-default SA with bindings → no match.
	nhi := saWithFlags("my-sa", "default", nil,
		[]models.BindingRef{{Name: "rb", Kind: "RoleBinding", RoleRef: "edit"}},
	)
	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match non-default SA")
	}

	// Default SA without bindings → no match.
	nhi2 := saWithFlags("default", "default", nil, nil)
	matched, _ = rule.Evaluate(nhi2)
	if matched {
		t.Error("should not match default SA with no bindings")
	}
}

func TestRule_SecretAccessClusterWide_Match(t *testing.T) {
	rule := ruleSecretAccessClusterWide()
	nhi := saWithFlags("traefik", "kube-system", []string{"SECRET_ACCESS_CLUSTER_WIDE"}, nil)
	matched, _ := rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match for SA with SECRET_ACCESS_CLUSTER_WIDE")
	}
}

func TestRule_SecretAccessClusterWide_NoMatch(t *testing.T) {
	rule := ruleSecretAccessClusterWide()
	nhi := saWithFlags("app", "default", []string{"CROSS_NAMESPACE_SECRET_ACCESS"}, nil)
	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match without SECRET_ACCESS_CLUSTER_WIDE flag")
	}
}

func TestRule_CrossNamespaceSecretAccess_Match(t *testing.T) {
	rule := ruleCrossNamespaceSecretAccess()
	nhi := saWithFlags("worker", "ci", []string{"CROSS_NAMESPACE_SECRET_ACCESS"}, nil)
	matched, detail := rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match")
	}
	if detail == "" {
		t.Error("expected non-empty detail")
	}
}

func TestRule_CrossNamespaceSecretAccess_NoMatch(t *testing.T) {
	rule := ruleCrossNamespaceSecretAccess()
	nhi := saWithFlags("app", "production", nil, nil)
	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match without flag")
	}
}

func TestRule_AutomountTokenEnabled_Match(t *testing.T) {
	rule := ruleAutomountTokenEnabled()

	// SA with bindings and default automount.
	nhi := saWithFlags("deployer", "production", nil,
		[]models.BindingRef{{Name: "rb", Kind: "RoleBinding", RoleRef: "edit"}},
	)
	nhi.Metadata["automount_token"] = "default (true)"

	matched, _ := rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match for SA with bindings and default automount")
	}

	// SA with bindings and explicit true.
	nhi.Metadata["automount_token"] = "true"
	matched, _ = rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match for SA with bindings and automount=true")
	}
}

func TestRule_AutomountTokenEnabled_NoMatch(t *testing.T) {
	rule := ruleAutomountTokenEnabled()

	// SA with automount=false.
	nhi := saWithFlags("secure", "default", nil,
		[]models.BindingRef{{Name: "rb", Kind: "RoleBinding", RoleRef: "edit"}},
	)
	nhi.Metadata["automount_token"] = "false"
	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match SA with automount=false")
	}

	// SA with no bindings (even with automount=true).
	nhi2 := saWithFlags("no-bindings", "default", nil, nil)
	nhi2.Metadata["automount_token"] = "default (true)"
	matched, _ = rule.Evaluate(nhi2)
	if matched {
		t.Error("should not match SA with no bindings (handled by NO_BINDINGS_BUT_AUTOMOUNT)")
	}
}

func TestRule_NoBindingsButAutomount_Match(t *testing.T) {
	rule := ruleNoBindingsButAutomount()
	nhi := saWithFlags("orphan", "default", nil, nil) // no bindings
	nhi.Metadata["automount_token"] = "default (true)"

	matched, _ := rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match for SA with no bindings and automount enabled")
	}
}

func TestRule_NoBindingsButAutomount_NoMatch(t *testing.T) {
	rule := ruleNoBindingsButAutomount()

	// SA with bindings → no match (handled by AUTOMOUNT_TOKEN_ENABLED).
	nhi := saWithFlags("with-bindings", "default", nil,
		[]models.BindingRef{{Name: "rb", Kind: "RoleBinding", RoleRef: "view"}},
	)
	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match SA with bindings")
	}

	// SA with automount=false → no match.
	nhi2 := saWithFlags("secure", "default", nil, nil)
	nhi2.Metadata["automount_token"] = "false"
	matched, _ = rule.Evaluate(nhi2)
	if matched {
		t.Error("should not match SA with automount=false")
	}
}

// ══════════════════════════════════════════════════════════════════════
//  Secret rule tests
// ══════════════════════════════════════════════════════════════════════

func TestRule_SecretNotRotated180D_Match(t *testing.T) {
	rule := ruleSecretNotRotated180D()
	nhi := secretCredential("old-api-key", "production", 200, nil, "api_key, api_secret")

	matched, detail := rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match for 200-day-old secret")
	}
	if detail == "" {
		t.Error("expected non-empty detail")
	}
}

func TestRule_SecretNotRotated180D_NoMatch(t *testing.T) {
	rule := ruleSecretNotRotated180D()
	nhi := secretCredential("fresh", "default", 100, nil, "password")

	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match 100-day-old secret")
	}
}

func TestRule_SecretNotRotated90D_Match(t *testing.T) {
	rule := ruleSecretNotRotated90D()
	nhi := secretCredential("stale-cred", "production", 120, nil, "db-password")

	matched, detail := rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match for 120-day-old secret")
	}
	if detail == "" {
		t.Error("expected non-empty detail")
	}
}

func TestRule_SecretNotRotated90D_NoMatch(t *testing.T) {
	rule := ruleSecretNotRotated90D()
	nhi := secretCredential("new-cred", "default", 30, nil, "token")

	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match 30-day-old secret")
	}
}

func TestRule_TLSCertExpired_Match(t *testing.T) {
	rule := ruleTLSCertExpired()
	nhi := tlsCert("expired-tls", "default", -10*24*time.Hour, "expired.example.com")

	matched, detail := rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match for expired TLS cert")
	}
	if detail == "" {
		t.Error("expected non-empty detail")
	}
}

func TestRule_TLSCertExpired_NoMatch(t *testing.T) {
	rule := ruleTLSCertExpired()

	// Valid cert.
	nhi := tlsCert("valid-tls", "default", 365*24*time.Hour, "valid.example.com")
	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match valid cert")
	}

	// Cert with zero expiry.
	nhi2 := &discovery.NonHumanIdentity{
		Type:     discovery.NHITypeTLSCert,
		Metadata: map[string]string{},
	}
	matched, _ = rule.Evaluate(nhi2)
	if matched {
		t.Error("should not match cert with zero ExpiresAt")
	}
}

func TestRule_TLSCertExpires30D_Match(t *testing.T) {
	rule := ruleTLSCertExpires30D()
	nhi := tlsCert("expiring-tls", "production", 15*24*time.Hour, "web.example.com")

	matched, detail := rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match for cert expiring in 15 days")
	}
	if detail == "" {
		t.Error("expected non-empty detail")
	}
}

func TestRule_TLSCertExpires30D_NoMatch(t *testing.T) {
	rule := ruleTLSCertExpires30D()

	// Cert expiring in 60 days → no match.
	nhi := tlsCert("ok-tls", "default", 60*24*time.Hour, "ok.example.com")
	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match cert expiring in 60 days")
	}

	// Already expired → no match (handled by TLS_CERT_EXPIRED).
	nhi2 := tlsCert("dead-tls", "default", -5*24*time.Hour, "dead.example.com")
	matched, _ = rule.Evaluate(nhi2)
	if matched {
		t.Error("should not match already expired cert")
	}
}

func TestRule_TLSCertExpires90D_Match(t *testing.T) {
	rule := ruleTLSCertExpires90D()
	nhi := tlsCert("soon-tls", "default", 60*24*time.Hour, "soon.example.com")

	matched, _ := rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match for cert expiring in 60 days")
	}
}

func TestRule_TLSCertExpires90D_NoMatch(t *testing.T) {
	rule := ruleTLSCertExpires90D()

	// Cert expiring in 120 days → no match.
	nhi := tlsCert("far-tls", "default", 120*24*time.Hour, "far.example.com")
	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match cert expiring in 120 days")
	}
}

func TestRule_ContainsPrivateKey_Match(t *testing.T) {
	rule := ruleContainsPrivateKey()

	tests := []struct {
		name string
		keys []string
	}{
		{"private-key", []string{"private-key", "hostname"}},
		{"private_key", []string{"config", "private_key"}},
		{"ssh-private-key", []string{"ssh-private-key"}},
		{".key suffix", []string{"ca.key", "hostname"}},
		{"signing.key", []string{"signing.key"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nhi := secretCredential("secret-with-key", "default", 10, tt.keys, "")
			matched, _ := rule.Evaluate(nhi)
			if !matched {
				t.Fatalf("expected match for keys: %v", tt.keys)
			}
		})
	}
}

func TestRule_ContainsPrivateKey_NoMatch(t *testing.T) {
	rule := ruleContainsPrivateKey()
	nhi := secretCredential("normal-secret", "default", 10,
		[]string{"password", "api-key", "hostname", "config.yaml"}, "")

	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match secret without private key patterns")
	}
}

// ══════════════════════════════════════════════════════════════════════
//  cert-manager Certificate rule tests
// ══════════════════════════════════════════════════════════════════════

func TestRule_CertNotReady_Match(t *testing.T) {
	rule := ruleCertNotReady()
	nhi := certManagerCert("failing-cert", "default", "False", 365*24*time.Hour, "ClusterIssuer:letsencrypt")
	nhi.Metadata["ready_reason"] = "IssuerNotReady"

	matched, detail := rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match for not-ready cert")
	}
	if detail == "" {
		t.Error("expected non-empty detail")
	}
}

func TestRule_CertNotReady_NoMatch(t *testing.T) {
	rule := ruleCertNotReady()

	// Ready cert.
	nhi := certManagerCert("ok-cert", "default", "True", 365*24*time.Hour, "")
	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match ready cert")
	}

	// Cert without ready status (empty).
	nhi2 := certManagerCert("new-cert", "default", "", 365*24*time.Hour, "")
	matched, _ = rule.Evaluate(nhi2)
	if matched {
		t.Error("should not match cert without ready status")
	}
}

func TestRule_CertExpires30D_Match(t *testing.T) {
	rule := ruleCertExpires30D()
	nhi := certManagerCert("short-cert", "default", "True", 20*24*time.Hour, "ClusterIssuer:le")

	matched, detail := rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match for cert expiring in 20 days")
	}
	if detail == "" {
		t.Error("expected non-empty detail")
	}
}

func TestRule_CertExpires30D_NoMatch(t *testing.T) {
	rule := ruleCertExpires30D()
	nhi := certManagerCert("long-cert", "default", "True", 60*24*time.Hour, "")

	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match cert expiring in 60 days")
	}
}

func TestRule_CertExpires90D_Match(t *testing.T) {
	rule := ruleCertExpires90D()
	nhi := certManagerCert("medium-cert", "default", "True", 45*24*time.Hour, "Issuer:ca")

	matched, _ := rule.Evaluate(nhi)
	if !matched {
		t.Fatal("expected match for cert expiring in 45 days")
	}
}

func TestRule_CertExpires90D_NoMatch(t *testing.T) {
	rule := ruleCertExpires90D()
	nhi := certManagerCert("safe-cert", "default", "True", 180*24*time.Hour, "")

	matched, _ := rule.Evaluate(nhi)
	if matched {
		t.Error("should not match cert expiring in 180 days")
	}
}

// ══════════════════════════════════════════════════════════════════════
//  Integration tests
// ══════════════════════════════════════════════════════════════════════

func TestAllRulesHaveCISMapping(t *testing.T) {
	rules := DefaultRules()
	rulesWithCIS := map[string]bool{
		"CLUSTER_ADMIN_BINDING":         true, // 5.1.1
		"WILDCARD_PERMISSIONS":          true, // 5.1.3
		"DEFAULT_SA_HAS_BINDINGS":       true, // 5.1.5
		"SECRET_ACCESS_CLUSTER_WIDE":    true, // 5.1.2
		"CROSS_NAMESPACE_SECRET_ACCESS": true, // 5.1.2
		"AUTOMOUNT_TOKEN_ENABLED":       true, // 5.1.6
		"NO_BINDINGS_BUT_AUTOMOUNT":     true, // 5.1.6
		"CONTAINS_PRIVATE_KEY":          true, // 5.4.1
	}
	for _, rule := range rules {
		if rulesWithCIS[rule.ID] {
			if len(rule.CISControls) == 0 {
				t.Errorf("Rule %s should have CIS controls mapped", rule.ID)
			}
		}
	}
}

func TestDefaultRules_Sanity(t *testing.T) {
	rules := DefaultRules()

	if len(rules) != 18 {
		t.Errorf("expected 18 default rules, got %d", len(rules))
	}

	// Check no duplicate IDs.
	seen := make(map[string]bool)
	for _, r := range rules {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID: %s", r.ID)
		}
		seen[r.ID] = true

		if r.Score < 0 || r.Score > 100 {
			t.Errorf("rule %s has invalid score: %d", r.ID, r.Score)
		}
		if r.Evaluate == nil {
			t.Errorf("rule %s has nil Evaluate function", r.ID)
		}
		if r.Description == "" {
			t.Errorf("rule %s has empty description", r.ID)
		}
	}
}

func TestIntegration_MixedNHIs(t *testing.T) {
	origNow := nowFunc
	defer func() { nowFunc = origNow }()
	fixedNow := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	nowFunc = func() time.Time { return fixedNow }

	engine := NewEngine(DefaultRules())

	nhis := []discovery.NonHumanIdentity{
		// 1. Cluster-admin SA → CRITICAL (95)
		{
			ID: "sa-admin", Type: discovery.NHITypeServiceAccount,
			Name: "admin-sa", Namespace: "kube-system",
			CreatedAt: fixedNow.Add(-30 * 24 * time.Hour),
			Metadata:  map[string]string{"automount_token": "default (true)"},
			Permissions: &models.PermissionSet{
				Bindings: []models.BindingRef{
					{Name: "admin-crb", Kind: "ClusterRoleBinding", RoleRef: "cluster-admin", RoleKind: "ClusterRole"},
				},
				Flags: []string{"CLUSTER_ADMIN", "WILDCARD_VERBS", "WILDCARD_RESOURCES", "WILDCARD_APIGROUPS",
					"SECRET_ACCESS_CLUSTER_WIDE", "CROSS_NAMESPACE_SECRET_ACCESS"},
			},
		},
		// 2. Stale secret > 180 days → CRITICAL (90)
		{
			ID: "sec-old", Type: discovery.NHITypeSecretCredential,
			Name: "old-api-key", Namespace: "production",
			CreatedAt: fixedNow.Add(-200 * 24 * time.Hour),
			Stale:     true,
			Keys:      []string{"api-key", "password"},
			Metadata:  map[string]string{"credential_keys": "api-key, password"},
		},
		// 3. Clean SA with automount but no bindings → INFO (10)
		{
			ID: "sa-clean", Type: discovery.NHITypeServiceAccount,
			Name: "clean-sa", Namespace: "default",
			CreatedAt: fixedNow.Add(-10 * 24 * time.Hour),
			Metadata:  map[string]string{"automount_token": "default (true)"},
			Permissions: &models.PermissionSet{
				Bindings: nil,
				Flags:    nil,
			},
		},
		// 4. TLS cert expiring in 15 days → HIGH (70)
		{
			ID: "tls-exp", Type: discovery.NHITypeTLSCert,
			Name: "expiring-cert", Namespace: "production",
			CreatedAt: fixedNow.Add(-350 * 24 * time.Hour),
			ExpiresAt: fixedNow.Add(15 * 24 * time.Hour),
			Metadata:  map[string]string{"subject": "web.example.com"},
		},
		// 5. Healthy cert-manager cert → INFO (0)
		{
			ID: "cm-ok", Type: discovery.NHITypeCertManagerCertificate,
			Name: "healthy-cert", Namespace: "cert-manager",
			CreatedAt: fixedNow.Add(-5 * 24 * time.Hour),
			ExpiresAt: fixedNow.Add(300 * 24 * time.Hour),
			Issuer:    "ClusterIssuer:letsencrypt",
			Metadata:  map[string]string{"ready": "True"},
		},
	}

	results := engine.ScoreAll(nhis)

	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}

	// Results should be sorted by score descending.
	if results[0].FinalScore < results[1].FinalScore {
		t.Error("results not sorted by score descending")
	}

	// Verify expected severities.
	expectedSeverities := map[string]Severity{
		"admin-sa":      SeverityCritical,
		"old-api-key":   SeverityCritical,
		"expiring-cert": SeverityHigh,
		"clean-sa":      SeverityInfo,
		"healthy-cert":  SeverityInfo,
	}

	for _, r := range results {
		expected, ok := expectedSeverities[r.Name]
		if !ok {
			continue
		}
		if r.FinalSeverity != expected {
			t.Errorf("%s: expected severity %s, got %s (score: %d, rules: %d)",
				r.Name, expected, r.FinalSeverity, r.FinalScore, len(r.Results))
		}
	}

	// Admin SA should have multiple findings.
	for _, r := range results {
		if r.Name == "admin-sa" {
			if len(r.Results) < 3 {
				t.Errorf("admin-sa expected 3+ findings, got %d", len(r.Results))
			}
			if r.FinalScore != 95 {
				t.Errorf("admin-sa expected score 95, got %d", r.FinalScore)
			}
		}
	}

	// Counts.
	counts := CountBySeverity(results)
	if counts[SeverityCritical] != 2 {
		t.Errorf("expected 2 CRITICAL, got %d", counts[SeverityCritical])
	}
	if counts[SeverityHigh] != 1 {
		t.Errorf("expected 1 HIGH, got %d", counts[SeverityHigh])
	}
}

func TestIntegration_RecommendationsGenerated(t *testing.T) {
	engine := NewEngine(DefaultRules())

	nhi := discovery.NonHumanIdentity{
		ID: "sa-admin", Type: discovery.NHITypeServiceAccount,
		Name: "bad-sa", Namespace: "default",
		CreatedAt: time.Now(),
		Metadata:  map[string]string{"automount_token": "default (true)"},
		Permissions: &models.PermissionSet{
			Bindings: []models.BindingRef{
				{Name: "crb", Kind: "ClusterRoleBinding", RoleRef: "cluster-admin", RoleKind: "ClusterRole"},
			},
			Flags: []string{"CLUSTER_ADMIN", "WILDCARD_VERBS", "SECRET_ACCESS_CLUSTER_WIDE"},
		},
	}

	result := engine.Score(&nhi)

	if result.Recommendation == "" {
		t.Fatal("expected recommendation for high-risk SA")
	}
	// Should contain advice for multiple rules.
	if len(result.Results) < 3 {
		t.Errorf("expected at least 3 matching rules, got %d", len(result.Results))
	}
}

func TestRule_BothRotationRulesMatch_For200DaySecret(t *testing.T) {
	origNow := nowFunc
	defer func() { nowFunc = origNow }()
	nowFunc = func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }

	engine := NewEngine(DefaultRules())
	nhi := discovery.NonHumanIdentity{
		ID: "sec-old", Type: discovery.NHITypeSecretCredential,
		Name: "ancient-secret", Namespace: "production",
		CreatedAt: nowFunc().Add(-200 * 24 * time.Hour),
		Stale:     true,
		Metadata:  map[string]string{"credential_keys": "password"},
	}

	result := engine.Score(&nhi)

	// Both 90D and 180D rules should match.
	found90, found180 := false, false
	for _, rr := range result.Results {
		if rr.RuleID == "SECRET_NOT_ROTATED_90D" {
			found90 = true
		}
		if rr.RuleID == "SECRET_NOT_ROTATED_180D" {
			found180 = true
		}
	}

	if !found90 || !found180 {
		t.Errorf("expected both rotation rules to match: 90D=%v, 180D=%v", found90, found180)
	}

	// Final score should be 90 (max of 75, 90).
	if result.FinalScore != 90 {
		t.Errorf("expected max score 90, got %d", result.FinalScore)
	}
}
