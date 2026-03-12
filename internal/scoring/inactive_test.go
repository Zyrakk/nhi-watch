package scoring

import (
	"testing"
	"time"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
	"github.com/Zyrakk/nhi-watch/internal/usage"
)

// ══════════════════════════════════════════════════════════════════════
//  Inactive NHI rule tests
// ══════════════════════════════════════════════════════════════════════

func TestInactiveNHI_NoUsageData(t *testing.T) {
	rules := InactiveRules()
	nhi := saNoPermissions("orphan-sa", "default")
	// UsageProfile is nil → no rules should fire.

	for _, rule := range rules {
		matched, _ := rule.Evaluate(nhi)
		if matched {
			t.Errorf("rule %s should not fire when UsageProfile is nil", rule.ID)
		}
	}
}

func TestInactiveNHI_ActiveSA(t *testing.T) {
	rules := InactiveRules()
	nhi := saNoPermissions("active-sa", "production")
	nhi.UsageProfile = &usage.UsageProfile{
		ServiceAccount:  "active-sa",
		Namespace:       "production",
		FirstSeen:       time.Now().Add(-45 * 24 * time.Hour),
		LastUpdated:     time.Now(),
		ObservationDays: 45,
		TotalCalls:      5000,
	}

	for _, rule := range rules {
		matched, _ := rule.Evaluate(nhi)
		if matched {
			t.Errorf("rule %s should not fire for active SA with TotalCalls=5000", rule.ID)
		}
	}
}

func TestInactiveNHI_HighConfidence(t *testing.T) {
	rules := InactiveRules()
	nhi := saNoPermissions("dormant-sa", "staging")
	nhi.UsageProfile = &usage.UsageProfile{
		ServiceAccount:  "dormant-sa",
		Namespace:       "staging",
		FirstSeen:       time.Now().Add(-45 * 24 * time.Hour),
		LastUpdated:     time.Now(),
		ObservationDays: 45,
		TotalCalls:      0,
	}

	// INACTIVE_NHI_HIGH should fire.
	highRule := rules[0]
	if highRule.ID != "INACTIVE_NHI_HIGH" {
		t.Fatalf("expected first rule to be INACTIVE_NHI_HIGH, got %s", highRule.ID)
	}
	matched, detail := highRule.Evaluate(nhi)
	if !matched {
		t.Fatal("INACTIVE_NHI_HIGH should fire for 0 calls over 45 days")
	}
	if detail == "" {
		t.Error("expected non-empty detail")
	}
	if highRule.Severity != SeverityMedium {
		t.Errorf("INACTIVE_NHI_HIGH severity should be MEDIUM, got %s", highRule.Severity)
	}

	// INACTIVE_NHI_MEDIUM should NOT fire (confidence is high, not medium).
	medRule := rules[1]
	if medRule.ID != "INACTIVE_NHI_MEDIUM" {
		t.Fatalf("expected second rule to be INACTIVE_NHI_MEDIUM, got %s", medRule.ID)
	}
	matched, _ = medRule.Evaluate(nhi)
	if matched {
		t.Error("INACTIVE_NHI_MEDIUM should not fire when confidence is high")
	}
}

func TestInactiveNHI_MediumConfidence(t *testing.T) {
	rules := InactiveRules()
	nhi := saNoPermissions("new-sa", "dev")
	nhi.UsageProfile = &usage.UsageProfile{
		ServiceAccount:  "new-sa",
		Namespace:       "dev",
		FirstSeen:       time.Now().Add(-14 * 24 * time.Hour),
		LastUpdated:     time.Now(),
		ObservationDays: 14,
		TotalCalls:      0,
	}

	// INACTIVE_NHI_HIGH should NOT fire (confidence is medium, not high).
	highRule := rules[0]
	matched, _ := highRule.Evaluate(nhi)
	if matched {
		t.Error("INACTIVE_NHI_HIGH should not fire when confidence is medium")
	}

	// INACTIVE_NHI_MEDIUM should fire.
	medRule := rules[1]
	matched, detail := medRule.Evaluate(nhi)
	if !matched {
		t.Fatal("INACTIVE_NHI_MEDIUM should fire for 0 calls over 14 days")
	}
	if detail == "" {
		t.Error("expected non-empty detail")
	}
	if medRule.Severity != SeverityLow {
		t.Errorf("INACTIVE_NHI_MEDIUM severity should be LOW, got %s", medRule.Severity)
	}
}

func TestInactiveNHI_InsufficientObservation(t *testing.T) {
	rules := InactiveRules()
	nhi := saNoPermissions("brand-new-sa", "default")
	nhi.UsageProfile = &usage.UsageProfile{
		ServiceAccount:  "brand-new-sa",
		Namespace:       "default",
		FirstSeen:       time.Now().Add(-3 * 24 * time.Hour),
		LastUpdated:     time.Now(),
		ObservationDays: 3,
		TotalCalls:      0,
	}

	// Confidence is "none" (< 7 days) → no rules should fire.
	for _, rule := range rules {
		matched, _ := rule.Evaluate(nhi)
		if matched {
			t.Errorf("rule %s should not fire with only 3 days of observation (confidence=none)", rule.ID)
		}
	}
}

func TestInactiveNHI_NonSAType(t *testing.T) {
	rules := InactiveRules()
	nhi := &discovery.NonHumanIdentity{
		ID:        "test-secret",
		Type:      discovery.NHITypeSecretCredential,
		Name:      "some-secret",
		Namespace: "default",
		Metadata:  map[string]string{},
		UsageProfile: &usage.UsageProfile{
			ServiceAccount:  "some-secret",
			Namespace:       "default",
			ObservationDays: 45,
			TotalCalls:      0,
		},
	}

	// Rules only apply to service-account type, so ruleApplies should filter them out.
	for _, rule := range rules {
		if ruleApplies(rule, nhi.Type) {
			t.Errorf("rule %s should not apply to NHITypeSecretCredential", rule.ID)
		}
	}
}
