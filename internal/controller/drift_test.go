package controller

import "testing"

func TestDetectDrift_NewFinding(t *testing.T) {
	previous := []NHISnapshot{}
	current := []NHISnapshot{
		{NHIID: "sa:default/app", Name: "app", Namespace: "default", Score: 80, Severity: "CRITICAL", RulesHash: "abc123"},
	}

	events := detectDrift(previous, current)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != "new" {
		t.Errorf("expected type 'new', got %q", events[0].Type)
	}
	if events[0].NHIID != "sa:default/app" {
		t.Errorf("expected NHIID 'sa:default/app', got %q", events[0].NHIID)
	}
	if events[0].NewScore != 80 {
		t.Errorf("expected NewScore 80, got %d", events[0].NewScore)
	}
	if events[0].NewSeverity != "CRITICAL" {
		t.Errorf("expected NewSeverity 'CRITICAL', got %q", events[0].NewSeverity)
	}
}

func TestDetectDrift_NewFindingZeroScore(t *testing.T) {
	previous := []NHISnapshot{}
	current := []NHISnapshot{
		{NHIID: "sa:default/noop", Name: "noop", Namespace: "default", Score: 0, Severity: "INFO", RulesHash: ""},
	}

	events := detectDrift(previous, current)
	if len(events) != 0 {
		t.Fatalf("expected 0 events for zero-score new NHI, got %d", len(events))
	}
}

func TestDetectDrift_Resolved(t *testing.T) {
	previous := []NHISnapshot{
		{NHIID: "sa:kube-system/old", Name: "old", Namespace: "kube-system", Score: 60, Severity: "HIGH", RulesHash: "xyz"},
	}
	current := []NHISnapshot{}

	events := detectDrift(previous, current)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != "resolved" {
		t.Errorf("expected type 'resolved', got %q", events[0].Type)
	}
	if events[0].OldScore != 60 {
		t.Errorf("expected OldScore 60, got %d", events[0].OldScore)
	}
	if events[0].OldSeverity != "HIGH" {
		t.Errorf("expected OldSeverity 'HIGH', got %q", events[0].OldSeverity)
	}
}

func TestDetectDrift_Regressed(t *testing.T) {
	previous := []NHISnapshot{
		{NHIID: "sa:default/web", Name: "web", Namespace: "default", Score: 50, Severity: "MEDIUM", RulesHash: "aaa"},
	}
	current := []NHISnapshot{
		{NHIID: "sa:default/web", Name: "web", Namespace: "default", Score: 80, Severity: "CRITICAL", RulesHash: "bbb"},
	}

	events := detectDrift(previous, current)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	if e.Type != "regressed" {
		t.Errorf("expected type 'regressed', got %q", e.Type)
	}
	if e.OldScore != 50 {
		t.Errorf("expected OldScore 50, got %d", e.OldScore)
	}
	if e.NewScore != 80 {
		t.Errorf("expected NewScore 80, got %d", e.NewScore)
	}
	if e.OldSeverity != "MEDIUM" {
		t.Errorf("expected OldSeverity 'MEDIUM', got %q", e.OldSeverity)
	}
	if e.NewSeverity != "CRITICAL" {
		t.Errorf("expected NewSeverity 'CRITICAL', got %q", e.NewSeverity)
	}
}

func TestDetectDrift_Improved(t *testing.T) {
	previous := []NHISnapshot{
		{NHIID: "sa:default/api", Name: "api", Namespace: "default", Score: 80, Severity: "CRITICAL", RulesHash: "r1"},
	}
	current := []NHISnapshot{
		{NHIID: "sa:default/api", Name: "api", Namespace: "default", Score: 30, Severity: "LOW", RulesHash: "r2"},
	}

	events := detectDrift(previous, current)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	if e.Type != "improved" {
		t.Errorf("expected type 'improved', got %q", e.Type)
	}
	if e.OldScore != 80 {
		t.Errorf("expected OldScore 80, got %d", e.OldScore)
	}
	if e.NewScore != 30 {
		t.Errorf("expected NewScore 30, got %d", e.NewScore)
	}
}

func TestDetectDrift_Unchanged(t *testing.T) {
	snap := NHISnapshot{
		NHIID: "sa:default/stable", Name: "stable", Namespace: "default",
		Score: 45, Severity: "MEDIUM", RulesHash: "same",
	}
	previous := []NHISnapshot{snap}
	current := []NHISnapshot{snap}

	events := detectDrift(previous, current)
	if len(events) != 0 {
		t.Fatalf("expected 0 events for unchanged NHI, got %d", len(events))
	}
}

func TestDetectDrift_RulesChanged(t *testing.T) {
	previous := []NHISnapshot{
		{NHIID: "sa:default/svc", Name: "svc", Namespace: "default", Score: 60, Severity: "HIGH", RulesHash: "hash-old"},
	}
	current := []NHISnapshot{
		{NHIID: "sa:default/svc", Name: "svc", Namespace: "default", Score: 60, Severity: "HIGH", RulesHash: "hash-new"},
	}

	events := detectDrift(previous, current)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	if e.Type != "regressed" {
		t.Errorf("expected type 'regressed', got %q", e.Type)
	}
	if e.Detail != "matched rules changed (same score)" {
		t.Errorf("unexpected detail: %q", e.Detail)
	}
	if e.OldScore != 60 || e.NewScore != 60 {
		t.Errorf("expected scores 60/60, got %d/%d", e.OldScore, e.NewScore)
	}
}

func TestDetectDrift_MultipleEvents(t *testing.T) {
	previous := []NHISnapshot{
		{NHIID: "sa:default/resolved-sa", Name: "resolved-sa", Namespace: "default", Score: 70, Severity: "HIGH", RulesHash: "r1"},
		{NHIID: "sa:default/regressed-sa", Name: "regressed-sa", Namespace: "default", Score: 40, Severity: "MEDIUM", RulesHash: "r2"},
		{NHIID: "sa:default/unchanged-sa", Name: "unchanged-sa", Namespace: "default", Score: 30, Severity: "LOW", RulesHash: "r3"},
	}
	current := []NHISnapshot{
		// resolved-sa is absent → resolved
		// regressed-sa score went up → regressed
		{NHIID: "sa:default/regressed-sa", Name: "regressed-sa", Namespace: "default", Score: 85, Severity: "CRITICAL", RulesHash: "r2x"},
		// unchanged-sa stays the same → no event
		{NHIID: "sa:default/unchanged-sa", Name: "unchanged-sa", Namespace: "default", Score: 30, Severity: "LOW", RulesHash: "r3"},
		// new-sa is brand new → new
		{NHIID: "sa:default/new-sa", Name: "new-sa", Namespace: "default", Score: 55, Severity: "MEDIUM", RulesHash: "r4"},
	}

	events := detectDrift(previous, current)

	counts := map[string]int{}
	for _, e := range events {
		counts[e.Type]++
	}

	if counts["resolved"] != 1 {
		t.Errorf("expected 1 resolved event, got %d", counts["resolved"])
	}
	if counts["regressed"] != 1 {
		t.Errorf("expected 1 regressed event, got %d", counts["regressed"])
	}
	if counts["new"] != 1 {
		t.Errorf("expected 1 new event, got %d", counts["new"])
	}
	if counts["improved"] != 0 {
		t.Errorf("expected 0 improved events, got %d", counts["improved"])
	}

	total := len(events)
	if total != 3 {
		t.Errorf("expected 3 total events, got %d", total)
	}
}
