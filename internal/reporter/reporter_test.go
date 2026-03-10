package reporter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Zyrakk/nhi-watch/internal/scoring"
)

func makeTestReport() *AuditReport {
	return &AuditReport{
		ClusterName: "test-cluster",
		Timestamp:   "2026-03-10T12:00:00Z",
		TotalNHIs:   42,
		Results: []scoring.ScoringResult{
			{
				NHIID:         "abc123",
				Name:          "admin-sa",
				Namespace:     "kube-system",
				Type:          "service-account",
				FinalScore:    95,
				BaseScore:     95,
				FinalSeverity: scoring.SeverityCritical,
				PostureMultiplier: 1.0,
				Results: []scoring.RuleResult{
					{
						RuleID:      "CLUSTER_ADMIN_BINDING",
						Description: "ServiceAccount is bound to cluster-admin",
						Severity:    scoring.SeverityCritical,
						Score:       95,
						Detail:      "Bound via ClusterRoleBinding admin-crb",
						CISControls: []string{"5.1.1"},
					},
				},
				Recommendation: "Remove the cluster-admin binding",
			},
			{
				NHIID:         "def456",
				Name:          "old-secret",
				Namespace:     "default",
				Type:          "secret-credential",
				FinalScore:    75,
				BaseScore:     75,
				FinalSeverity: scoring.SeverityHigh,
				PostureMultiplier: 1.0,
				Results: []scoring.RuleResult{
					{
						RuleID:      "SECRET_NOT_ROTATED_90D",
						Description: "Secret not rotated in 90 days",
						Severity:    scoring.SeverityHigh,
						Score:       75,
						Detail:      "Created 120 days ago",
					},
				},
				Recommendation: "Rotate the secret",
			},
		},
	}
}

// ── Table tests ──────────────────────────────────────────────────────

func TestTableReporter_ContainsBoxHeader(t *testing.T) {
	r := &TableReporter{}
	out, err := r.Render(makeTestReport())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "NHI-Watch Audit Report") {
		t.Error("missing box header title")
	}
	if !strings.Contains(s, "test-cluster") {
		t.Error("missing cluster name")
	}
	if !strings.Contains(s, "╔") || !strings.Contains(s, "╗") {
		t.Error("missing box border characters")
	}
}

func TestTableReporter_ContainsSeverityGroups(t *testing.T) {
	r := &TableReporter{}
	out, err := r.Render(makeTestReport())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "── CRITICAL") {
		t.Error("missing CRITICAL severity group")
	}
	if !strings.Contains(s, "── HIGH") {
		t.Error("missing HIGH severity group")
	}
}

func TestTableReporter_ContainsFindingDetails(t *testing.T) {
	r := &TableReporter{}
	out, err := r.Render(makeTestReport())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "[95]") {
		t.Error("missing score [95]")
	}
	if !strings.Contains(s, `"admin-sa"`) {
		t.Error("missing NHI name")
	}
	if !strings.Contains(s, "Rule: CLUSTER_ADMIN_BINDING") {
		t.Error("missing rule ID")
	}
}

func TestTableReporter_ContainsStatistics(t *testing.T) {
	r := &TableReporter{}
	out, err := r.Render(makeTestReport())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "── STATISTICS") {
		t.Error("missing STATISTICS section")
	}
	if !strings.Contains(s, "TOTAL") {
		t.Error("missing TOTAL row")
	}
}

func TestTableReporter_ContainsSummaryLine(t *testing.T) {
	r := &TableReporter{}
	out, err := r.Render(makeTestReport())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "SUMMARY: 42 NHIs discovered") {
		t.Error("missing summary line")
	}
}

func TestTableReporter_RecommendationTruncated(t *testing.T) {
	report := makeTestReport()
	report.Results[0].Recommendation = strings.Repeat("x", 200)
	r := &TableReporter{}
	out, err := r.Render(report)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "...") {
		t.Error("long recommendation should be truncated with ...")
	}
}

func TestTableReporter_EmptyResults(t *testing.T) {
	report := &AuditReport{
		ClusterName: "empty-cluster",
		Timestamp:   "2026-01-01T00:00:00Z",
		TotalNHIs:   0,
		Results:     nil,
	}
	r := &TableReporter{}
	out, err := r.Render(report)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "NHI-Watch Audit Report") {
		t.Error("should still render header for empty results")
	}
	if !strings.Contains(s, "SUMMARY: 0 NHIs discovered") {
		t.Error("should show 0 NHIs")
	}
}

// ── JSON tests ───────────────────────────────────────────────────────

func TestJSONReporter_ValidJSON(t *testing.T) {
	r := &JSONReporter{}
	out, err := r.Render(makeTestReport())
	if err != nil {
		t.Fatal(err)
	}
	var parsed jsonReport
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed.Cluster != "test-cluster" {
		t.Errorf("expected cluster test-cluster, got %s", parsed.Cluster)
	}
	if parsed.TotalNHIs != 42 {
		t.Errorf("expected 42 NHIs, got %d", parsed.TotalNHIs)
	}
	if len(parsed.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(parsed.Findings))
	}
}

func TestJSONReporter_Summary(t *testing.T) {
	r := &JSONReporter{}
	out, err := r.Render(makeTestReport())
	if err != nil {
		t.Fatal(err)
	}
	var parsed jsonReport
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Summary[scoring.SeverityCritical] != 1 {
		t.Errorf("expected 1 CRITICAL, got %d", parsed.Summary[scoring.SeverityCritical])
	}
	if parsed.Summary[scoring.SeverityHigh] != 1 {
		t.Errorf("expected 1 HIGH, got %d", parsed.Summary[scoring.SeverityHigh])
	}
}

func TestJSONReporter_EmptyResults(t *testing.T) {
	report := &AuditReport{
		ClusterName: "empty",
		TotalNHIs:   0,
		Results:     nil,
	}
	r := &JSONReporter{}
	out, err := r.Render(report)
	if err != nil {
		t.Fatal(err)
	}
	var parsed jsonReport
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid JSON for empty report: %v", err)
	}
}

// ── SARIF tests ──────────────────────────────────────────────────────

func TestSARIFReporter_ValidSchema(t *testing.T) {
	r := &SARIFReporter{}
	out, err := r.Render(makeTestReport())
	if err != nil {
		t.Fatal(err)
	}
	var sarif sarifLog
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("expected SARIF 2.1.0, got %s", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}
	if sarif.Runs[0].Tool.Driver.Name != "nhi-watch" {
		t.Errorf("expected tool name nhi-watch, got %s", sarif.Runs[0].Tool.Driver.Name)
	}
}

func TestSARIFReporter_RuleDefinitions(t *testing.T) {
	r := &SARIFReporter{}
	out, err := r.Render(makeTestReport())
	if err != nil {
		t.Fatal(err)
	}
	var sarif sarifLog
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatal(err)
	}
	rules := sarif.Runs[0].Tool.Driver.Rules
	if len(rules) != 2 {
		t.Fatalf("expected 2 rule definitions, got %d", len(rules))
	}
	// First rule should have CIS tag
	found := false
	for _, rd := range rules {
		if rd.ID == "CLUSTER_ADMIN_BINDING" {
			found = true
			if len(rd.Properties.Tags) == 0 {
				t.Error("CLUSTER_ADMIN_BINDING should have CIS tags")
			}
			if rd.Properties.Tags[0] != "CIS-5.1.1" {
				t.Errorf("expected CIS-5.1.1 tag, got %s", rd.Properties.Tags[0])
			}
		}
	}
	if !found {
		t.Error("CLUSTER_ADMIN_BINDING rule definition not found")
	}
}

func TestSARIFReporter_SeverityMapping(t *testing.T) {
	r := &SARIFReporter{}
	out, err := r.Render(makeTestReport())
	if err != nil {
		t.Fatal(err)
	}
	var sarif sarifLog
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatal(err)
	}
	results := sarif.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	// CRITICAL → error, HIGH → error
	for _, sr := range results {
		if sr.Level != "error" {
			t.Errorf("expected 'error' level for CRITICAL/HIGH, got %s", sr.Level)
		}
	}
}

func TestSARIFReporter_Locations(t *testing.T) {
	r := &SARIFReporter{}
	out, err := r.Render(makeTestReport())
	if err != nil {
		t.Fatal(err)
	}
	var sarif sarifLog
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatal(err)
	}
	result := sarif.Runs[0].Results[0]
	if len(result.Locations) == 0 {
		t.Fatal("expected at least one location")
	}
	loc := result.Locations[0].LogicalLocations[0]
	if loc.Name != "admin-sa" {
		t.Errorf("expected name admin-sa, got %s", loc.Name)
	}
	if loc.FullyQualifiedName != "kube-system/admin-sa" {
		t.Errorf("expected fqn kube-system/admin-sa, got %s", loc.FullyQualifiedName)
	}
}

func TestSARIFReporter_EmptyResults(t *testing.T) {
	report := &AuditReport{
		ClusterName: "empty",
		TotalNHIs:   0,
		Results:     nil,
	}
	r := &SARIFReporter{}
	out, err := r.Render(report)
	if err != nil {
		t.Fatal(err)
	}
	var sarif sarifLog
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatalf("invalid SARIF for empty: %v", err)
	}
	if len(sarif.Runs[0].Results) != 0 {
		t.Error("expected 0 results for empty report")
	}
}

// ── Factory tests ────────────────────────────────────────────────────

func TestNew_ReturnsCorrectType(t *testing.T) {
	if _, ok := New(FormatTable).(*TableReporter); !ok {
		t.Error("FormatTable should return *TableReporter")
	}
	if _, ok := New(FormatJSON).(*JSONReporter); !ok {
		t.Error("FormatJSON should return *JSONReporter")
	}
	if _, ok := New(FormatSARIF).(*SARIFReporter); !ok {
		t.Error("FormatSARIF should return *SARIFReporter")
	}
	// Unknown format defaults to table
	if _, ok := New("unknown").(*TableReporter); !ok {
		t.Error("unknown format should default to *TableReporter")
	}
}
