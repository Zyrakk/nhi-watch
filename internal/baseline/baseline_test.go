package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Zyrakk/nhi-watch/internal/scoring"
)

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	results := []scoring.ScoringResult{
		{NHIID: "abc123", Name: "admin-sa", Namespace: "default",
			FinalScore: 95, FinalSeverity: scoring.SeverityCritical},
	}

	if err := Save(path, results, "test-cluster"); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ClusterName != "test-cluster" {
		t.Error("cluster name mismatch")
	}
	if len(loaded.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(loaded.Findings))
	}
}

func TestSave_SkipsZeroScore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	results := []scoring.ScoringResult{
		{NHIID: "abc123", FinalScore: 95, FinalSeverity: scoring.SeverityCritical},
		{NHIID: "zero", FinalScore: 0, FinalSeverity: scoring.SeverityInfo},
	}

	if err := Save(path, results, "test"); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Findings) != 1 {
		t.Errorf("expected 1 finding (zero-score skipped), got %d", len(loaded.Findings))
	}
}

func TestDiff_NewFinding(t *testing.T) {
	bl := &Baseline{
		Findings: map[string]BaselineFinding{
			"abc123": {NHIID: "abc123", Score: 95, Severity: "CRITICAL"},
		},
	}
	current := []scoring.ScoringResult{
		{NHIID: "abc123", FinalScore: 95, FinalSeverity: scoring.SeverityCritical},
		{NHIID: "def456", FinalScore: 80, FinalSeverity: scoring.SeverityHigh},
	}
	diff := Diff(current, bl)
	if len(diff.New) != 1 {
		t.Errorf("expected 1 new finding, got %d", len(diff.New))
	}
	if diff.New[0].NHIID != "def456" {
		t.Error("expected def456 as new finding")
	}
}

func TestDiff_ResolvedFinding(t *testing.T) {
	bl := &Baseline{
		Findings: map[string]BaselineFinding{
			"abc123": {NHIID: "abc123", Score: 95, Severity: "CRITICAL"},
			"def456": {NHIID: "def456", Score: 80, Severity: "HIGH"},
		},
	}
	current := []scoring.ScoringResult{
		{NHIID: "abc123", FinalScore: 95, FinalSeverity: scoring.SeverityCritical},
	}
	diff := Diff(current, bl)
	if len(diff.Resolved) != 1 {
		t.Errorf("expected 1 resolved finding, got %d", len(diff.Resolved))
	}
}

func TestDiff_RegressionDetected(t *testing.T) {
	bl := &Baseline{
		Findings: map[string]BaselineFinding{
			"abc123": {NHIID: "abc123", Score: 60, Severity: "MEDIUM"},
		},
	}
	current := []scoring.ScoringResult{
		{NHIID: "abc123", FinalScore: 95, FinalSeverity: scoring.SeverityCritical},
	}
	diff := Diff(current, bl)
	if len(diff.Regressed) != 1 {
		t.Errorf("expected 1 regressed finding, got %d", len(diff.Regressed))
	}
}

func TestDiff_UnchangedFinding(t *testing.T) {
	bl := &Baseline{
		Findings: map[string]BaselineFinding{
			"abc123": {NHIID: "abc123", Score: 95, Severity: "CRITICAL"},
		},
	}
	current := []scoring.ScoringResult{
		{NHIID: "abc123", FinalScore: 95, FinalSeverity: scoring.SeverityCritical},
	}
	diff := Diff(current, bl)
	if len(diff.Unchanged) != 1 {
		t.Errorf("expected 1 unchanged finding, got %d", len(diff.Unchanged))
	}
}

func TestDiff_ImprovedScoreIsUnchanged(t *testing.T) {
	bl := &Baseline{
		Findings: map[string]BaselineFinding{
			"abc123": {NHIID: "abc123", Score: 95, Severity: "CRITICAL"},
		},
	}
	current := []scoring.ScoringResult{
		{NHIID: "abc123", FinalScore: 60, FinalSeverity: scoring.SeverityHigh},
	}
	diff := Diff(current, bl)
	if len(diff.Unchanged) != 1 {
		t.Errorf("improved score should be unchanged, got %d unchanged", len(diff.Unchanged))
	}
	if len(diff.Regressed) != 0 {
		t.Errorf("improved score should NOT be regressed, got %d", len(diff.Regressed))
	}
}

func TestDiff_NoBaseline(t *testing.T) {
	current := []scoring.ScoringResult{
		{NHIID: "abc123", FinalScore: 95, FinalSeverity: scoring.SeverityCritical},
	}
	diff := Diff(current, nil)
	if len(diff.New) != 1 {
		t.Error("all findings should be new when no baseline")
	}
}

func TestLoad_NonexistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestHasFailures_NewAboveThreshold(t *testing.T) {
	diff := DiffResult{
		New: []scoring.ScoringResult{
			{FinalSeverity: scoring.SeverityCritical},
		},
	}
	if !diff.HasFailures(scoring.SeverityHigh) {
		t.Error("CRITICAL new finding should fail at HIGH threshold")
	}
}

func TestHasFailures_NewBelowThreshold(t *testing.T) {
	diff := DiffResult{
		New: []scoring.ScoringResult{
			{FinalSeverity: scoring.SeverityLow},
		},
	}
	if diff.HasFailures(scoring.SeverityHigh) {
		t.Error("LOW new finding should not fail at HIGH threshold")
	}
}

func TestHasFailures_RegressedAboveThreshold(t *testing.T) {
	diff := DiffResult{
		Regressed: []scoring.ScoringResult{
			{FinalSeverity: scoring.SeverityHigh},
		},
	}
	if !diff.HasFailures(scoring.SeverityHigh) {
		t.Error("HIGH regressed finding should fail at HIGH threshold")
	}
}

func TestHasFailures_OnlyUnchanged(t *testing.T) {
	diff := DiffResult{
		Unchanged: []scoring.ScoringResult{
			{FinalSeverity: scoring.SeverityCritical},
		},
	}
	if diff.HasFailures(scoring.SeverityInfo) {
		t.Error("only unchanged findings should not trigger failure")
	}
}

func TestSaveAndLoad_PreservesVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	results := []scoring.ScoringResult{
		{NHIID: "abc123", FinalScore: 50, FinalSeverity: scoring.SeverityMedium},
	}
	if err := Save(path, results, "cluster"); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != "1" {
		t.Errorf("expected version 1, got %s", loaded.Version)
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
