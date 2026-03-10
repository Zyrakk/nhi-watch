package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Zyrakk/nhi-watch/internal/scoring"
)

// Baseline represents a saved snapshot of audit findings for diff comparison.
type Baseline struct {
	Version     string                     `json:"version"`
	Timestamp   time.Time                  `json:"timestamp"`
	ClusterName string                     `json:"cluster_name"`
	Findings    map[string]BaselineFinding `json:"findings"`
}

// BaselineFinding stores the essential info for a single finding.
type BaselineFinding struct {
	NHIID    string `json:"nhi_id"`
	Name     string `json:"name"`
	Score    int    `json:"score"`
	Severity string `json:"severity"`
}

// DiffResult categorizes current findings against a baseline.
type DiffResult struct {
	New       []scoring.ScoringResult // Findings not in baseline
	Resolved  []BaselineFinding       // Baseline findings no longer present
	Regressed []scoring.ScoringResult // Findings with worse score than baseline
	Unchanged []scoring.ScoringResult // Same or better
}

// Save writes current results as a baseline JSON file.
func Save(path string, results []scoring.ScoringResult, clusterName string) error {
	bl := Baseline{
		Version:     "1",
		Timestamp:   time.Now().UTC(),
		ClusterName: clusterName,
		Findings:    make(map[string]BaselineFinding, len(results)),
	}
	for _, r := range results {
		if r.FinalScore == 0 {
			continue // Don't baseline zero-score findings
		}
		bl.Findings[r.NHIID] = BaselineFinding{
			NHIID:    r.NHIID,
			Name:     r.Name,
			Score:    r.FinalScore,
			Severity: string(r.FinalSeverity),
		}
	}
	data, err := json.MarshalIndent(bl, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// Load reads a baseline from a JSON file.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline: %w", err)
	}
	var bl Baseline
	if err := json.Unmarshal(data, &bl); err != nil {
		return nil, fmt.Errorf("parsing baseline: %w", err)
	}
	return &bl, nil
}

// Diff compares current scoring results against a baseline and categorizes them.
func Diff(current []scoring.ScoringResult, bl *Baseline) DiffResult {
	var diff DiffResult
	if bl == nil {
		diff.New = current
		return diff
	}
	seen := make(map[string]bool)
	for _, r := range current {
		if r.FinalScore == 0 {
			continue
		}
		seen[r.NHIID] = true
		prev, existed := bl.Findings[r.NHIID]
		if !existed {
			diff.New = append(diff.New, r)
		} else if r.FinalScore > prev.Score {
			diff.Regressed = append(diff.Regressed, r)
		} else {
			diff.Unchanged = append(diff.Unchanged, r)
		}
	}
	for id, f := range bl.Findings {
		if !seen[id] {
			diff.Resolved = append(diff.Resolved, f)
		}
	}
	return diff
}

// HasFailures returns true if there are new or regressed findings at or above
// the given minimum severity.
func (d DiffResult) HasFailures(minSeverity scoring.Severity) bool {
	for _, r := range d.New {
		if scoring.SeverityMeetsThreshold(r.FinalSeverity, minSeverity) {
			return true
		}
	}
	for _, r := range d.Regressed {
		if scoring.SeverityMeetsThreshold(r.FinalSeverity, minSeverity) {
			return true
		}
	}
	return false
}
