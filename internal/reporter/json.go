package reporter

import (
	"encoding/json"

	"github.com/Zyrakk/nhi-watch/internal/scoring"
)

// JSONReporter renders a machine-readable JSON report.
type JSONReporter struct{}

type jsonReport struct {
	Cluster   string                   `json:"cluster"`
	Timestamp string                   `json:"timestamp"`
	TotalNHIs int                      `json:"total_nhis"`
	Summary   map[scoring.Severity]int `json:"summary"`
	Findings  []scoring.ScoringResult  `json:"findings"`
}

func (r *JSONReporter) Render(report *AuditReport) ([]byte, error) {
	jr := jsonReport{
		Cluster:   report.ClusterName,
		Timestamp: report.Timestamp,
		TotalNHIs: report.TotalNHIs,
		Summary:   scoring.CountBySeverity(report.Results),
		Findings:  report.Results,
	}
	return json.MarshalIndent(jr, "", "  ")
}
