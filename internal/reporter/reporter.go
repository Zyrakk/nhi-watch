// Package reporter handles output generation for NHI-Watch audit scans.
//
// Supported formats:
//   - Table:  terminal-friendly with severity grouping (intended for stderr)
//   - JSON:   machine-readable for jq / SIEM integration (intended for stdout)
//   - SARIF:  GitHub Security tab integration (intended for stdout)
//
// The Reporter.Render() method returns []byte. The CLI layer decides
// which output stream (stderr vs stdout) to write to.
package reporter

import (
	"github.com/Zyrakk/nhi-watch/internal/scoring"
)

// Format identifies the output format.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// AuditReport is the data passed to any reporter.
type AuditReport struct {
	ClusterName string
	Timestamp   string
	TotalNHIs   int
	Results     []scoring.ScoringResult
}

// Reporter renders an AuditReport into a specific output format.
type Reporter interface {
	Render(report *AuditReport) ([]byte, error)
}

// New creates a Reporter for the given format.
func New(format Format) Reporter {
	switch format {
	case FormatJSON:
		return &JSONReporter{}
	case FormatSARIF:
		return &SARIFReporter{}
	default:
		return &TableReporter{}
	}
}
