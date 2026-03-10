package reporter

import (
	"bytes"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
	"github.com/Zyrakk/nhi-watch/internal/scoring"
)

// TableReporter renders a human-readable table to bytes.
// The caller (CLI layer) writes these bytes to stderr so that
// JSON/SARIF can be piped on stdout.
type TableReporter struct{}

func (r *TableReporter) Render(report *AuditReport) ([]byte, error) {
	var buf bytes.Buffer
	counts := scoring.CountBySeverity(report.Results)

	// Box header.
	boxW := 62
	border := strings.Repeat("═", boxW)
	fmt.Fprintf(&buf, "\n╔%s╗\n", border)
	fmt.Fprintf(&buf, "║  %-*s║\n", boxW-1, "NHI-Watch Audit Report")
	fmt.Fprintf(&buf, "║  %-*s║\n", boxW-1, "Cluster: "+report.ClusterName)
	fmt.Fprintf(&buf, "║  %-*s║\n", boxW-1, report.Timestamp)
	fmt.Fprintf(&buf, "╚%s╝\n", border)

	// Summary line.
	fmt.Fprintf(&buf, "\nSUMMARY: %d NHIs discovered", report.TotalNHIs)
	for _, sev := range scoring.AllSeverities() {
		if c, ok := counts[sev]; ok && c > 0 {
			fmt.Fprintf(&buf, " | %d %s", c, sev)
		}
	}
	fmt.Fprintln(&buf)

	// Findings grouped by severity.
	for _, sev := range scoring.AllSeverities() {
		sevResults := filterBySev(report.Results, sev)
		if len(sevResults) == 0 {
			continue
		}

		fmt.Fprintf(&buf, "\n── %s %s\n", sev, strings.Repeat("─", 55-len(string(sev))))

		for _, r := range sevResults {
			fmt.Fprintf(&buf, "\n")
			fmt.Fprintf(&buf, "[%d] %s %q (%s)\n", r.FinalScore, r.Type, r.Name, r.Namespace)

			ruleIDs := make([]string, 0, len(r.Results))
			for _, rr := range r.Results {
				ruleIDs = append(ruleIDs, rr.RuleID)
			}
			if len(ruleIDs) == 1 {
				fmt.Fprintf(&buf, "     Rule: %s\n", ruleIDs[0])
			} else if len(ruleIDs) > 1 {
				fmt.Fprintf(&buf, "     Rules: %s\n", strings.Join(ruleIDs, ", "))
			}

			if len(r.Results) > 0 {
				detail := r.Results[0].Detail
				for _, rr := range r.Results {
					if rr.Score > r.Results[0].Score {
						detail = rr.Detail
					}
				}
				if detail != "" {
					fmt.Fprintf(&buf, "     %s\n", detail)
				}
			}

			if r.Recommendation != "" {
				rec := r.Recommendation
				if len(rec) > 120 {
					rec = rec[:117] + "..."
				}
				fmt.Fprintf(&buf, "     → %s\n", rec)
			}
		}
	}

	// Statistics table.
	fmt.Fprintf(&buf, "\n── STATISTICS %s\n\n", strings.Repeat("─", 47))

	typeStats := scoring.CountByTypeAndSeverity(report.Results)
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "NHI Type\tCount\tCritical\tHigh\tMedium\tLow/Info\n")

	typeOrder := discovery.AllNHITypes()
	totalCount := 0
	totalCrit, totalHigh, totalMed, totalLow := 0, 0, 0, 0

	for _, t := range typeOrder {
		ts := string(t)
		stats, ok := typeStats[ts]
		if !ok {
			continue
		}
		count := 0
		for _, c := range stats {
			count += c
		}
		crit := stats[scoring.SeverityCritical]
		high := stats[scoring.SeverityHigh]
		med := stats[scoring.SeverityMedium]
		low := stats[scoring.SeverityLow] + stats[scoring.SeverityInfo]

		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\n", ts, count, crit, high, med, low)

		totalCount += count
		totalCrit += crit
		totalHigh += high
		totalMed += med
		totalLow += low
	}

	fmt.Fprintf(w, "─\t─\t─\t─\t─\t─\n")
	fmt.Fprintf(w, "TOTAL\t%d\t%d\t%d\t%d\t%d\n", totalCount, totalCrit, totalHigh, totalMed, totalLow)
	w.Flush()
	fmt.Fprintln(&buf)

	return buf.Bytes(), nil
}

func filterBySev(results []scoring.ScoringResult, sev scoring.Severity) []scoring.ScoringResult {
	filtered := make([]scoring.ScoringResult, 0)
	for _, r := range results {
		if r.FinalSeverity == sev {
			filtered = append(filtered, r)
		}
	}
	return filtered
}
