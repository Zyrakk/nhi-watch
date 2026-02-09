package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
	"github.com/Zyrakk/nhi-watch/internal/k8s"
	"github.com/Zyrakk/nhi-watch/internal/permissions"
	"github.com/Zyrakk/nhi-watch/internal/scoring"
)

var (
	auditSeverity    string
	auditTypeFilter  string
	auditRulesConfig string
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run a full NHI security audit with risk scoring",
	Long: `Execute a comprehensive audit that combines discovery, permission
analysis, and risk scoring into a single prioritized report.

Combines all phases:
  1. Discover all NHIs in the cluster
  2. Resolve effective RBAC permissions
  3. Apply scoring rules (deterministic, 16 built-in rules)
  4. Output findings ranked by severity with remediation hints

Output formats:
  table     Terminal-friendly with severity grouping (default)
  json      Machine-readable for jq / SIEM integration
  markdown  For documentation, tickets, or PRs`,
	RunE: runAudit,
}

func init() {
	auditCmd.Flags().StringVar(&auditSeverity, "severity", "", "minimum severity to report: critical, high, medium, low, info")
	auditCmd.Flags().StringVar(&auditTypeFilter, "type", "", "filter by NHI type (e.g. service-account, secret-credential)")
	auditCmd.Flags().StringVar(&auditRulesConfig, "rules-config", "", "custom scoring rules file (not yet implemented)")
	rootCmd.AddCommand(auditCmd)
}

// auditReport is the full report structure for JSON output.
type auditReport struct {
	Cluster   string                   `json:"cluster"`
	Timestamp string                   `json:"timestamp"`
	TotalNHIs int                      `json:"total_nhis"`
	Summary   map[scoring.Severity]int `json:"summary"`
	Findings  []scoring.ScoringResult  `json:"findings"`
}

func runAudit(cmd *cobra.Command, args []string) error {
	// Validate --rules-config (hook for future YAML loading).
	if auditRulesConfig != "" {
		return fmt.Errorf("--rules-config is not yet implemented (planned for Phase 3.5)")
	}

	// Parse --severity flag.
	var minSeverity scoring.Severity
	if auditSeverity != "" {
		switch strings.ToUpper(auditSeverity) {
		case "CRITICAL":
			minSeverity = scoring.SeverityCritical
		case "HIGH":
			minSeverity = scoring.SeverityHigh
		case "MEDIUM":
			minSeverity = scoring.SeverityMedium
		case "LOW":
			minSeverity = scoring.SeverityLow
		case "INFO":
			minSeverity = scoring.SeverityInfo
		default:
			return fmt.Errorf("invalid severity %q; valid values: critical, high, medium, low, info", auditSeverity)
		}
	}

	// Validate --type flag.
	if auditTypeFilter != "" {
		valid := false
		for _, t := range discovery.AllNHITypes() {
			if discovery.NHIType(auditTypeFilter) == t {
				valid = true
				break
			}
		}
		if !valid {
			validTypes := make([]string, 0, len(discovery.AllNHITypes()))
			for _, t := range discovery.AllNHITypes() {
				validTypes = append(validTypes, string(t))
			}
			return fmt.Errorf("invalid type %q; valid types: %s", auditTypeFilter, strings.Join(validTypes, ", "))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	clientOpts := k8s.ClientOpts{
		Kubeconfig: kubeconfig,
		Context:    kubeCtx,
	}

	// Build all Kubernetes clients (typed + dynamic + discovery).
	clients, err := k8s.NewClients(clientOpts)
	if err != nil {
		return fmt.Errorf("failed to connect to cluster: %w", err)
	}

	logf := func(format string, args ...interface{}) {
		if verbose {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	// ── Phase 1: Discovery ────────────────────────────────────────────
	logf("[*] Phase 1: Discovering Non-Human Identities...")

	discoverOpts := discovery.DiscoverOpts{
		Namespace:  namespace,
		TypeFilter: discovery.NHIType(auditTypeFilter),
		Verbose:    verbose,
		LogFunc:    logf,
	}

	nhis, errs := discovery.DiscoverAll(ctx, clients.Clientset, clients.Discovery, clients.Dynamic, discoverOpts)
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "⚠  %v\n", e)
	}

	logf("[*] Discovered %d NHIs", len(nhis))

	// ── Phase 2: Permission Resolution ────────────────────────────────
	logf("[*] Phase 2: Resolving RBAC permissions...")

	resolver, err := permissions.NewResolver(ctx, clients.Clientset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠  RBAC resolution failed: %v (scoring will proceed without permission data)\n", err)
	} else {
		for i := range nhis {
			if nhis[i].Type != discovery.NHITypeServiceAccount {
				continue
			}
			ps := resolver.ResolveServiceAccount(nhis[i].Name, nhis[i].Namespace)
			permissions.Analyze(ps, nhis[i].Name, nhis[i].Namespace)
			nhis[i].Permissions = ps
		}
		logf("[*] RBAC permissions resolved for all ServiceAccounts")
	}

	// ── Phase 3: Scoring ──────────────────────────────────────────────
	logf("[*] Phase 3: Scoring NHIs...")

	engine := scoring.NewEngine(scoring.DefaultRules())
	results := engine.ScoreAll(nhis)

	logf("[*] Scoring complete: %d NHIs scored", len(results))

	// Apply severity filter.
	if minSeverity != "" {
		results = scoring.FilterBySeverity(results, minSeverity)
	}

	// ── Render Output ─────────────────────────────────────────────────
	clusterName := k8s.ClusterName(clientOpts)
	timestamp := time.Now().Format(time.RFC3339)
	totalNHIs := len(nhis)

	switch outputFmt {
	case "json":
		return renderAuditJSON(clusterName, timestamp, totalNHIs, results)
	case "markdown":
		renderAuditMarkdown(clusterName, timestamp, totalNHIs, results)
		return nil
	case "table":
		renderAuditTable(clusterName, timestamp, totalNHIs, results)
		return nil
	default:
		return fmt.Errorf("unsupported output format: %q (use: table, json, markdown)", outputFmt)
	}
}

// ══════════════════════════════════════════════════════════════════════════
//  Table output
// ══════════════════════════════════════════════════════════════════════════

func renderAuditTable(cluster, timestamp string, totalNHIs int, results []scoring.ScoringResult) {
	counts := scoring.CountBySeverity(results)

	// Box header.
	boxW := 62
	border := strings.Repeat("═", boxW)
	fmt.Fprintf(os.Stderr, "\n╔%s╗\n", border)
	fmt.Fprintf(os.Stderr, "║  %-*s║\n", boxW-1, "NHI-Watch Audit Report")
	fmt.Fprintf(os.Stderr, "║  %-*s║\n", boxW-1, "Cluster: "+cluster)
	fmt.Fprintf(os.Stderr, "║  %-*s║\n", boxW-1, timestamp)
	fmt.Fprintf(os.Stderr, "╚%s╝\n", border)

	// Summary line.
	fmt.Fprintf(os.Stderr, "\nSUMMARY: %d NHIs discovered", totalNHIs)
	for _, sev := range scoring.AllSeverities() {
		if c, ok := counts[sev]; ok && c > 0 {
			fmt.Fprintf(os.Stderr, " | %d %s", c, sev)
		}
	}
	fmt.Fprintln(os.Stderr)

	// Findings grouped by severity.
	for _, sev := range scoring.AllSeverities() {
		sevResults := filterResultsBySeverity(results, sev)
		if len(sevResults) == 0 {
			continue
		}

		fmt.Fprintf(os.Stderr, "\n── %s %s\n", sev, strings.Repeat("─", 55-len(string(sev))))

		for _, r := range sevResults {
			fmt.Fprintf(os.Stderr, "\n")
			// Header: [score] Type "name" (namespace)
			fmt.Fprintf(os.Stderr, "[%d] %s %q (%s)\n", r.FinalScore, r.Type, r.Name, r.Namespace)

			// Rule IDs.
			ruleIDs := make([]string, 0, len(r.Results))
			for _, rr := range r.Results {
				ruleIDs = append(ruleIDs, rr.RuleID)
			}
			if len(ruleIDs) == 1 {
				fmt.Fprintf(os.Stderr, "     Rule: %s\n", ruleIDs[0])
			} else if len(ruleIDs) > 1 {
				fmt.Fprintf(os.Stderr, "     Rules: %s\n", strings.Join(ruleIDs, ", "))
			}

			// Detail from the highest-scoring result.
			if len(r.Results) > 0 {
				detail := r.Results[0].Detail
				for _, rr := range r.Results {
					if rr.Score > r.Results[0].Score {
						detail = rr.Detail
					}
				}
				if detail != "" {
					fmt.Fprintf(os.Stderr, "     %s\n", detail)
				}
			}

			// Recommendation (truncated for table output).
			if r.Recommendation != "" {
				rec := r.Recommendation
				if len(rec) > 120 {
					rec = rec[:117] + "..."
				}
				fmt.Fprintf(os.Stderr, "     → %s\n", rec)
			}
		}
	}

	// Statistics table.
	fmt.Fprintf(os.Stderr, "\n── STATISTICS %s\n\n", strings.Repeat("─", 47))

	typeStats := scoring.CountByTypeAndSeverity(results)
	w := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "NHI Type\tCount\tCritical\tHigh\tMedium\tLow/Info\n")

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

		_, _ = fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\n", ts, count, crit, high, med, low)

		totalCount += count
		totalCrit += crit
		totalHigh += high
		totalMed += med
		totalLow += low
	}

	_, _ = fmt.Fprintf(w, "─\t─\t─\t─\t─\t─\n")
	_, _ = fmt.Fprintf(w, "TOTAL\t%d\t%d\t%d\t%d\t%d\n", totalCount, totalCrit, totalHigh, totalMed, totalLow)
	_ = w.Flush()
	fmt.Fprintln(os.Stderr)
}

// ══════════════════════════════════════════════════════════════════════════
//  JSON output
// ══════════════════════════════════════════════════════════════════════════

func renderAuditJSON(cluster, timestamp string, totalNHIs int, results []scoring.ScoringResult) error {
	report := auditReport{
		Cluster:   cluster,
		Timestamp: timestamp,
		TotalNHIs: totalNHIs,
		Summary:   scoring.CountBySeverity(results),
		Findings:  results,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// ══════════════════════════════════════════════════════════════════════════
//  Markdown output
// ══════════════════════════════════════════════════════════════════════════

func renderAuditMarkdown(cluster, timestamp string, totalNHIs int, results []scoring.ScoringResult) {
	counts := scoring.CountBySeverity(results)

	fmt.Println("# NHI-Watch Audit Report")
	fmt.Println()
	fmt.Printf("**Cluster:** %s  \n", cluster)
	fmt.Printf("**Date:** %s  \n", timestamp)
	fmt.Printf("**NHIs Discovered:** %d  \n", totalNHIs)
	fmt.Println()

	// Summary table.
	fmt.Println("## Summary")
	fmt.Println()
	fmt.Println("| Severity | Count |")
	fmt.Println("|----------|-------|")
	for _, sev := range scoring.AllSeverities() {
		c := counts[sev]
		if c > 0 {
			fmt.Printf("| %s | %d |\n", sev, c)
		}
	}
	fmt.Println()

	// Findings by severity.
	fmt.Println("## Findings")

	for _, sev := range scoring.AllSeverities() {
		sevResults := filterResultsBySeverity(results, sev)
		if len(sevResults) == 0 {
			continue
		}

		fmt.Println()
		fmt.Printf("### %s\n", sev)

		for _, r := range sevResults {
			fmt.Println()
			ruleIDs := make([]string, 0, len(r.Results))
			for _, rr := range r.Results {
				ruleIDs = append(ruleIDs, rr.RuleID)
			}

			fmt.Printf("#### [%d] %s `%s` (%s)\n", r.FinalScore, r.Type, r.Name, r.Namespace)
			fmt.Printf("- **Rules:** %s\n", strings.Join(ruleIDs, ", "))

			for _, rr := range r.Results {
				if rr.Detail != "" {
					fmt.Printf("- %s: %s\n", rr.RuleID, rr.Detail)
				}
			}

			if r.Recommendation != "" {
				fmt.Printf("- **Recommendation:** %s\n", r.Recommendation)
			}
		}
	}

	// Statistics table.
	fmt.Println()
	fmt.Println("## Statistics")
	fmt.Println()
	fmt.Println("| NHI Type | Count | Critical | High | Medium | Low/Info |")
	fmt.Println("|----------|-------|----------|------|--------|----------|")

	typeStats := scoring.CountByTypeAndSeverity(results)
	for _, t := range discovery.AllNHITypes() {
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
		fmt.Printf("| %s | %d | %d | %d | %d | %d |\n", ts, count, crit, high, med, low)
	}
	fmt.Println()
}

// ══════════════════════════════════════════════════════════════════════════
//  Helpers
// ══════════════════════════════════════════════════════════════════════════

func filterResultsBySeverity(results []scoring.ScoringResult, sev scoring.Severity) []scoring.ScoringResult {
	filtered := make([]scoring.ScoringResult, 0)
	for _, r := range results {
		if r.FinalSeverity == sev {
			filtered = append(filtered, r)
		}
	}
	return filtered
}
