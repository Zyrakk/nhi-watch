package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Zyrakk/nhi-watch/internal/baseline"
	"github.com/Zyrakk/nhi-watch/internal/discovery"
	"github.com/Zyrakk/nhi-watch/internal/k8s"
	"github.com/Zyrakk/nhi-watch/internal/permissions"
	"github.com/Zyrakk/nhi-watch/internal/reporter"
	"github.com/Zyrakk/nhi-watch/internal/scoring"
)

var (
	auditSeverity     string
	auditTypeFilter   string
	auditRulesConfig  string
	auditFailOn       string
	auditSaveBaseline string
	auditBaseline     string
	auditQuiet        bool
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
  sarif     SARIF v2.1.0 for GitHub Security tab

CI/CD integration:
  --fail-on high          Exit code 2 if findings >= HIGH severity
  --quiet                 Suppress non-error output (for scripting)
  --save-baseline bl.json Save current results as baseline
  --baseline bl.json      Only fail on new/regressed findings vs baseline`,
	RunE: runAudit,
}

func init() {
	auditCmd.Flags().StringVar(&auditSeverity, "severity", "", "minimum severity to report: critical, high, medium, low, info")
	auditCmd.Flags().StringVar(&auditTypeFilter, "type", "", "filter by NHI type (e.g. service-account, secret-credential)")
	auditCmd.Flags().StringVar(&auditRulesConfig, "rules-config", "", "custom scoring rules file (not yet implemented)")
	auditCmd.Flags().StringVar(&auditFailOn, "fail-on", "", "exit code 2 if findings at or above this severity (critical|high|medium|low)")
	auditCmd.Flags().StringVar(&auditSaveBaseline, "save-baseline", "", "save current results as baseline to this file path")
	auditCmd.Flags().StringVar(&auditBaseline, "baseline", "", "compare results against this baseline file (only new/regressed findings trigger --fail-on)")
	auditCmd.Flags().BoolVarP(&auditQuiet, "quiet", "q", false, "suppress all non-error output (warnings, progress, table rendering to stderr)")
	rootCmd.AddCommand(auditCmd)
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
		if verbose && !auditQuiet {
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
		if !auditQuiet {
			fmt.Fprintf(os.Stderr, "⚠  %v\n", e)
		}
	}

	logf("[*] Discovered %d NHIs", len(nhis))

	// ── Phase 2: Permission Resolution ────────────────────────────────
	logf("[*] Phase 2: Resolving RBAC permissions...")

	resolver, err := permissions.NewResolver(ctx, clients.Clientset)
	if err != nil {
		if !auditQuiet {
			fmt.Fprintf(os.Stderr, "⚠  RBAC resolution failed: %v (scoring will proceed without permission data)\n", err)
		}
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

	report := &reporter.AuditReport{
		ClusterName: clusterName,
		Timestamp:   timestamp,
		TotalNHIs:   totalNHIs,
		Results:     results,
	}

	var format reporter.Format
	switch outputFmt {
	case "json":
		format = reporter.FormatJSON
	case "sarif":
		format = reporter.FormatSARIF
	case "table":
		format = reporter.FormatTable
	default:
		return fmt.Errorf("unsupported output format: %q (use: table, json, sarif)", outputFmt)
	}

	r := reporter.New(format)
	out, err := r.Render(report)
	if err != nil {
		return fmt.Errorf("rendering report: %w", err)
	}

	// Stream routing: table → stderr, JSON/SARIF → stdout.
	if format == reporter.FormatTable {
		if !auditQuiet {
			_, _ = os.Stderr.Write(out)
		}
	} else {
		_, _ = os.Stdout.Write(out)
		// JSON/SARIF: ensure trailing newline for shell friendliness.
		if len(out) > 0 && out[len(out)-1] != '\n' {
			_, _ = fmt.Fprintln(os.Stdout)
		}
	}

	// ── CI/CD: Save baseline ─────────────────────────────────────────
	if auditSaveBaseline != "" {
		if err := baseline.Save(auditSaveBaseline, results, clusterName); err != nil {
			return fmt.Errorf("saving baseline: %w", err)
		}
		if !auditQuiet {
			fmt.Fprintf(os.Stderr, "Baseline saved to %s (%d findings)\n", auditSaveBaseline, len(results))
		}
	}

	// ── CI/CD: Fail-on threshold ─────────────────────────────────────
	if auditFailOn != "" {
		failSev := scoring.ParseSeverity(auditFailOn)
		if failSev == "" {
			return fmt.Errorf("invalid severity for --fail-on: %q; valid values: critical, high, medium, low", auditFailOn)
		}

		if auditBaseline != "" {
			bl, err := baseline.Load(auditBaseline)
			if err != nil {
				return fmt.Errorf("loading baseline: %w", err)
			}
			diff := baseline.Diff(results, bl)
			if diff.HasFailures(failSev) {
				return NewExitCodeError(2, "FAIL: %d new, %d regressed findings at %s or above",
					len(diff.New), len(diff.Regressed), auditFailOn)
			}
		} else {
			// No baseline: fail on any finding at threshold.
			filtered := scoring.FilterBySeverity(results, failSev)
			if len(filtered) > 0 {
				return NewExitCodeError(2, "FAIL: %d findings at %s or above",
					len(filtered), auditFailOn)
			}
		}
	}

	return nil
}
