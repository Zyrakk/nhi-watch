package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run a full NHI security audit with risk scoring",
	Long: `Execute a comprehensive audit that combines discovery, permission
analysis, and risk scoring into a single prioritized report.

Combines all phases:
  1. Discover all NHIs in the cluster
  2. Resolve effective RBAC permissions
  3. Apply scoring rules (deterministic, YAML-configurable)
  4. Output findings ranked by severity with remediation hints

Flags (planned):
  --with-usage        Include audit log usage analysis (Phase 4)
  --config            Custom scoring rules file
  --severity          Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW)

Status: planned for Phase 3.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("⚠  full audit is not yet implemented (Phase 3)")
		fmt.Println("   Track progress: https://github.com/Zyrakk/nhi-watch/issues")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
}
