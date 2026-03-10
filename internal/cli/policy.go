package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Zyrakk/nhi-watch/internal/policy"
)

var (
	policyOutputDir string
	policyFormat    string
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Generate security policies from scoring rules",
}

var policyExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export Gatekeeper ConstraintTemplates",
	Long: `Generate OPA/Gatekeeper ConstraintTemplates from NHI-Watch scoring rules.

Turns detection into prevention by generating admission policies that
enforce the same rules NHI-Watch scores against.

Supported rules:
  CLUSTER_ADMIN_BINDING      Block cluster-admin bindings
  WILDCARD_PERMISSIONS       Block wildcard verb/resource permissions
  DEFAULT_SA_HAS_BINDINGS    Block bindings to default ServiceAccount
  SECRET_ACCESS_CLUSTER_WIDE Block cluster-wide secret access
  AUTOMOUNT_TOKEN_ENABLED    Block automounted SA tokens

Output is multi-document YAML to stdout, or individual files with --output-dir.`,
	RunE: runPolicyExport,
}

func init() {
	policyExportCmd.Flags().StringVar(&policyOutputDir, "output-dir", "", "write individual YAML files to this directory")
	policyExportCmd.Flags().StringVar(&policyFormat, "format", "gatekeeper", "policy format: gatekeeper")
	policyCmd.AddCommand(policyExportCmd)
	rootCmd.AddCommand(policyCmd)
}

func runPolicyExport(cmd *cobra.Command, args []string) error {
	if policyFormat != "gatekeeper" {
		return fmt.Errorf("unsupported policy format %q; supported: gatekeeper", policyFormat)
	}

	templates, err := policy.GenerateGatekeeperTemplates()
	if err != nil {
		return fmt.Errorf("generating templates: %w", err)
	}

	if policyOutputDir != "" {
		if err := os.MkdirAll(policyOutputDir, 0755); err != nil {
			return fmt.Errorf("creating output dir: %w", err)
		}
		for _, tmpl := range templates {
			filename := filepath.Join(policyOutputDir, "nhiwatch-"+tmpl.RuleID+".yaml")
			if err := os.WriteFile(filename, []byte(tmpl.YAML), 0644); err != nil {
				return fmt.Errorf("writing %s: %w", filename, err)
			}
			if _, err := fmt.Fprintf(os.Stderr, "Written: %s\n", filename); err != nil {
				return fmt.Errorf("writing status: %w", err)
			}
		}
	} else {
		for i, tmpl := range templates {
			if i > 0 {
				if _, err := fmt.Println("---"); err != nil {
					return fmt.Errorf("writing separator: %w", err)
				}
			}
			if _, err := fmt.Print(tmpl.YAML); err != nil {
				return fmt.Errorf("writing template: %w", err)
			}
		}
	}

	return nil
}
