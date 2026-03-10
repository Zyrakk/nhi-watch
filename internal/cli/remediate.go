package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
	"github.com/Zyrakk/nhi-watch/internal/remediation"
)

var (
	remediateOutputDir string
	remediateDryRun    bool
)

var remediateCmd = &cobra.Command{
	Use:   "remediate [sa-name]",
	Short: "Generate remediation YAML for known workloads",
	Long: `Generate least-privilege RBAC YAML proposals for recognized workloads.

Currently supports:
  - Traefik (ingress controller)
  - cert-manager (certificate management)

Generated YAML is marked as PROPOSAL and should be reviewed before applying.
Unknown workloads only receive text recommendations (no YAML generation).

Examples:
  nhi-watch remediate traefik -n kube-system
  nhi-watch remediate --output-dir=./fixes/`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRemediate,
}

func init() {
	remediateCmd.Flags().StringVar(&remediateOutputDir, "output-dir", "", "write YAML files to this directory instead of stdout")
	remediateCmd.Flags().BoolVar(&remediateDryRun, "dry-run", true, "only print YAML, do not write files (default: true)")
	rootCmd.AddCommand(remediateCmd)
}

func runRemediate(cmd *cobra.Command, args []string) error {
	var saName string
	if len(args) > 0 {
		saName = args[0]
	}

	// Build a minimal NHI from flags for template matching.
	nhi := &discovery.NonHumanIdentity{
		Name:      saName,
		Namespace: namespace,
		Type:      discovery.NHITypeServiceAccount,
	}

	yaml, err := remediation.GenerateYAML(nhi)
	if err != nil {
		return fmt.Errorf("generating remediation: %w", err)
	}

	if yaml == "" {
		fmt.Fprintf(os.Stderr, "No YAML remediation available for %q. Only text recommendations apply.\n", saName)
		fmt.Fprintf(os.Stderr, "Supported workloads: traefik, cert-manager\n")
		return nil
	}

	if remediateOutputDir != "" && !remediateDryRun {
		filename := filepath.Join(remediateOutputDir, nhi.Name+"-remediation.yaml")
		if err := os.MkdirAll(remediateOutputDir, 0755); err != nil {
			return fmt.Errorf("creating output dir: %w", err)
		}
		if err := os.WriteFile(filename, []byte(yaml), 0644); err != nil {
			return fmt.Errorf("writing file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Written to %s\n", filename)
	} else {
		fmt.Print(yaml)
	}

	return nil
}
