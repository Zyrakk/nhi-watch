package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
	"github.com/Zyrakk/nhi-watch/internal/k8s"
	"github.com/Zyrakk/nhi-watch/internal/remediation"
)

var (
	remediateOutputDir string
	remediateDryRun    bool
	remediateAll       bool
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
  nhi-watch remediate --all
  nhi-watch remediate --all --output-dir=./fixes/`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRemediate,
}

func init() {
	remediateCmd.Flags().StringVar(&remediateOutputDir, "output-dir", "", "write YAML files to this directory instead of stdout")
	remediateCmd.Flags().BoolVar(&remediateDryRun, "dry-run", true, "only print YAML, do not write files (default: true)")
	remediateCmd.Flags().BoolVar(&remediateAll, "all", false, "generate remediation for all known workloads in the cluster")
	rootCmd.AddCommand(remediateCmd)
}

func runRemediate(cmd *cobra.Command, args []string) error {
	if len(args) == 0 && !remediateAll {
		return fmt.Errorf("specify a ServiceAccount name with -n namespace, or use --all")
	}
	if len(args) > 0 && remediateAll {
		return fmt.Errorf("cannot specify both a ServiceAccount name and --all")
	}

	if remediateAll {
		return runRemediateAll()
	}

	saName := args[0]

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

	return writeRemediationYAML(nhi.Name, yaml)
}

func runRemediateAll() error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	clients, err := k8s.NewClients(k8s.ClientOpts{
		Kubeconfig: kubeconfig,
		Context:    kubeCtx,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to cluster: %w", err)
	}

	logf := func(format string, args ...interface{}) {
		if verbose {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	discoverOpts := discovery.DiscoverOpts{
		Namespace:  namespace,
		TypeFilter: discovery.NHITypeServiceAccount,
		Verbose:    verbose,
		LogFunc:    logf,
	}

	nhis, errs := discovery.DiscoverAll(ctx, clients.Clientset, clients.Discovery, clients.Dynamic, discoverOpts)
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "⚠  %v\n", e)
	}

	generated := 0
	for i := range nhis {
		yaml, err := remediation.GenerateYAML(&nhis[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠  %s/%s: %v\n", nhis[i].Namespace, nhis[i].Name, err)
			continue
		}
		if yaml == "" {
			continue
		}
		generated++

		fmt.Fprintf(os.Stderr, "Remediation available for ServiceAccount %s/%s\n", nhis[i].Namespace, nhis[i].Name)
		if err := writeRemediationYAML(nhis[i].Name, yaml); err != nil {
			return err
		}
	}

	fmt.Fprintf(os.Stderr, "Remediation generated for %d ServiceAccount(s)\n", generated)
	if generated == 0 {
		fmt.Fprintf(os.Stderr, "Supported workloads: traefik, cert-manager\n")
	}
	return nil
}

func writeRemediationYAML(name, yaml string) error {
	if remediateOutputDir != "" && !remediateDryRun {
		filename := filepath.Join(remediateOutputDir, name+"-remediation.yaml")
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
