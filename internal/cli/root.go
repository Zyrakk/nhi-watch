// Package cli implements the Cobra command tree for NHI-Watch.
// All subcommands are registered in their own files via init().
package cli

import (
	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Global flags shared across all subcommands.
var (
	kubeconfig string
	kubeCtx    string
	outputFmt  string
	namespace  string
	verbose    bool
)

// Discover-specific flags (registered by discover.go).
var (
	typeFilter string
	staleOnly  bool
)

// rootCmd is the base command for nhi-watch.
var rootCmd = &cobra.Command{
	Use:   "nhi-watch",
	Short: "Discover, audit and score Non-Human Identities in Kubernetes/OpenShift",
	Long: `NHI-Watch is a security CLI that discovers all Non-Human Identities
(ServiceAccounts, Secrets, certificates, OIDC clients) in your Kubernetes
or OpenShift cluster, analyzes their RBAC permissions, and assigns a
risk score to help you harden your workload identity posture.

NHIs include:
  • ServiceAccounts with their RBAC bindings
  • Secrets containing credentials (API keys, tokens, passwords)
  • TLS certificates (cert-manager and native)
  • Legacy SA token secrets (pre-1.24)
  • Docker registry credentials
  • Agent identities (Wazuh, Falco, Datadog, ZCloud)
  • Cloud provider credentials (AWS, OCI, Azure)

Compatible with k3s, vanilla Kubernetes, and OpenShift.`,
	SilenceUsage: true,
}

// Execute runs the root command. Called from main.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig file (default: ~/.kube/config)")
	rootCmd.PersistentFlags().StringVar(&kubeCtx, "context", "", "kubernetes context to use")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "table", "output format: table, json")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "target namespace (default: all namespaces)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
}