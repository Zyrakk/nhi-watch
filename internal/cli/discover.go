package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
	"github.com/Zyrakk/nhi-watch/internal/k8s"
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover Non-Human Identities in the cluster",
	Long: `Enumerate all Non-Human Identities (NHIs) across namespaces.

Phase 0 discovers:
  • ServiceAccounts (all namespaces or filtered by -n)

Future phases will add:
  • Secrets with credentials (API keys, tokens, passwords)
  • TLS certificates (cert-manager)
  • Agent identities (Wazuh, Falco, Datadog, ZCloud)
  • Cloud provider credentials (AWS, OCI, Azure)`,
	RunE: runDiscover,
}

func init() {
	rootCmd.AddCommand(discoverCmd)
}

func runDiscover(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Build client options from global flags.
	clientOpts := k8s.ClientOpts{
		Kubeconfig: kubeconfig,
		Context:    kubeCtx,
	}

	// Build Kubernetes client.
	client, err := k8s.NewClient(clientOpts)
	if err != nil {
		return fmt.Errorf("failed to connect to cluster: %w", err)
	}

	if verbose {
		_, _ = fmt.Fprintln(os.Stderr, "[*] Connected to cluster, discovering Non-Human Identities...")
	}

	// Run ServiceAccount discovery (Phase 0 scope).
	nhis, err := discovery.DiscoverServiceAccounts(ctx, client, namespace)
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	// Build the result envelope.
	result := &discovery.DiscoveryResult{
		ClusterName: k8s.ClusterName(clientOpts),
		Timestamp:   time.Now(),
		Identities:  nhis,
	}

	// Render output.
	switch outputFmt {
	case "json":
		return renderJSON(result)
	case "table":
		renderTable(result)
		return nil
	default:
		return fmt.Errorf("unsupported output format: %q (use: table, json)", outputFmt)
	}
}

func renderTable(result *discovery.DiscoveryResult) {
	_, _ = fmt.Fprintf(os.Stderr, "\nCluster: %s\n", result.ClusterName)
	_, _ = fmt.Fprintf(os.Stderr, "Scan time: %s\n\n", result.Timestamp.Format(time.RFC3339))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	_, _ = fmt.Fprintf(w, "NAMESPACE\tNAME\tTYPE\tSOURCE\tAUTOMOUNT\tAGE\n")

	for _, nhi := range result.Identities {
		automount := nhi.Metadata["automount_token"]
		age := discovery.FormatAge(time.Since(nhi.CreatedAt))

		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			nhi.Namespace,
			nhi.Name,
			nhi.Type,
			nhi.Source,
			automount,
			age,
		)
	}

	_ = w.Flush()

	// Summary by type (matches roadmap entregable).
	_, _ = fmt.Fprintln(os.Stderr)
	counts := result.CountByType()
	for nhiType, count := range counts {
		_, _ = fmt.Fprintf(os.Stderr, "  %-24s %d\n", nhiType, count)
	}
	_, _ = fmt.Fprintf(os.Stderr, "  ---\n")
	_, _ = fmt.Fprintf(os.Stderr, "  %-24s %d\n", "TOTAL NHIs", result.Total())
}

func renderJSON(result *discovery.DiscoveryResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}