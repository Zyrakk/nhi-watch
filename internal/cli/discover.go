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
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover Non-Human Identities in the cluster",
	Long: `Enumerate all Non-Human Identities (NHIs) across namespaces.

Discovers:
  • ServiceAccounts (all namespaces or filtered by -n)
  • Secrets with credentials (API keys, tokens, passwords)
  • TLS certificates (kubernetes.io/tls secrets with x509 parsing)
  • Legacy SA token secrets (pre-1.24)
  • Docker registry credentials
  • cert-manager Certificate resources (if installed)

Filters:
  --type TYPE    Show only NHIs of a specific type
  --stale        Show only stale NHIs (credentials > 90 days old)

Valid types: service-account, secret-credential, tls-certificate,
             sa-token, registry-credential, cert-manager-certificate`,
	RunE: runDiscover,
}

func init() {
	discoverCmd.Flags().StringVar(&typeFilter, "type", "", "filter by NHI type (e.g. secret-credential, tls-certificate)")
	discoverCmd.Flags().BoolVar(&staleOnly, "stale", false, "show only stale NHIs (> 90 days without rotation)")
	rootCmd.AddCommand(discoverCmd)
}

func runDiscover(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Validate --type flag if provided.
	if typeFilter != "" {
		valid := false
		for _, t := range discovery.AllNHITypes() {
			if discovery.NHIType(typeFilter) == t {
				valid = true
				break
			}
		}
		if !valid {
			validTypes := make([]string, 0, len(discovery.AllNHITypes()))
			for _, t := range discovery.AllNHITypes() {
				validTypes = append(validTypes, string(t))
			}
			return fmt.Errorf("invalid type %q; valid types: %s", typeFilter, strings.Join(validTypes, ", "))
		}
	}

	// Build client options from global flags.
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

	logf("[*] Connected to cluster, discovering Non-Human Identities...")

	// Run all discovery phases in parallel.
	opts := discovery.DiscoverOpts{
		Namespace:  namespace,
		TypeFilter: discovery.NHIType(typeFilter),
		StaleOnly:  staleOnly,
		Verbose:    verbose,
		LogFunc:    logf,
	}

	nhis, errs := discovery.DiscoverAll(ctx, clients.Clientset, clients.Discovery, clients.Dynamic, opts)

	// Log non-fatal errors.
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "⚠  %v\n", e)
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

	_, _ = fmt.Fprintf(w, "NAMESPACE\tNAME\tTYPE\tSOURCE\tDETAIL\tAGE\n")

	for _, nhi := range result.Identities {
		detail := renderDetail(nhi)
		age := discovery.FormatAge(time.Since(nhi.CreatedAt))

		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			nhi.Namespace,
			nhi.Name,
			nhi.Type,
			nhi.Source,
			detail,
			age,
		)
	}

	_ = w.Flush()

	// Summary by type.
	_, _ = fmt.Fprintln(os.Stderr)
	counts := result.CountByType()

	// Print in a deterministic order.
	typeOrder := discovery.AllNHITypes()
	for _, nhiType := range typeOrder {
		if count, ok := counts[nhiType]; ok {
			_, _ = fmt.Fprintf(os.Stderr, "  %-30s %d\n", nhiType, count)
		}
	}

	_, _ = fmt.Fprintf(os.Stderr, "  ---\n")
	_, _ = fmt.Fprintf(os.Stderr, "  %-30s %d\n", "TOTAL NHIs", result.Total())

	// Show stale count if relevant.
	staleCount := 0
	for _, nhi := range result.Identities {
		if nhi.Stale {
			staleCount++
		}
	}
	if staleCount > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "  %-30s %d ⚠\n", "STALE (>90d)", staleCount)
	}
}

// renderDetail returns the most relevant detail for the DETAIL column
// based on the NHI type.
func renderDetail(nhi discovery.NonHumanIdentity) string {
	switch nhi.Type {
	case discovery.NHITypeServiceAccount:
		automount := nhi.Metadata["automount_token"]
		if automount != "" {
			return "automount=" + automount
		}
		return ""

	case discovery.NHITypeTLSCert:
		parts := make([]string, 0, 2)
		if subj, ok := nhi.Metadata["subject"]; ok && subj != "" {
			parts = append(parts, "CN="+subj)
		}
		if !nhi.ExpiresAt.IsZero() {
			remaining := time.Until(nhi.ExpiresAt)
			if remaining < 0 {
				parts = append(parts, "EXPIRED")
			} else if remaining < 30*24*time.Hour {
				parts = append(parts, fmt.Sprintf("expires=%s ⚠", discovery.FormatAge(remaining)))
			} else {
				parts = append(parts, "expires="+discovery.FormatAge(remaining))
			}
		}
		if nhi.Stale {
			parts = append(parts, "stale")
		}
		return strings.Join(parts, " ")

	case discovery.NHITypeSecretCredential:
		parts := make([]string, 0, 2)
		if keys, ok := nhi.Metadata["credential_keys"]; ok {
			parts = append(parts, "keys=["+keys+"]")
		}
		if nhi.Stale {
			parts = append(parts, "stale ⚠")
		}
		return strings.Join(parts, " ")

	case discovery.NHITypeSAToken:
		parts := make([]string, 0, 2)
		if sa, ok := nhi.Metadata["service_account"]; ok {
			parts = append(parts, "sa="+sa)
		}
		if nhi.Stale {
			parts = append(parts, "stale ⚠")
		}
		return strings.Join(parts, " ")

	case discovery.NHITypeRegistryCredential:
		if nhi.Stale {
			return "stale ⚠"
		}
		return ""

	case discovery.NHITypeCertManagerCertificate:
		parts := make([]string, 0, 3)
		if nhi.Issuer != "" {
			parts = append(parts, "issuer="+nhi.Issuer)
		}
		if ready, ok := nhi.Metadata["ready"]; ok {
			parts = append(parts, "ready="+ready)
		}
		if !nhi.ExpiresAt.IsZero() {
			remaining := time.Until(nhi.ExpiresAt)
			if remaining < 0 {
				parts = append(parts, "EXPIRED")
			} else if remaining < 30*24*time.Hour {
				parts = append(parts, fmt.Sprintf("expires=%s ⚠", discovery.FormatAge(remaining)))
			} else {
				parts = append(parts, "expires="+discovery.FormatAge(remaining))
			}
		}
		return strings.Join(parts, " ")

	default:
		return ""
	}
}

func renderJSON(result *discovery.DiscoveryResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
