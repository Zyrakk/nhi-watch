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
	"github.com/Zyrakk/nhi-watch/internal/models"
	"github.com/Zyrakk/nhi-watch/internal/permissions"
)

var (
	flagOverprivileged bool
	flagScope          string
)

var permissionsCmd = &cobra.Command{
	Use:   "permissions [sa-name]",
	Short: "Analyze RBAC permissions for discovered NHIs",
	Long: `Evaluate the effective RBAC permissions for each Non-Human Identity,
resolving the full chain: ServiceAccount → RoleBinding/ClusterRoleBinding
→ Role/ClusterRole → verbs + resources.

Modes:
  nhi-watch permissions <name> -n <namespace>   Show resolved permissions for a specific SA
  nhi-watch permissions --overprivileged         List only SAs with excessive permissions
  nhi-watch permissions --scope cluster-wide     Filter by scope (cluster-wide, namespace-scoped, minimal, none)
  nhi-watch permissions                          List all SAs with their permission scope and flags

Detects overly-permissive patterns:
  • CLUSTER_ADMIN             — ServiceAccount bound to cluster-admin
  • WILDCARD_VERBS            — wildcard (*) in verbs
  • WILDCARD_RESOURCES        — wildcard (*) in resources
  • WILDCARD_APIGROUPS        — wildcard (*) in apiGroups
  • SECRET_ACCESS_CLUSTER_WIDE — can read secrets cluster-wide
  • DEFAULT_SA_HAS_BINDINGS   — default SA with additional bindings
  • CROSS_NAMESPACE_SECRET_ACCESS — can read secrets in other namespaces`,
	RunE: runPermissions,
}

func init() {
	permissionsCmd.Flags().BoolVar(&flagOverprivileged, "overprivileged", false, "show only NHIs with excessive permissions")
	permissionsCmd.Flags().StringVar(&flagScope, "scope", "", "filter by scope: cluster-wide, namespace-scoped, minimal, none")
	rootCmd.AddCommand(permissionsCmd)
}

// permResult holds a resolved SA with its permission set for rendering.
type permResult struct {
	Name      string                `json:"name"`
	Namespace string                `json:"namespace"`
	Source    string                `json:"source,omitempty"`
	CreatedAt time.Time             `json:"created_at"`
	Perms     *models.PermissionSet `json:"permissions"`
}

func runPermissions(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clientOpts := k8s.ClientOpts{
		Kubeconfig: kubeconfig,
		Context:    kubeCtx,
	}

	client, err := k8s.NewClient(clientOpts)
	if err != nil {
		return fmt.Errorf("failed to connect to cluster: %w", err)
	}

	if verbose {
		_, _ = fmt.Fprintln(os.Stderr, "[*] Connected to cluster, loading RBAC data...")
	}

	// Build the RBAC resolver (fetches and caches all RBAC objects once).
	resolver, err := permissions.NewResolver(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to build RBAC resolver: %w", err)
	}

	if verbose {
		_, _ = fmt.Fprintln(os.Stderr, "[*] RBAC cache loaded, discovering ServiceAccounts...")
	}

	// Run SA discovery.
	nhis, err := discovery.DiscoverServiceAccounts(ctx, client, namespace)
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	// If a specific SA name is given, show detailed view.
	if len(args) > 0 {
		saName := args[0]
		if namespace == "" {
			return fmt.Errorf("please specify namespace with -n when querying a specific ServiceAccount")
		}
		return renderDetailedPermissions(resolver, saName, namespace, nhis)
	}

	// Resolve permissions for all discovered SAs.
	results := make([]permResult, 0, len(nhis))
	for i := range nhis {
		nhi := &nhis[i]
		if nhi.Type != discovery.NHITypeServiceAccount {
			continue
		}

		ps := resolver.ResolveServiceAccount(nhi.Name, nhi.Namespace)
		permissions.Analyze(ps, nhi.Name, nhi.Namespace)
		nhi.Permissions = ps

		// Apply filters.
		if flagOverprivileged && len(ps.Flags) == 0 {
			continue
		}
		if flagScope != "" && string(ps.Scope) != flagScope {
			continue
		}

		results = append(results, permResult{
			Name:      nhi.Name,
			Namespace: nhi.Namespace,
			Source:    nhi.Source,
			CreatedAt: nhi.CreatedAt,
			Perms:     ps,
		})
	}

	switch outputFmt {
	case "json":
		return renderPermissionsJSON(results)
	case "table":
		renderPermissionsTable(results, k8s.ClusterName(clientOpts))
		return nil
	default:
		return fmt.Errorf("unsupported output format: %q (use: table, json)", outputFmt)
	}
}

func renderDetailedPermissions(resolver *permissions.Resolver, saName, saNamespace string, nhis []discovery.NonHumanIdentity) error {
	// Find the SA in the discovery results.
	var targetNHI *discovery.NonHumanIdentity
	for i := range nhis {
		if nhis[i].Name == saName && nhis[i].Namespace == saNamespace {
			targetNHI = &nhis[i]
			break
		}
	}

	if targetNHI == nil {
		return fmt.Errorf("ServiceAccount %q not found in namespace %q", saName, saNamespace)
	}

	ps := resolver.ResolveServiceAccount(saName, saNamespace)
	permissions.Analyze(ps, saName, saNamespace)
	targetNHI.Permissions = ps

	if outputFmt == "json" {
		result := permResult{
			Name:      targetNHI.Name,
			Namespace: targetNHI.Namespace,
			Source:    targetNHI.Source,
			CreatedAt: targetNHI.CreatedAt,
			Perms:     ps,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	// Detailed table output.
	fmt.Printf("ServiceAccount: %s (%s)\n", saName, saNamespace)
	fmt.Printf("Created: %s\n", targetNHI.CreatedAt.Format("2006-01-02"))
	if targetNHI.Source != "" && targetNHI.Source != "unknown" {
		fmt.Printf("Source: %s\n", targetNHI.Source)
	}
	fmt.Println()

	if len(ps.Bindings) == 0 {
		fmt.Println("RBAC Bindings: none")
	} else {
		fmt.Println("RBAC Bindings:")
		for _, b := range ps.Bindings {
			bindingDesc := fmt.Sprintf("  %s %q → %s %q", b.Kind, b.Name, b.RoleKind, b.RoleRef)
			fmt.Println(bindingDesc)

			// Print rules from this binding's role.
			for _, rule := range ps.Rules {
				if rule.Source != b.RoleRef {
					continue
				}
				resources := strings.Join(rule.Resources, ", ")
				verbs := strings.Join(rule.Verbs, ", ")
				line := fmt.Sprintf("    - %s: [%s]", resources, verbs)

				// Add warning annotations.
				if ruleHasSecretAccess(rule) && b.Kind == "ClusterRoleBinding" {
					line += "     ⚠ cluster-wide secret access"
				}
				if containsStr(rule.Verbs, "*") {
					line += "     ⚠ wildcard verbs"
				}
				if containsStr(rule.Resources, "*") {
					line += "     ⚠ wildcard resources"
				}

				fmt.Println(line)
			}
		}
	}

	fmt.Println()
	fmt.Printf("Scope: %s\n", strings.ToUpper(string(ps.Scope)))

	if len(ps.Flags) > 0 {
		fmt.Printf("Flags: %s\n", strings.Join(ps.Flags, ", "))
	}

	return nil
}

func renderPermissionsTable(results []permResult, clusterName string) {
	_, _ = fmt.Fprintf(os.Stderr, "\nCluster: %s\n\n", clusterName)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "NAMESPACE\tNAME\tSCOPE\tBINDINGS\tFLAGS\n")

	for _, r := range results {
		flags := "-"
		if len(r.Perms.Flags) > 0 {
			flags = strings.Join(r.Perms.Flags, ", ")
		}

		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
			r.Namespace,
			r.Name,
			r.Perms.Scope,
			len(r.Perms.Bindings),
			flags,
		)
	}
	_ = w.Flush()

	// Summary.
	_, _ = fmt.Fprintln(os.Stderr)
	scopeCounts := make(map[models.PermissionScope]int)
	flaggedCount := 0
	for _, r := range results {
		scopeCounts[r.Perms.Scope]++
		if len(r.Perms.Flags) > 0 {
			flaggedCount++
		}
	}

	for _, scope := range []models.PermissionScope{
		models.ScopeClusterWide,
		models.ScopeNamespaced,
		models.ScopeMinimal,
		models.ScopeNone,
	} {
		if c, ok := scopeCounts[scope]; ok {
			_, _ = fmt.Fprintf(os.Stderr, "  %-24s %d\n", scope, c)
		}
	}
	_, _ = fmt.Fprintf(os.Stderr, "  ---\n")
	_, _ = fmt.Fprintf(os.Stderr, "  %-24s %d\n", "TOTAL", len(results))
	_, _ = fmt.Fprintf(os.Stderr, "  %-24s %d\n", "FLAGGED", flaggedCount)
}

func renderPermissionsJSON(results []permResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

// ruleHasSecretAccess checks if a resolved rule grants access to secrets.
func ruleHasSecretAccess(rule models.ResolvedRule) bool {
	hasSecret := false
	for _, r := range rule.Resources {
		if r == "secrets" || r == "*" {
			hasSecret = true
			break
		}
	}
	if !hasSecret {
		return false
	}
	for _, ag := range rule.APIGroups {
		if ag == "" || ag == "*" {
			return true
		}
	}
	return false
}

// containsStr checks if a string slice contains a specific value.
func containsStr(ss []string, val string) bool {
	for _, s := range ss {
		if s == val {
			return true
		}
	}
	return false
}
