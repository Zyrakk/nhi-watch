package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var permissionsCmd = &cobra.Command{
	Use:   "permissions [nhi-name]",
	Short: "Analyze RBAC permissions for discovered NHIs",
	Long: `Evaluate the effective RBAC permissions for each Non-Human Identity,
resolving the full chain: ServiceAccount → RoleBinding/ClusterRoleBinding
→ Role/ClusterRole → verbs + resources.

Detects overly-permissive patterns:
  • ServiceAccounts bound to cluster-admin
  • Wildcard (*) permissions on verbs or resources
  • Default ServiceAccounts with additional RoleBindings
  • Cross-namespace access to Secrets

Flags (planned):
  --overprivileged    Show only NHIs with excessive permissions

Status: planned for Phase 2.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("⚠  permissions analysis is not yet implemented (Phase 2)")
		fmt.Println("   Track progress: https://github.com/Zyrakk/nhi-watch/issues")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(permissionsCmd)
}
