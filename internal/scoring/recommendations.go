package scoring

import "strings"

// recommendationMap provides remediation advice for each rule ID.
var recommendationMap = map[string]string{
	"CLUSTER_ADMIN_BINDING": "Remove the cluster-admin ClusterRoleBinding. Create a scoped ClusterRole with only the permissions this ServiceAccount actually needs.",

	"WILDCARD_PERMISSIONS": "Replace wildcard (*) permissions with explicit resource and verb lists. Audit actual API usage to determine the minimum required set.",

	"DEFAULT_SA_HAS_BINDINGS": "Create a dedicated ServiceAccount for pods that need these permissions. Remove all non-default bindings from the default SA.",

	"SECRET_ACCESS_CLUSTER_WIDE": "Restrict secret access to specific namespaces using RoleBindings instead of ClusterRoleBindings. Only grant secret access where strictly necessary.",

	"CROSS_NAMESPACE_SECRET_ACCESS": "Review whether cross-namespace secret access is required. Prefer namespace-scoped RoleBindings to limit the blast radius.",

	"AUTOMOUNT_TOKEN_ENABLED": "Set automountServiceAccountToken: false on the ServiceAccount or Pod spec unless the workload explicitly needs to call the Kubernetes API.",

	"NO_BINDINGS_BUT_AUTOMOUNT": "Consider setting automountServiceAccountToken: false since this ServiceAccount has no RBAC bindings. The automounted token provides no useful access.",

	"SECRET_NOT_ROTATED_180D": "Rotate this secret immediately. It has not been rotated in over 180 days. Consider migrating to a secrets manager (Vault, Sealed Secrets) with automatic rotation.",

	"SECRET_NOT_ROTATED_90D": "Rotate this secret. It has not been rotated in over 90 days. Establish a rotation policy (recommended: every 90 days or less).",

	"TLS_CERT_EXPIRED": "This TLS certificate has expired. Renew immediately or check cert-manager/issuer configuration if automatic renewal failed.",

	"TLS_CERT_EXPIRES_30D": "This TLS certificate expires within 30 days. Ensure cert-manager or your renewal process is configured. Renew manually if needed.",

	"TLS_CERT_EXPIRES_90D": "This TLS certificate expires within 90 days. Verify that automatic renewal is configured and working.",

	"CONTAINS_PRIVATE_KEY": "Ensure private key material in this secret is necessary and properly secured. Consider using a secrets manager or Kubernetes CSI driver for sensitive key material.",

	"CERT_NOT_READY": "The cert-manager Certificate is not in Ready state. Check the Certificate status, issuer configuration, and cert-manager logs for errors.",

	"CERT_EXPIRES_30D": "The cert-manager Certificate expires within 30 days. Verify renewBefore is configured and cert-manager is healthy.",

	"CERT_EXPIRES_90D": "The cert-manager Certificate expires within 90 days. Verify the renewal pipeline is functional.",

	"INACTIVE_NHI_HIGH":   "Remove or disable this ServiceAccount — it has not made any API calls in 30+ days. If still needed, review its RBAC bindings and reduce permissions to minimum required.",
	"INACTIVE_NHI_MEDIUM": "Monitor this ServiceAccount — no API calls observed yet, but observation period is short (7-29 days). If unused after 30 days, consider removal.",
}

// GenerateRecommendation creates a combined recommendation from multiple rule results.
func GenerateRecommendation(results []RuleResult) string {
	if len(results) == 0 {
		return ""
	}

	// Deduplicate and collect recommendations in rule order.
	seen := make(map[string]bool)
	recommendations := make([]string, 0, len(results))

	for _, r := range results {
		if seen[r.RuleID] {
			continue
		}
		seen[r.RuleID] = true
		if rec, ok := recommendationMap[r.RuleID]; ok {
			recommendations = append(recommendations, rec)
		}
	}

	return strings.Join(recommendations, " ")
}
