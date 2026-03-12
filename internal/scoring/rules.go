package scoring

import (
	"fmt"
	"strings"
	"time"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
)

// nowFunc returns the current time. Override in tests for deterministic results.
var nowFunc = time.Now

// DefaultRules returns the built-in scoring rules.
func DefaultRules() []Rule {
	rules := []Rule{
		// ── ServiceAccount rules (7) ──────────────────────────────────
		ruleClusterAdminBinding(),
		ruleWildcardPermissions(),
		ruleDefaultSAHasBindings(),
		ruleSecretAccessClusterWide(),
		ruleCrossNamespaceSecretAccess(),
		ruleAutomountTokenEnabled(),
		ruleNoBindingsButAutomount(),

		// ── Secret rules (6) ──────────────────────────────────────────
		ruleSecretNotRotated180D(),
		ruleSecretNotRotated90D(),
		ruleTLSCertExpired(),
		ruleTLSCertExpires30D(),
		ruleTLSCertExpires90D(),
		ruleContainsPrivateKey(),

		// ── cert-manager Certificate rules (3) ────────────────────────
		ruleCertNotReady(),
		ruleCertExpires30D(),
		ruleCertExpires90D(),
	}

	// ── Inactive NHI rules (2) — require usage data ───────────────
	rules = append(rules, InactiveRules()...)

	return rules
}

// ══════════════════════════════════════════════════════════════════════
//  ServiceAccount rules
// ══════════════════════════════════════════════════════════════════════

func ruleClusterAdminBinding() Rule {
	return Rule{
		ID:          "CLUSTER_ADMIN_BINDING",
		Description: "ServiceAccount is bound to cluster-admin ClusterRole",
		Severity:    SeverityCritical,
		Score:       95,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeServiceAccount},
		CISControls: []string{"5.1.1"},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			if nhi.Permissions == nil {
				return false, ""
			}
			if !hasFlag(nhi, "CLUSTER_ADMIN") {
				return false, ""
			}
			for _, b := range nhi.Permissions.Bindings {
				if b.RoleRef == "cluster-admin" && b.RoleKind == "ClusterRole" {
					return true, fmt.Sprintf("Bound to cluster-admin via %s %q", b.Kind, b.Name)
				}
			}
			return true, "Bound to cluster-admin ClusterRole"
		},
	}
}

func ruleWildcardPermissions() Rule {
	return Rule{
		ID:          "WILDCARD_PERMISSIONS",
		Description: "ServiceAccount has wildcard (*) in verbs or resources",
		Severity:    SeverityHigh,
		Score:       80,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeServiceAccount},
		CISControls: []string{"5.1.3"},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			if nhi.Permissions == nil {
				return false, ""
			}
			parts := make([]string, 0, 3)
			if hasFlag(nhi, "WILDCARD_VERBS") {
				parts = append(parts, "wildcard verbs (*)")
			}
			if hasFlag(nhi, "WILDCARD_RESOURCES") {
				parts = append(parts, "wildcard resources (*)")
			}
			if hasFlag(nhi, "WILDCARD_APIGROUPS") {
				parts = append(parts, "wildcard apiGroups (*)")
			}
			if len(parts) == 0 {
				return false, ""
			}
			return true, "Has " + strings.Join(parts, ", ")
		},
	}
}

func ruleDefaultSAHasBindings() Rule {
	return Rule{
		ID:          "DEFAULT_SA_HAS_BINDINGS",
		Description: "Default ServiceAccount has additional RoleBindings",
		Severity:    SeverityHigh,
		Score:       70,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeServiceAccount},
		CISControls: []string{"5.1.5"},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			if nhi.Name != "default" {
				return false, ""
			}
			if nhi.Permissions == nil || len(nhi.Permissions.Bindings) == 0 {
				return false, ""
			}
			names := make([]string, 0, len(nhi.Permissions.Bindings))
			for _, b := range nhi.Permissions.Bindings {
				names = append(names, b.Name)
			}
			return true, fmt.Sprintf("Default SA has %d binding(s): %s",
				len(nhi.Permissions.Bindings), strings.Join(names, ", "))
		},
	}
}

func ruleSecretAccessClusterWide() Rule {
	return Rule{
		ID:          "SECRET_ACCESS_CLUSTER_WIDE",
		Description: "ServiceAccount can read Secrets cluster-wide",
		Severity:    SeverityMedium,
		Score:       60,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeServiceAccount},
		CISControls: []string{"5.1.2"},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			if nhi.Permissions == nil {
				return false, ""
			}
			if !hasFlag(nhi, "SECRET_ACCESS_CLUSTER_WIDE") {
				return false, ""
			}
			return true, "Can read Secrets in all namespaces via ClusterRoleBinding"
		},
	}
}

func ruleCrossNamespaceSecretAccess() Rule {
	return Rule{
		ID:          "CROSS_NAMESPACE_SECRET_ACCESS",
		Description: "ServiceAccount can read Secrets outside its own namespace",
		Severity:    SeverityMedium,
		Score:       55,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeServiceAccount},
		CISControls: []string{"5.1.2"},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			if nhi.Permissions == nil {
				return false, ""
			}
			if !hasFlag(nhi, "CROSS_NAMESPACE_SECRET_ACCESS") {
				return false, ""
			}
			return true, "Can access Secrets in namespaces other than " + nhi.Namespace
		},
	}
}

func ruleAutomountTokenEnabled() Rule {
	return Rule{
		ID:          "AUTOMOUNT_TOKEN_ENABLED",
		Description: "ServiceAccount has automountServiceAccountToken enabled",
		Severity:    SeverityLow,
		Score:       20,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeServiceAccount},
		CISControls: []string{"5.1.6"},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			automount := nhi.Metadata["automount_token"]
			if automount == "false" {
				return false, ""
			}
			// Only flag if the SA has actual bindings (meaningful permissions).
			if nhi.Permissions == nil || len(nhi.Permissions.Bindings) == 0 {
				return false, ""
			}
			if automount == "default (true)" {
				return true, "automountServiceAccountToken not explicitly set (defaults to true)"
			}
			return true, "automountServiceAccountToken is true"
		},
	}
}

func ruleNoBindingsButAutomount() Rule {
	return Rule{
		ID:          "NO_BINDINGS_BUT_AUTOMOUNT",
		Description: "ServiceAccount has no bindings but automount is enabled",
		Severity:    SeverityInfo,
		Score:       10,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeServiceAccount},
		CISControls: []string{"5.1.6"},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			automount := nhi.Metadata["automount_token"]
			if automount == "false" {
				return false, ""
			}
			// Only match if SA has NO bindings.
			if nhi.Permissions != nil && len(nhi.Permissions.Bindings) > 0 {
				return false, ""
			}
			return true, "No RBAC bindings but token is automounted to pods"
		},
	}
}

// ══════════════════════════════════════════════════════════════════════
//  Secret rules
// ══════════════════════════════════════════════════════════════════════

func ruleSecretNotRotated180D() Rule {
	return Rule{
		ID:          "SECRET_NOT_ROTATED_180D",
		Description: "Secret has not been rotated in more than 180 days",
		Severity:    SeverityCritical,
		Score:       90,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeSecretCredential},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			ageDays := int(nowFunc().Sub(nhi.CreatedAt).Hours() / 24)
			if ageDays <= 180 {
				return false, ""
			}
			detail := fmt.Sprintf("Created %d days ago", ageDays)
			if keys, ok := nhi.Metadata["credential_keys"]; ok && keys != "" {
				detail += ". Keys: " + keys
			}
			return true, detail
		},
	}
}

func ruleSecretNotRotated90D() Rule {
	return Rule{
		ID:          "SECRET_NOT_ROTATED_90D",
		Description: "Secret has not been rotated in more than 90 days",
		Severity:    SeverityHigh,
		Score:       75,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeSecretCredential},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			ageDays := int(nowFunc().Sub(nhi.CreatedAt).Hours() / 24)
			if ageDays <= 90 {
				return false, ""
			}
			detail := fmt.Sprintf("Created %d days ago", ageDays)
			if keys, ok := nhi.Metadata["credential_keys"]; ok && keys != "" {
				detail += ". Keys: " + keys
			}
			return true, detail
		},
	}
}

func ruleTLSCertExpired() Rule {
	return Rule{
		ID:          "TLS_CERT_EXPIRED",
		Description: "TLS certificate has expired",
		Severity:    SeverityCritical,
		Score:       95,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeTLSCert},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			if nhi.ExpiresAt.IsZero() {
				return false, ""
			}
			if nowFunc().Before(nhi.ExpiresAt) {
				return false, ""
			}
			expiredDays := int(nowFunc().Sub(nhi.ExpiresAt).Hours() / 24)
			detail := fmt.Sprintf("Expired %d days ago", expiredDays)
			if subj, ok := nhi.Metadata["subject"]; ok && subj != "" {
				detail = fmt.Sprintf("CN=%s. %s", subj, detail)
			}
			return true, detail
		},
	}
}

func ruleTLSCertExpires30D() Rule {
	return Rule{
		ID:          "TLS_CERT_EXPIRES_30D",
		Description: "TLS certificate expires within 30 days",
		Severity:    SeverityHigh,
		Score:       70,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeTLSCert},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			if nhi.ExpiresAt.IsZero() {
				return false, ""
			}
			remaining := nhi.ExpiresAt.Sub(nowFunc())
			if remaining < 0 || remaining > 30*24*time.Hour {
				return false, ""
			}
			days := int(remaining.Hours() / 24)
			detail := fmt.Sprintf("Expires in %d days", days)
			if subj, ok := nhi.Metadata["subject"]; ok && subj != "" {
				detail = fmt.Sprintf("CN=%s. %s", subj, detail)
			}
			return true, detail
		},
	}
}

func ruleTLSCertExpires90D() Rule {
	return Rule{
		ID:          "TLS_CERT_EXPIRES_90D",
		Description: "TLS certificate expires within 90 days",
		Severity:    SeverityMedium,
		Score:       50,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeTLSCert},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			if nhi.ExpiresAt.IsZero() {
				return false, ""
			}
			remaining := nhi.ExpiresAt.Sub(nowFunc())
			if remaining < 0 || remaining > 90*24*time.Hour {
				return false, ""
			}
			days := int(remaining.Hours() / 24)
			detail := fmt.Sprintf("Expires in %d days", days)
			if subj, ok := nhi.Metadata["subject"]; ok && subj != "" {
				detail = fmt.Sprintf("CN=%s. %s", subj, detail)
			}
			return true, detail
		},
	}
}

func ruleContainsPrivateKey() Rule {
	return Rule{
		ID:          "CONTAINS_PRIVATE_KEY",
		Description: "Secret contains keys with private key patterns",
		Severity:    SeverityMedium,
		Score:       55,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeSecretCredential},
		CISControls: []string{"5.4.1"},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			matched := make([]string, 0)
			for _, key := range nhi.Keys {
				lower := strings.ToLower(key)
				if strings.Contains(lower, "private") || strings.HasSuffix(lower, ".key") {
					matched = append(matched, key)
				}
			}
			if len(matched) == 0 {
				return false, ""
			}
			return true, "Contains private key data in: " + strings.Join(matched, ", ")
		},
	}
}

// ══════════════════════════════════════════════════════════════════════
//  cert-manager Certificate rules
// ══════════════════════════════════════════════════════════════════════

func ruleCertNotReady() Rule {
	return Rule{
		ID:          "CERT_NOT_READY",
		Description: "cert-manager Certificate is not in Ready state",
		Severity:    SeverityHigh,
		Score:       75,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeCertManagerCertificate},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			ready := nhi.Metadata["ready"]
			if ready == "" || ready == "True" {
				return false, ""
			}
			detail := "Certificate is not ready (status: " + ready + ")"
			if reason, ok := nhi.Metadata["ready_reason"]; ok && reason != "" {
				detail += ", reason: " + reason
			}
			return true, detail
		},
	}
}

func ruleCertExpires30D() Rule {
	return Rule{
		ID:          "CERT_EXPIRES_30D",
		Description: "cert-manager Certificate expires within 30 days",
		Severity:    SeverityHigh,
		Score:       70,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeCertManagerCertificate},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			if nhi.ExpiresAt.IsZero() {
				return false, ""
			}
			remaining := nhi.ExpiresAt.Sub(nowFunc())
			if remaining < 0 || remaining > 30*24*time.Hour {
				return false, ""
			}
			days := int(remaining.Hours() / 24)
			detail := fmt.Sprintf("Expires in %d days", days)
			if nhi.Issuer != "" {
				detail += " (issuer: " + nhi.Issuer + ")"
			}
			return true, detail
		},
	}
}

func ruleCertExpires90D() Rule {
	return Rule{
		ID:          "CERT_EXPIRES_90D",
		Description: "cert-manager Certificate expires within 90 days",
		Severity:    SeverityMedium,
		Score:       50,
		AppliesTo:   []discovery.NHIType{discovery.NHITypeCertManagerCertificate},
		Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
			if nhi.ExpiresAt.IsZero() {
				return false, ""
			}
			remaining := nhi.ExpiresAt.Sub(nowFunc())
			if remaining < 0 || remaining > 90*24*time.Hour {
				return false, ""
			}
			days := int(remaining.Hours() / 24)
			detail := fmt.Sprintf("Expires in %d days", days)
			if nhi.Issuer != "" {
				detail += " (issuer: " + nhi.Issuer + ")"
			}
			return true, detail
		},
	}
}

// ══════════════════════════════════════════════════════════════════════
//  Helpers
// ══════════════════════════════════════════════════════════════════════

// hasFlag checks if the NHI's permission set contains the given flag string.
func hasFlag(nhi *discovery.NonHumanIdentity, flag string) bool {
	if nhi.Permissions == nil {
		return false
	}
	for _, f := range nhi.Permissions.Flags {
		if f == flag {
			return true
		}
	}
	return false
}
