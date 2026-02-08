// Package scoring implements risk scoring for Non-Human Identities
// based on their permissions, token hygiene, and security posture.
//
// Phase 0: Stub — types and severity levels only.
//
// Phase 3 will implement a deterministic, YAML-configurable scoring engine:
//   - Risk score 0-100 per NHI
//   - Weighted factors loaded from configs/scoring-rules.yaml
//   - Built-in rules:
//   - CLUSTER_ADMIN_BINDING (weight: 40)
//   - WILDCARD_PERMISSIONS (weight: 25)
//   - SECRET_NOT_ROTATED_90D (weight: 20)
//   - AUTOMOUNT_TOKEN_ENABLED (weight: 15)
//   - DEFAULT_SA_WITH_BINDING (weight: 30)
//   - CERT_EXPIRING_30D (weight: 20)
//   - CROSS_NAMESPACE_SECRET_ACCESS (weight: 25)
//   - Aggregate cluster risk score
//   - Reproducible and auditable — no AI/ML, pure deterministic rules
package scoring

// Severity represents the risk level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL" // Score 80-100
	SeverityHigh     Severity = "HIGH"     // Score 60-79
	SeverityMedium   Severity = "MEDIUM"   // Score 40-59
	SeverityLow      Severity = "LOW"      // Score 20-39
	SeverityInfo     Severity = "INFO"     // Score 0-19
)

// SeverityFromScore maps a numeric score to its Severity level.
func SeverityFromScore(score int) Severity {
	switch {
	case score >= 80:
		return SeverityCritical
	case score >= 60:
		return SeverityHigh
	case score >= 40:
		return SeverityMedium
	case score >= 20:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// RuleID identifies a specific scoring rule.
type RuleID string

// Built-in rule identifiers (to be implemented in Phase 3).
const (
	RuleClusterAdminBinding        RuleID = "CLUSTER_ADMIN_BINDING"
	RuleWildcardPermissions        RuleID = "WILDCARD_PERMISSIONS"
	RuleSecretNotRotated90D        RuleID = "SECRET_NOT_ROTATED_90D"
	RuleAutomountTokenEnabled      RuleID = "AUTOMOUNT_TOKEN_ENABLED"
	RuleDefaultSAWithBinding       RuleID = "DEFAULT_SA_WITH_BINDING"
	RuleCertExpiring30D            RuleID = "CERT_EXPIRING_30D"
	RuleCrossNamespaceSecretAccess RuleID = "CROSS_NAMESPACE_SECRET_ACCESS"
	RulePermissionUsageGap         RuleID = "PERMISSION_USAGE_GAP" // Phase 4
)

// Finding represents a single security issue detected by a rule.
type Finding struct {
	Rule        RuleID `json:"rule"`
	Description string `json:"description"`
	Weight      int    `json:"weight"`
}

// RiskScore holds the calculated risk for a single NHI.
type RiskScore struct {
	NHIID     string    `json:"nhi_id"`
	Name      string    `json:"name"`
	Namespace string    `json:"namespace"`
	Score     int       `json:"score"`    // 0 (safe) – 100 (critical)
	Severity  Severity  `json:"severity"`
	Findings  []Finding `json:"findings"`
}