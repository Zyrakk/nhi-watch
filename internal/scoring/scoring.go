// Package scoring implements deterministic risk scoring for Non-Human
// Identities based on their permissions, token hygiene, and security posture.
//
// Phase 3: Deterministic, rule-based scoring engine.
//
//   - Risk score 0-100 per NHI (final score = max of all matching rules)
//   - 16 built-in rules covering ServiceAccounts, Secrets, TLS certs, cert-manager
//   - Severity levels: CRITICAL (80-100), HIGH (60-79), MEDIUM (40-59), LOW (20-39), INFO (0-19)
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

// AllSeverities returns severities in descending order of severity.
func AllSeverities() []Severity {
	return []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}
}

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

// SeverityRank returns a numeric rank for sorting (higher = more severe).
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// SeverityMeetsThreshold returns true if s is at least as severe as threshold.
func SeverityMeetsThreshold(s, threshold Severity) bool {
	return SeverityRank(s) >= SeverityRank(threshold)
}
