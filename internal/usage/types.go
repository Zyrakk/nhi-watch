// Package usage defines the core types for NHI usage profiling and the
// pluggable interface that data sources (audit webhook, Wazuh, Falco)
// implement to feed observed API activity into the scoring engine.
package usage

import "time"

// UsageRecord represents a single observed API interaction by a service
// account. Records are aggregated by verb+resource+apiGroup+namespace.
type UsageRecord struct {
	Verb      string    `json:"verb"`
	Resource  string    `json:"resource"`
	APIGroup  string    `json:"api_group,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	Count     int64     `json:"count"`
	LastSeen  time.Time `json:"last_seen"`
}

// UsageProfile aggregates all observed API activity for a single service
// account over a time window. The profile is used to compare granted RBAC
// permissions against actual usage, enabling least-privilege scoring.
type UsageProfile struct {
	ServiceAccount  string        `json:"service_account"`
	Namespace       string        `json:"namespace"`
	Records         []UsageRecord `json:"records"`
	FirstSeen       time.Time     `json:"first_seen"`
	LastUpdated     time.Time     `json:"last_updated"`
	ObservationDays int           `json:"observation_days"`
	TotalCalls      int64         `json:"total_calls"`
}

// Confidence indicates how reliable a usage profile is, based on the
// length of the observation window. Longer windows yield higher confidence.
type Confidence string

const (
	// ConfidenceNone means fewer than 7 days of observation data.
	ConfidenceNone Confidence = "none"

	// ConfidenceMedium means 7-29 days of observation data.
	ConfidenceMedium Confidence = "medium"

	// ConfidenceHigh means 30 or more days of observation data.
	ConfidenceHigh Confidence = "high"
)

// ConfidenceFromDays maps an observation window length to a Confidence level.
func ConfidenceFromDays(days int) Confidence {
	switch {
	case days >= 30:
		return ConfidenceHigh
	case days >= 7:
		return ConfidenceMedium
	default:
		return ConfidenceNone
	}
}

// IsInactive returns true when no API calls have been observed for this
// service account during the entire observation window.
func (p *UsageProfile) IsInactive() bool {
	return p.TotalCalls == 0
}

// GetConfidence returns the confidence level of this profile based on
// the number of observation days.
func (p *UsageProfile) GetConfidence() Confidence {
	return ConfidenceFromDays(p.ObservationDays)
}
