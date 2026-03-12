package scoring

import (
	"fmt"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
	"github.com/Zyrakk/nhi-watch/internal/usage"
)

// InactiveRules returns scoring rules that detect ServiceAccounts with zero
// observed API calls. Rules only fire when usage data is available and the
// confidence level meets the rule's threshold — nil UsageProfile (no data)
// never triggers a finding, ensuring zero false positives.
func InactiveRules() []Rule {
	return []Rule{
		{
			ID:          "INACTIVE_NHI_HIGH",
			Description: "ServiceAccount with 0 API calls over 30+ days of observation (high confidence)",
			Severity:    SeverityMedium,
			Score:       55,
			AppliesTo:   []discovery.NHIType{discovery.NHITypeServiceAccount},
			Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
				if nhi.UsageProfile == nil {
					return false, ""
				}
				if !nhi.UsageProfile.IsInactive() {
					return false, ""
				}
				if nhi.UsageProfile.GetConfidence() != usage.ConfidenceHigh {
					return false, ""
				}
				return true, fmt.Sprintf("0 API calls observed over %d days (high confidence)", nhi.UsageProfile.ObservationDays)
			},
		},
		{
			ID:          "INACTIVE_NHI_MEDIUM",
			Description: "ServiceAccount with 0 API calls over 7-29 days of observation (medium confidence)",
			Severity:    SeverityLow,
			Score:       25,
			AppliesTo:   []discovery.NHIType{discovery.NHITypeServiceAccount},
			Evaluate: func(nhi *discovery.NonHumanIdentity) (bool, string) {
				if nhi.UsageProfile == nil {
					return false, ""
				}
				if !nhi.UsageProfile.IsInactive() {
					return false, ""
				}
				if nhi.UsageProfile.GetConfidence() != usage.ConfidenceMedium {
					return false, ""
				}
				return true, fmt.Sprintf("0 API calls observed over %d days (medium confidence — observe longer)", nhi.UsageProfile.ObservationDays)
			},
		},
	}
}
