package usage

import (
	"testing"
	"time"
)

func TestConfidenceFromDays(t *testing.T) {
	tests := []struct {
		name string
		days int
		want Confidence
	}{
		{name: "zero days", days: 0, want: ConfidenceNone},
		{name: "1 day", days: 1, want: ConfidenceNone},
		{name: "6 days (just below medium)", days: 6, want: ConfidenceNone},
		{name: "7 days (medium threshold)", days: 7, want: ConfidenceMedium},
		{name: "14 days", days: 14, want: ConfidenceMedium},
		{name: "29 days (just below high)", days: 29, want: ConfidenceMedium},
		{name: "30 days (high threshold)", days: 30, want: ConfidenceHigh},
		{name: "90 days", days: 90, want: ConfidenceHigh},
		{name: "365 days", days: 365, want: ConfidenceHigh},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConfidenceFromDays(tt.days)
			if got != tt.want {
				t.Errorf("ConfidenceFromDays(%d) = %q, want %q", tt.days, got, tt.want)
			}
		})
	}
}

func TestUsageProfile_IsInactive(t *testing.T) {
	t.Run("inactive profile with zero calls", func(t *testing.T) {
		p := &UsageProfile{
			ServiceAccount:  "unused-sa",
			Namespace:       "default",
			ObservationDays: 30,
			TotalCalls:      0,
		}
		if !p.IsInactive() {
			t.Error("expected IsInactive()=true for profile with 0 total calls")
		}
	})

	t.Run("active profile with calls", func(t *testing.T) {
		p := &UsageProfile{
			ServiceAccount:  "active-sa",
			Namespace:       "default",
			ObservationDays: 30,
			TotalCalls:      42,
			Records: []UsageRecord{{
				Verb:     "get",
				Resource: "pods",
				Count:    42,
				LastSeen: time.Now(),
			}},
		}
		if p.IsInactive() {
			t.Error("expected IsInactive()=false for profile with 42 total calls")
		}
	})
}

func TestUsageProfile_GetConfidence(t *testing.T) {
	t.Run("high confidence at 45 days", func(t *testing.T) {
		p := &UsageProfile{
			ServiceAccount:  "well-observed-sa",
			Namespace:       "production",
			ObservationDays: 45,
			TotalCalls:      1000,
		}
		got := p.GetConfidence()
		if got != ConfidenceHigh {
			t.Errorf("GetConfidence() = %q, want %q for 45 observation days", got, ConfidenceHigh)
		}
	})

	t.Run("none confidence at 3 days", func(t *testing.T) {
		p := &UsageProfile{
			ServiceAccount:  "new-sa",
			Namespace:       "staging",
			ObservationDays: 3,
			TotalCalls:      5,
		}
		got := p.GetConfidence()
		if got != ConfidenceNone {
			t.Errorf("GetConfidence() = %q, want %q for 3 observation days", got, ConfidenceNone)
		}
	})
}
