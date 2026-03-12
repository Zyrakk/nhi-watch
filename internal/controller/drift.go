package controller

import (
	"fmt"
	"time"
)

// DriftEvent represents a detected change in NHI risk posture.
type DriftEvent struct {
	Type        string
	NHIID       string
	Name        string
	Namespace   string
	OldScore    int
	NewScore    int
	OldSeverity string
	NewSeverity string
	Detail      string
	Timestamp   time.Time
}

// detectDrift compares previous snapshots against current snapshots and returns
// drift events for new, resolved, regressed, and improved NHIs. Zero-score NHIs
// are ignored for both "new" and "resolved" events since they carry no risk.
func detectDrift(previous, current []NHISnapshot) []DriftEvent {
	now := time.Now().UTC()

	prevMap := make(map[string]NHISnapshot, len(previous))
	for _, s := range previous {
		prevMap[s.NHIID] = s
	}

	currMap := make(map[string]NHISnapshot, len(current))
	for _, s := range current {
		currMap[s.NHIID] = s
	}

	var events []DriftEvent

	// Check current against previous.
	for _, cur := range current {
		prev, existed := prevMap[cur.NHIID]
		if !existed {
			// New NHI — only emit if it has a non-zero score.
			if cur.Score > 0 {
				events = append(events, DriftEvent{
					Type:        "new",
					NHIID:       cur.NHIID,
					Name:        cur.Name,
					Namespace:   cur.Namespace,
					NewScore:    cur.Score,
					NewSeverity: cur.Severity,
					Detail:      fmt.Sprintf("new finding with score %d (%s)", cur.Score, cur.Severity),
					Timestamp:   now,
				})
			}
			continue
		}

		// Existed before — compare scores.
		if cur.Score > prev.Score {
			events = append(events, DriftEvent{
				Type:        "regressed",
				NHIID:       cur.NHIID,
				Name:        cur.Name,
				Namespace:   cur.Namespace,
				OldScore:    prev.Score,
				NewScore:    cur.Score,
				OldSeverity: prev.Severity,
				NewSeverity: cur.Severity,
				Detail:      fmt.Sprintf("score increased from %d to %d", prev.Score, cur.Score),
				Timestamp:   now,
			})
		} else if cur.Score < prev.Score {
			events = append(events, DriftEvent{
				Type:        "improved",
				NHIID:       cur.NHIID,
				Name:        cur.Name,
				Namespace:   cur.Namespace,
				OldScore:    prev.Score,
				NewScore:    cur.Score,
				OldSeverity: prev.Severity,
				NewSeverity: cur.Severity,
				Detail:      fmt.Sprintf("score decreased from %d to %d", prev.Score, cur.Score),
				Timestamp:   now,
			})
		} else if cur.RulesHash != prev.RulesHash {
			// Same score but different matched rules.
			events = append(events, DriftEvent{
				Type:        "regressed",
				NHIID:       cur.NHIID,
				Name:        cur.Name,
				Namespace:   cur.Namespace,
				OldScore:    prev.Score,
				NewScore:    cur.Score,
				OldSeverity: prev.Severity,
				NewSeverity: cur.Severity,
				Detail:      "matched rules changed (same score)",
				Timestamp:   now,
			})
		}
		// Same score and same RulesHash → no event.
	}

	// Check previous not in current — resolved.
	for _, prev := range previous {
		if _, exists := currMap[prev.NHIID]; !exists && prev.Score > 0 {
			events = append(events, DriftEvent{
				Type:        "resolved",
				NHIID:       prev.NHIID,
				Name:        prev.Name,
				Namespace:   prev.Namespace,
				OldScore:    prev.Score,
				OldSeverity: prev.Severity,
				Detail:      fmt.Sprintf("finding resolved (was score %d)", prev.Score),
				Timestamp:   now,
			})
		}
	}

	return events
}
