package controller

import "time"

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

// detectDrift compares previous snapshots against current snapshots.
// Full implementation in Task 4.
func detectDrift(previous, current []NHISnapshot) []DriftEvent {
	return nil
}
