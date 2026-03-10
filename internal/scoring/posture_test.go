package scoring

import (
	"math"
	"testing"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
)

const floatTolerance = 1e-9

func floatEqual(a, b float64) bool {
	return math.Abs(a-b) < floatTolerance
}

// ── CalculatePostureMultiplier tests ─────────────────────────────────

func TestCalculatePostureMultiplier_NoPods(t *testing.T) {
	m := CalculatePostureMultiplier(nil)
	if m != 1.0 {
		t.Errorf("expected 1.0 for nil postures, got %f", m)
	}

	m = CalculatePostureMultiplier([]discovery.PodPosture{})
	if m != 1.0 {
		t.Errorf("expected 1.0 for empty postures, got %f", m)
	}
}

func TestCalculatePostureMultiplier_RestrictedPod(t *testing.T) {
	// A pod with no risky flags should return 1.0.
	postures := []discovery.PodPosture{
		{PodName: "safe-pod", Namespace: "default"},
	}
	m := CalculatePostureMultiplier(postures)
	if m != 1.0 {
		t.Errorf("expected 1.0 for restricted pod, got %f", m)
	}
}

func TestCalculatePostureMultiplier_PrivilegedPod(t *testing.T) {
	postures := []discovery.PodPosture{
		{PodName: "priv-pod", Namespace: "default", Privileged: true},
	}
	m := CalculatePostureMultiplier(postures)
	if m <= 1.0 {
		t.Errorf("expected multiplier > 1.0 for privileged pod, got %f", m)
	}
	// Privileged alone should add 0.20 → 1.20
	if !floatEqual(m, 1.20) {
		t.Errorf("expected 1.20 for privileged-only pod, got %f", m)
	}
}

func TestCalculatePostureMultiplier_FullHostAccess(t *testing.T) {
	postures := []discovery.PodPosture{
		{
			PodName:     "full-host-pod",
			Namespace:   "default",
			Privileged:  true,
			HostPID:     true,
			HostNetwork: true,
			HostPath:    true,
			RunAsRoot:   true,
		},
	}
	m := CalculatePostureMultiplier(postures)
	// 1.0 + 0.20 (privileged) + 0.10 (hostPID) + 0.05 (hostNetwork) + 0.05 (hostPath) + 0.05 (runAsRoot) = 1.45
	if m < 1.3 {
		t.Errorf("expected multiplier >= 1.3 for full host access, got %f", m)
	}
	expected := 1.45
	if !floatEqual(m, expected) {
		t.Errorf("expected %f for full host access pod, got %f", expected, m)
	}
}

func TestCalculatePostureMultiplier_AllFlags(t *testing.T) {
	postures := []discovery.PodPosture{
		{
			PodName:     "everything-pod",
			Namespace:   "default",
			Privileged:  true,
			HostPID:     true,
			HostNetwork: true,
			HostIPC:     true,
			HostPath:    true,
			RunAsRoot:   true,
		},
	}
	m := CalculatePostureMultiplier(postures)
	// 1.0 + 0.20 + 0.10 + 0.05 + 0.05 + 0.05 + 0.05 = 1.50
	expected := 1.50
	if !floatEqual(m, expected) {
		t.Errorf("expected %f for all-flags pod, got %f", expected, m)
	}
}

func TestCalculatePostureMultiplier_WorstPodWins(t *testing.T) {
	postures := []discovery.PodPosture{
		// Safe pod
		{PodName: "safe-pod", Namespace: "default"},
		// Medium risk pod
		{PodName: "medium-pod", Namespace: "default", RunAsRoot: true},
		// Worst pod: privileged + hostPID
		{PodName: "worst-pod", Namespace: "default", Privileged: true, HostPID: true},
	}
	m := CalculatePostureMultiplier(postures)
	// Worst pod: 1.0 + 0.20 + 0.10 = 1.30
	expected := 1.30
	if !floatEqual(m, expected) {
		t.Errorf("expected worst pod multiplier %f, got %f", expected, m)
	}
}

func TestCalculatePostureMultiplier_HostIPCOnly(t *testing.T) {
	postures := []discovery.PodPosture{
		{PodName: "ipc-pod", Namespace: "default", HostIPC: true},
	}
	m := CalculatePostureMultiplier(postures)
	if m != 1.05 {
		t.Errorf("expected 1.05 for hostIPC-only pod, got %f", m)
	}
}

// ── applyMultiplier tests ────────────────────────────────────────────

func TestApplyMultiplier_CappedAt100(t *testing.T) {
	// 95 * 1.50 = 142.5, should cap at 100
	result := applyMultiplier(95, 1.50)
	if result != 100 {
		t.Errorf("expected 100 (capped), got %d", result)
	}

	// 80 * 1.30 = 104, should cap at 100
	result = applyMultiplier(80, 1.30)
	if result != 100 {
		t.Errorf("expected 100 (capped), got %d", result)
	}
}

func TestApplyMultiplier_NoChange(t *testing.T) {
	result := applyMultiplier(70, 1.0)
	if result != 70 {
		t.Errorf("expected 70 (no change), got %d", result)
	}

	result = applyMultiplier(0, 1.0)
	if result != 0 {
		t.Errorf("expected 0 (no change), got %d", result)
	}
}

func TestApplyMultiplier_RoundsCorrectly(t *testing.T) {
	// 55 * 1.05 = 57.75, should round to 58
	result := applyMultiplier(55, 1.05)
	if result != 58 {
		t.Errorf("expected 58 (rounded from 57.75), got %d", result)
	}

	// 33 * 1.20 = 39.6, should round to 40
	result = applyMultiplier(33, 1.20)
	if result != 40 {
		t.Errorf("expected 40 (rounded from 39.6), got %d", result)
	}

	// 45 * 1.10 = 49.5, should round to 50 (math.Round rounds .5 to even, but 49.5 → 50)
	result = applyMultiplier(45, 1.10)
	if result != 50 {
		t.Errorf("expected 50 (rounded from 49.5), got %d", result)
	}
}
