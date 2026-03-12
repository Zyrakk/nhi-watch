package scoring

import (
	"fmt"
	"math"
	"strings"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
)

// CalculatePostureMultiplier returns a risk multiplier based on the worst
// pod security posture among all pods referencing an NHI.
// Returns 1.0 if no pods or all pods are restricted.
func CalculatePostureMultiplier(postures []discovery.PodPosture) float64 {
	if len(postures) == 0 {
		return 1.0
	}
	worst := 1.0
	for _, p := range postures {
		m := 1.0
		if p.Privileged {
			m += 0.20
		}
		if p.HostPID {
			m += 0.10
		}
		if p.HostNetwork {
			m += 0.05
		}
		if p.HostIPC {
			m += 0.05
		}
		if p.HostPath {
			m += 0.05
		}
		if p.RunAsRoot {
			m += 0.05
		}
		// Unrestricted egress = higher risk.
		// Only penalize if we have pod posture data and no restriction was found.
		// HasEgressRestriction=false is the default, so only apply when we've
		// actively checked (indicated by the posture having a PodName).
		if p.PodName != "" && !p.HasEgressRestriction {
			m += 0.10
		}
		if m > worst {
			worst = m
		}
	}
	return worst
}

// applyMultiplier scales a base score by the given multiplier and caps at 100.
func applyMultiplier(baseScore int, multiplier float64) int {
	result := int(math.Round(float64(baseScore) * multiplier))
	if result > 100 {
		return 100
	}
	return result
}

// postureDetail returns a human-readable description of the worst posture
// flags when the multiplier is greater than 1.0.
func postureDetail(postures []discovery.PodPosture) string {
	if len(postures) == 0 {
		return ""
	}

	// Find the worst posture (same logic as CalculatePostureMultiplier).
	var worst discovery.PodPosture
	worstScore := 1.0
	for _, p := range postures {
		m := 1.0
		if p.Privileged {
			m += 0.20
		}
		if p.HostPID {
			m += 0.10
		}
		if p.HostNetwork {
			m += 0.05
		}
		if p.HostIPC {
			m += 0.05
		}
		if p.HostPath {
			m += 0.05
		}
		if p.RunAsRoot {
			m += 0.05
		}
		if p.PodName != "" && !p.HasEgressRestriction {
			m += 0.10
		}
		if m > worstScore {
			worstScore = m
			worst = p
		}
	}

	if worstScore <= 1.0 {
		return ""
	}

	flags := make([]string, 0, 7)
	if worst.Privileged {
		flags = append(flags, "privileged")
	}
	if worst.HostPID {
		flags = append(flags, "hostPID")
	}
	if worst.HostNetwork {
		flags = append(flags, "hostNetwork")
	}
	if worst.HostIPC {
		flags = append(flags, "hostIPC")
	}
	if worst.HostPath {
		flags = append(flags, "hostPath")
	}
	if worst.RunAsRoot {
		flags = append(flags, "runAsRoot")
	}
	if worst.PodName != "" && !worst.HasEgressRestriction {
		flags = append(flags, "noEgressRestriction")
	}

	podRef := worst.PodName
	if worst.Namespace != "" {
		podRef = worst.Namespace + "/" + worst.PodName
	}

	return fmt.Sprintf("Worst pod %s: %s (x%.2f)", podRef, strings.Join(flags, ", "), worstScore)
}
