package remediation

import (
	"strings"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
)

// GenerateYAML returns a remediation YAML proposal. When usage data is
// available, it generates precise least-privilege RBAC from observed API
// calls. Otherwise it falls back to heuristic templates for known workloads.
// Returns empty string for unknown workloads without usage data.
func GenerateYAML(nhi *discovery.NonHumanIdentity) (string, error) {
	// Try usage-based first — precise RBAC from observed API calls
	if nhi.UsageProfile != nil && len(nhi.UsageProfile.Records) > 0 {
		return renderFromUsage(nhi)
	}

	// Fall back to heuristic template
	tmpl := matchTemplate(nhi)
	if tmpl == nil {
		return "", nil
	}
	return tmpl.render(nhi)
}

type workloadTemplate struct {
	name    string
	matcher func(nhi *discovery.NonHumanIdentity) bool
	render  func(nhi *discovery.NonHumanIdentity) (string, error)
}

func matchTemplate(nhi *discovery.NonHumanIdentity) *workloadTemplate {
	for i := range knownTemplates {
		if knownTemplates[i].matcher(nhi) {
			return &knownTemplates[i]
		}
	}
	return nil
}

// isTraefik checks if the NHI is a Traefik workload.
func isTraefik(nhi *discovery.NonHumanIdentity) bool {
	if strings.Contains(strings.ToLower(nhi.Name), "traefik") {
		return true
	}
	return strings.Contains(strings.ToLower(nhi.Source), "traefik")
}

// isCertManager checks if the NHI is a cert-manager workload.
func isCertManager(nhi *discovery.NonHumanIdentity) bool {
	if strings.Contains(strings.ToLower(nhi.Name), "cert-manager") {
		return true
	}
	return strings.Contains(strings.ToLower(nhi.Source), "cert-manager")
}
