package usage

import (
	"strings"
	"testing"
)

func TestGenerateAuditPolicy_ValidYAML(t *testing.T) {
	policy := GenerateAuditPolicy()

	required := []string{
		"audit.k8s.io/v1",
		"kind: Policy",
		"system:serviceaccounts",
		"system:kube-proxy",
		"level: Metadata",
	}
	for _, s := range required {
		if !strings.Contains(policy, s) {
			t.Errorf("audit policy missing required string %q", s)
		}
	}
}

func TestGenerateAuditPolicy_ExcludesWatch(t *testing.T) {
	policy := GenerateAuditPolicy()

	if !strings.Contains(policy, `- "watch"`) {
		t.Error("audit policy should exclude watch verb")
	}
}

func TestGenerateAuditPolicyForWebhook(t *testing.T) {
	url := "https://nhi-watch.monitoring.svc:8443"
	config := GenerateAuditPolicyForWebhook(url)

	if !strings.Contains(config, url+"/webhook/audit") {
		t.Errorf("webhook config should contain %s/webhook/audit", url)
	}
	if !strings.Contains(config, "apiVersion: v1") {
		t.Error("webhook config should contain apiVersion: v1")
	}
	if !strings.Contains(config, "kind: Config") {
		t.Error("webhook config should contain kind: Config")
	}
	if !strings.Contains(config, "current-context: nhi-watch") {
		t.Error("webhook config should contain current-context: nhi-watch")
	}
}
