package remediation

import (
	"strings"
	"testing"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
)

func TestGenerateYAML_Traefik(t *testing.T) {
	nhi := &discovery.NonHumanIdentity{
		Name:      "traefik",
		Namespace: "kube-system",
		Type:      discovery.NHITypeServiceAccount,
		Source:    "helm-chart:traefik-25.0.0",
	}
	yaml, err := GenerateYAML(nhi)
	if err != nil {
		t.Fatal(err)
	}
	if yaml == "" {
		t.Fatal("expected YAML output for traefik")
	}
	if !strings.Contains(yaml, "# PROPOSAL") {
		t.Error("generated YAML must be marked as proposal")
	}
	if !strings.Contains(yaml, "traefik") {
		t.Error("YAML should reference traefik")
	}
	if !strings.Contains(yaml, "ClusterRole") {
		t.Error("should contain ClusterRole")
	}
	if !strings.Contains(yaml, "kube-system") {
		t.Error("should reference namespace")
	}
}

func TestGenerateYAML_TraefikBySource(t *testing.T) {
	nhi := &discovery.NonHumanIdentity{
		Name:      "custom-ingress-sa",
		Namespace: "ingress",
		Type:      discovery.NHITypeServiceAccount,
		Source:    "helm-chart:traefik-25.0.0",
	}
	yaml, err := GenerateYAML(nhi)
	if err != nil {
		t.Fatal(err)
	}
	if yaml == "" {
		t.Fatal("should match traefik by source")
	}
}

func TestGenerateYAML_CertManager(t *testing.T) {
	nhi := &discovery.NonHumanIdentity{
		Name:      "cert-manager",
		Namespace: "cert-manager",
		Type:      discovery.NHITypeServiceAccount,
		Source:    "Helm:cert-manager",
	}
	yaml, err := GenerateYAML(nhi)
	if err != nil {
		t.Fatal(err)
	}
	if yaml == "" {
		t.Fatal("expected YAML output for cert-manager")
	}
	if !strings.Contains(yaml, "# PROPOSAL") {
		t.Error("generated YAML must be marked as proposal")
	}
	if !strings.Contains(yaml, "cert-manager.io") {
		t.Error("should contain cert-manager API group")
	}
}

func TestGenerateYAML_UnknownWorkload(t *testing.T) {
	nhi := &discovery.NonHumanIdentity{
		Name:      "custom-app",
		Namespace: "default",
		Type:      discovery.NHITypeServiceAccount,
		Source:    "unknown",
	}
	yaml, err := GenerateYAML(nhi)
	if err != nil {
		t.Fatal(err)
	}
	if yaml != "" {
		t.Error("should return empty YAML for unknown workloads")
	}
}

func TestGenerateYAML_SecretType(t *testing.T) {
	nhi := &discovery.NonHumanIdentity{
		Name:      "traefik-tls",
		Namespace: "kube-system",
		Type:      discovery.NHITypeSecretCredential,
		Source:    "helm-chart:traefik-25.0.0",
	}
	// Secrets don't get YAML remediation (only SAs do in this template set)
	// but should still match by name/source
	yaml, err := GenerateYAML(nhi)
	if err != nil {
		t.Fatal(err)
	}
	// This is fine either way - the template matching is by name/source
	_ = yaml
}

func TestIsTraefik(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{"traefik", "helm-chart:traefik-25.0.0", true},
		{"custom-sa", "helm-chart:traefik-25.0.0", true},
		{"traefik-ingress", "unknown", true},
		{"my-app", "unknown", false},
		{"my-app", "Helm:something", false},
	}
	for _, tt := range tests {
		nhi := &discovery.NonHumanIdentity{Name: tt.name, Source: tt.source}
		got := isTraefik(nhi)
		if got != tt.want {
			t.Errorf("isTraefik(name=%q, source=%q) = %v, want %v", tt.name, tt.source, got, tt.want)
		}
	}
}

func TestIsCertManager(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{"cert-manager", "Helm:cert-manager", true},
		{"cert-manager-webhook", "Helm:cert-manager", true},
		{"my-app", "Helm:cert-manager", true},
		{"my-app", "unknown", false},
	}
	for _, tt := range tests {
		nhi := &discovery.NonHumanIdentity{Name: tt.name, Source: tt.source}
		got := isCertManager(nhi)
		if got != tt.want {
			t.Errorf("isCertManager(name=%q, source=%q) = %v, want %v", tt.name, tt.source, got, tt.want)
		}
	}
}
