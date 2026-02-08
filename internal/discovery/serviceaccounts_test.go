package discovery

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDiscoverServiceAccounts_Empty(t *testing.T) {
	client := fake.NewSimpleClientset()

	nhis, err := DiscoverServiceAccounts(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nhis) != 0 {
		t.Errorf("expected 0 NHIs, got %d", len(nhis))
	}
}

func TestDiscoverServiceAccounts_MultipleNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "default",
				Namespace: "kube-system",
			},
		},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "traefik",
				Namespace: "kube-system",
				Labels: map[string]string{
					"helm.sh/chart": "traefik-25.0.0",
				},
			},
		},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "app-backend",
				Namespace: "production",
			},
			AutomountServiceAccountToken: boolPtr(false),
		},
	)

	nhis, err := DiscoverServiceAccounts(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nhis) != 3 {
		t.Fatalf("expected 3 NHIs, got %d", len(nhis))
	}

	for _, nhi := range nhis {
		if nhi.Type != NHITypeServiceAccount {
			t.Errorf("expected type %q, got %q", NHITypeServiceAccount, nhi.Type)
		}
		if nhi.ID == "" {
			t.Error("expected non-empty ID")
		}
	}
}

func TestDiscoverServiceAccounts_ByNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "sa-a", Namespace: "target-ns"},
		},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "sa-b", Namespace: "other-ns"},
		},
	)

	nhis, err := DiscoverServiceAccounts(context.Background(), client, "target-ns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nhis) != 1 {
		t.Fatalf("expected 1 NHI, got %d", len(nhis))
	}
	if nhis[0].Name != "sa-a" {
		t.Errorf("expected sa-a, got %s", nhis[0].Name)
	}
}

func TestServiceAccountToNHI_DefaultSA(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "production",
		},
	}

	nhi := serviceAccountToNHI(sa)

	if nhi.Metadata["is_default_sa"] != "true" {
		t.Error("expected default SA to be flagged")
	}
	if nhi.Metadata["automount_token"] != "default (true)" {
		t.Errorf("expected 'default (true)', got %q", nhi.Metadata["automount_token"])
	}
}

func TestServiceAccountToNHI_HelmSource(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "traefik",
			Namespace: "kube-system",
			Labels: map[string]string{
				"helm.sh/chart": "traefik-25.0.0",
			},
		},
	}

	nhi := serviceAccountToNHI(sa)

	if nhi.Source != "helm-chart:traefik-25.0.0" {
		t.Errorf("expected source 'helm-chart:traefik-25.0.0', got %q", nhi.Source)
	}
}

func TestServiceAccountToNHI_AutomountExplicit(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secure-sa",
			Namespace: "production",
		},
		AutomountServiceAccountToken: boolPtr(false),
		Secrets: []corev1.ObjectReference{
			{Name: "secret-1"},
			{Name: "secret-2"},
		},
	}

	nhi := serviceAccountToNHI(sa)

	if nhi.Metadata["automount_token"] != "false" {
		t.Errorf("expected 'false', got %q", nhi.Metadata["automount_token"])
	}
	if nhi.Metadata["secret_count"] != "2" {
		t.Errorf("expected '2', got %q", nhi.Metadata["secret_count"])
	}
}

func TestGenerateID_Deterministic(t *testing.T) {
	id1 := generateID(NHITypeServiceAccount, "default", "traefik")
	id2 := generateID(NHITypeServiceAccount, "default", "traefik")

	if id1 != id2 {
		t.Errorf("expected deterministic ID, got %q and %q", id1, id2)
	}

	id3 := generateID(NHITypeServiceAccount, "default", "coredns")
	if id1 == id3 {
		t.Error("different inputs produced same ID")
	}
}

func TestDiscoveryResult_CountByType(t *testing.T) {
	result := &DiscoveryResult{
		Identities: []NonHumanIdentity{
			{Type: NHITypeServiceAccount},
			{Type: NHITypeServiceAccount},
			{Type: NHITypeSecretCredential},
			{Type: NHITypeTLSCert},
		},
	}

	counts := result.CountByType()
	if counts[NHITypeServiceAccount] != 2 {
		t.Errorf("expected 2 SAs, got %d", counts[NHITypeServiceAccount])
	}
	if counts[NHITypeSecretCredential] != 1 {
		t.Errorf("expected 1 secret, got %d", counts[NHITypeSecretCredential])
	}
	if result.Total() != 4 {
		t.Errorf("expected total 4, got %d", result.Total())
	}
}

func TestFormatAge(t *testing.T) {
	tests := []struct {
		name     string
		d        time.Duration
		expected string
	}{
		{"years", time.Hour * 24 * 365 * 2, "2y"},
		{"months", time.Hour * 24 * 30 * 3, "3mo"},
		{"days", time.Hour * 24 * 15, "15d"},
		{"hours", time.Hour * 5, "5h"},
		{"minutes", time.Minute * 30, "30m"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatAge(tt.d)
			if got != tt.expected {
				t.Errorf("FormatAge(%v) = %q, want %q", tt.d, got, tt.expected)
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }
