package discovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// --- Credential key pattern matching tests ---

func TestIsCredentialKey(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		// Positive matches.
		{"password", true},
		{"db-password", true},
		{"DB_PASSWORD", true},
		{"api-key", true},
		{"api_key", true},
		{"APIKEY", true},
		{"auth-token", true},
		{"TOKEN", true},
		{"client_secret", true},
		{"CLIENT-SECRET", true},
		{"aws_access_key", true},
		{"aws_secret_access_key", true},
		{"connection-string", true},
		{"connection_string", true},
		{"oauth-token", true},
		{"private-key", true},
		{"private_key", true},
		{"secret-key", true},
		{"credential", true},
		{"my-credential-file", true},
		{"PASSWD", true},

		// Negative matches (should NOT match).
		{"config", false},
		{"data", false},
		{"hostname", false},
		{"port", false},
		{"ca.crt", false},
		{"tls.crt", false},
		{"tls.key", false}, // tls.key doesn't match our patterns (intentional)
		{"namespace", false},
		{"username", false},
		{"email", false},
		{"readme", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := IsCredentialKey(tt.key)
			if got != tt.expected {
				t.Errorf("IsCredentialKey(%q) = %v, want %v", tt.key, got, tt.expected)
			}
		})
	}
}

// --- x509 certificate parsing tests ---

func TestParseCertificate_Valid(t *testing.T) {
	certPEM := generateTestCert(t, "test.example.com", []string{"test.example.com", "*.example.com"}, time.Now(), time.Now().Add(365*24*time.Hour))

	cert, err := parseCertificate(certPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("expected CN 'test.example.com', got %q", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(cert.DNSNames))
	}
}

func TestParseCertificate_Expired(t *testing.T) {
	certPEM := generateTestCert(t, "expired.example.com", nil, time.Now().Add(-2*365*24*time.Hour), time.Now().Add(-365*24*time.Hour))

	cert, err := parseCertificate(certPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if time.Now().Before(cert.NotAfter) {
		t.Error("expected certificate to be expired")
	}
}

func TestParseCertificate_InvalidData(t *testing.T) {
	_, err := parseCertificate([]byte("not-a-certificate"))
	if err == nil {
		t.Error("expected error for invalid certificate data")
	}
}

// --- Secret → NHI conversion tests ---

func TestSecretToNHI_SAToken(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-sa-token-xxxx",
			Namespace: "default",
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": "my-sa",
			},
		},
		Type: corev1.SecretTypeServiceAccountToken,
		Data: map[string][]byte{
			"token":     []byte("fake-token"),
			"ca.crt":    []byte("fake-ca"),
			"namespace": []byte("default"),
		},
	}

	nhi, ok := secretToNHI(secret)
	if !ok {
		t.Fatal("expected SA token secret to be relevant")
	}
	if nhi.Type != NHITypeSAToken {
		t.Errorf("expected type %q, got %q", NHITypeSAToken, nhi.Type)
	}
	if nhi.Metadata["service_account"] != "my-sa" {
		t.Errorf("expected SA 'my-sa', got %q", nhi.Metadata["service_account"])
	}
}

func TestSecretToNHI_TLSSecret(t *testing.T) {
	certPEM := generateTestCert(t, "web.example.com", []string{"web.example.com"}, time.Now(), time.Now().Add(365*24*time.Hour))

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-tls",
			Namespace: "production",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": []byte("fake-key"),
		},
	}

	nhi, ok := secretToNHI(secret)
	if !ok {
		t.Fatal("expected TLS secret to be relevant")
	}
	if nhi.Type != NHITypeTLSCert {
		t.Errorf("expected type %q, got %q", NHITypeTLSCert, nhi.Type)
	}
	if nhi.Metadata["subject"] != "web.example.com" {
		t.Errorf("expected subject 'web.example.com', got %q", nhi.Metadata["subject"])
	}
	if len(nhi.DNSNames) != 1 {
		t.Errorf("expected 1 DNS name, got %d", len(nhi.DNSNames))
	}
	if nhi.ExpiresAt.IsZero() {
		t.Error("expected non-zero ExpiresAt")
	}
}

func TestSecretToNHI_TLSSecret_InvalidCert(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bad-tls",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte("invalid-cert-data"),
			"tls.key": []byte("fake-key"),
		},
	}

	nhi, ok := secretToNHI(secret)
	if !ok {
		t.Fatal("expected TLS secret to still be relevant even with bad cert")
	}
	if nhi.Metadata["tls_parse_error"] == "" {
		t.Error("expected tls_parse_error in metadata")
	}
}

func TestSecretToNHI_RegistryCredential(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "registry-cred",
			Namespace: "ci",
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			".dockerconfigjson": []byte(`{"auths":{}}`),
		},
	}

	nhi, ok := secretToNHI(secret)
	if !ok {
		t.Fatal("expected registry secret to be relevant")
	}
	if nhi.Type != NHITypeRegistryCredential {
		t.Errorf("expected type %q, got %q", NHITypeRegistryCredential, nhi.Type)
	}
}

func TestSecretToNHI_OpaqueWithCredentials(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-config",
			Namespace: "production",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"db-password": []byte("secret"),
			"api-key":     []byte("key"),
			"hostname":    []byte("db.local"),
		},
	}

	nhi, ok := secretToNHI(secret)
	if !ok {
		t.Fatal("expected opaque secret with credentials to be relevant")
	}
	if nhi.Type != NHITypeSecretCredential {
		t.Errorf("expected type %q, got %q", NHITypeSecretCredential, nhi.Type)
	}
	if nhi.Metadata["credential_keys"] == "" {
		t.Error("expected credential_keys in metadata")
	}
}

func TestSecretToNHI_OpaqueNoCredentials(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-config",
			Namespace: "production",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"config.yaml": []byte("key: value"),
			"hostname":    []byte("db.local"),
		},
	}

	_, ok := secretToNHI(secret)
	if ok {
		t.Error("expected opaque secret without credentials to be skipped")
	}
}

func TestSecretToNHI_Stale(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "old-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-120 * 24 * time.Hour)),
		},
		Type: corev1.SecretTypeServiceAccountToken,
		Data: map[string][]byte{"token": []byte("x")},
	}

	nhi, ok := secretToNHI(secret)
	if !ok {
		t.Fatal("expected secret to be relevant")
	}
	if !nhi.Stale {
		t.Error("expected secret older than 90 days to be stale")
	}
}

func TestSecretToNHI_NotStale(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "fresh-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * 24 * time.Hour)),
		},
		Type: corev1.SecretTypeServiceAccountToken,
		Data: map[string][]byte{"token": []byte("x")},
	}

	nhi, ok := secretToNHI(secret)
	if !ok {
		t.Fatal("expected secret to be relevant")
	}
	if nhi.Stale {
		t.Error("expected recent secret to not be stale")
	}
}

// --- Integration: DiscoverSecrets with fake client ---

func TestDiscoverSecrets_Mixed(t *testing.T) {
	certPEM := generateTestCert(t, "test.local", nil, time.Now(), time.Now().Add(365*24*time.Hour))

	client := fake.NewSimpleClientset(
		// SA token — should be discovered.
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "sa-token-1", Namespace: "default"},
			Type:       corev1.SecretTypeServiceAccountToken,
			Data:       map[string][]byte{"token": []byte("x")},
		},
		// TLS — should be discovered.
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-1", Namespace: "default"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": certPEM, "tls.key": []byte("k")},
		},
		// Opaque with credential key — should be discovered.
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "app-secret", Namespace: "default"},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{"password": []byte("x")},
		},
		// Opaque without credential key — should be skipped.
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "config-map-like", Namespace: "default"},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{"config.yaml": []byte("x")},
		},
		// Registry — should be discovered.
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "registry-1", Namespace: "ci"},
			Type:       corev1.SecretTypeDockerConfigJson,
			Data:       map[string][]byte{".dockerconfigjson": []byte("{}")},
		},
	)

	nhis, err := DiscoverSecrets(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expect 4: sa-token, tls, opaque-credential, registry. NOT config-map-like.
	if len(nhis) != 4 {
		t.Errorf("expected 4 NHIs, got %d", len(nhis))
		for _, n := range nhis {
			t.Logf("  %s/%s (%s)", n.Namespace, n.Name, n.Type)
		}
	}
}

func TestDiscoverSecrets_ByNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "target"},
			Type:       corev1.SecretTypeServiceAccountToken,
			Data:       map[string][]byte{"token": []byte("x")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "s2", Namespace: "other"},
			Type:       corev1.SecretTypeServiceAccountToken,
			Data:       map[string][]byte{"token": []byte("x")},
		},
	)

	nhis, err := DiscoverSecrets(context.Background(), client, "target")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nhis) != 1 {
		t.Errorf("expected 1 NHI, got %d", len(nhis))
	}
}

// --- Helpers ---

// generateTestCert creates a self-signed PEM certificate for testing.
func generateTestCert(t *testing.T, cn string, dnsNames []string, notBefore, notAfter time.Time) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}