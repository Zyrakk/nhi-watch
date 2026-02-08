package discovery

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// credentialKeyPatterns are substrings that indicate a Secret key likely
// contains a credential. We inspect key names only, NEVER values.
var credentialKeyPatterns = []string{
	"password",
	"passwd",
	"api-key",
	"api_key",
	"apikey",
	"token",
	"secret",
	"credential",
	"aws_access_key",
	"aws_secret_access_key",
	"connection-string",
	"connection_string",
	"connectionstring",
	"client_secret",
	"client-secret",
	"oauth",
	"private-key",
	"private_key",
	"privatekey",
	"access-key",
	"access_key",
	"secret-key",
	"secret_key",
}

// DiscoverSecrets enumerates Kubernetes Secrets and classifies them into
// NHI types: sa-token, tls-certificate, secret-credential, registry-credential.
func DiscoverSecrets(ctx context.Context, client kubernetes.Interface, namespace string) ([]NonHumanIdentity, error) {
	secretList, err := client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing secrets: %w", err)
	}

	nhis := make([]NonHumanIdentity, 0)
	for i := range secretList.Items {
		secret := &secretList.Items[i]
		nhi, ok := secretToNHI(secret)
		if ok {
			nhis = append(nhis, nhi)
		}
	}

	return nhis, nil
}

// secretToNHI converts a Kubernetes Secret to a NonHumanIdentity if it
// represents a credential. Returns (nhi, true) if the secret is relevant,
// or (zero, false) if it should be skipped.
func secretToNHI(secret *corev1.Secret) (NonHumanIdentity, bool) {
	switch secret.Type {
	case corev1.SecretTypeServiceAccountToken:
		return saTokenSecretToNHI(secret), true

	case corev1.SecretTypeTLS:
		return tlsSecretToNHI(secret), true

	case corev1.SecretTypeDockerConfigJson, corev1.SecretTypeDockercfg:
		return registrySecretToNHI(secret), true

	case corev1.SecretTypeOpaque:
		if matchingKeys := findCredentialKeys(secret); len(matchingKeys) > 0 {
			return opaqueSecretToNHI(secret, matchingKeys), true
		}
		return NonHumanIdentity{}, false

	default:
		// Skip unknown secret types (e.g., bootstrap tokens, etc.)
		return NonHumanIdentity{}, false
	}
}

// saTokenSecretToNHI converts a legacy SA token secret.
func saTokenSecretToNHI(secret *corev1.Secret) NonHumanIdentity {
	nhi := baseSecretNHI(secret, NHITypeSAToken)
	nhi.SecretType = string(secret.Type)
	nhi.Keys = secretKeys(secret)

	// Link to the owning ServiceAccount if annotated.
	if saName, ok := secret.Annotations["kubernetes.io/service-account.name"]; ok {
		nhi.Metadata["service_account"] = saName
	}

	return nhi
}

// tlsSecretToNHI converts a TLS secret, parsing the certificate for metadata.
func tlsSecretToNHI(secret *corev1.Secret) NonHumanIdentity {
	nhi := baseSecretNHI(secret, NHITypeTLSCert)
	nhi.SecretType = string(secret.Type)
	nhi.Keys = secretKeys(secret)

	// Attempt to parse the TLS certificate for expiration and SANs.
	if certData, ok := secret.Data["tls.crt"]; ok {
		if cert, err := parseCertificate(certData); err == nil {
			nhi.ExpiresAt = cert.NotAfter
			nhi.DNSNames = cert.DNSNames
			nhi.Metadata["subject"] = cert.Subject.CommonName
			nhi.Metadata["issuer"] = cert.Issuer.CommonName
			nhi.Metadata["not_before"] = cert.NotBefore.Format(time.RFC3339)
			nhi.Metadata["not_after"] = cert.NotAfter.Format(time.RFC3339)

			// Flag if expiring within 30 days.
			if time.Until(cert.NotAfter) < 30*24*time.Hour {
				nhi.Metadata["expiring_soon"] = "true"
			}
			// Flag if already expired.
			if time.Now().After(cert.NotAfter) {
				nhi.Metadata["expired"] = "true"
			}
		} else {
			nhi.Metadata["tls_parse_error"] = err.Error()
		}
	}

	return nhi
}

// registrySecretToNHI converts a Docker registry credential secret.
func registrySecretToNHI(secret *corev1.Secret) NonHumanIdentity {
	nhi := baseSecretNHI(secret, NHITypeRegistryCredential)
	nhi.SecretType = string(secret.Type)
	nhi.Keys = secretKeys(secret)
	return nhi
}

// opaqueSecretToNHI converts an Opaque secret that has credential-like keys.
func opaqueSecretToNHI(secret *corev1.Secret, matchingKeys []string) NonHumanIdentity {
	nhi := baseSecretNHI(secret, NHITypeSecretCredential)
	nhi.SecretType = string(secret.Type)
	nhi.Keys = secretKeys(secret)
	nhi.Metadata["credential_keys"] = strings.Join(matchingKeys, ", ")
	return nhi
}

// baseSecretNHI creates a NonHumanIdentity with the common fields for any secret type.
func baseSecretNHI(secret *corev1.Secret, nhiType NHIType) NonHumanIdentity {
	created := secret.CreationTimestamp.Time
	stale := time.Since(created) > time.Duration(staleDays)*24*time.Hour

	nhi := NonHumanIdentity{
		ID:        generateID(nhiType, secret.Namespace, secret.Name),
		Type:      nhiType,
		Name:      secret.Name,
		Namespace: secret.Namespace,
		CreatedAt: created,
		Stale:     stale,
		Source:    detectSecretSource(secret),
		Metadata:  make(map[string]string),
	}

	if stale {
		nhi.Metadata["stale"] = "true"
		nhi.Metadata["age_days"] = fmt.Sprintf("%d", int(time.Since(created).Hours()/24))
	}

	return nhi
}

// detectSecretSource attempts to determine the origin of a Secret.
func detectSecretSource(secret *corev1.Secret) string {
	// Helm managed.
	if chart, ok := secret.Labels["helm.sh/chart"]; ok {
		return "helm-chart:" + chart
	}
	if managedBy, ok := secret.Labels["app.kubernetes.io/managed-by"]; ok {
		if name, ok2 := secret.Labels["app.kubernetes.io/name"]; ok2 {
			return managedBy + ":" + name
		}
		return managedBy
	}

	// cert-manager managed TLS secrets.
	if _, ok := secret.Annotations["cert-manager.io/certificate-name"]; ok {
		certName := secret.Annotations["cert-manager.io/certificate-name"]
		return "cert-manager:" + certName
	}

	// ArgoCD / Flux.
	if _, ok := secret.Labels["argocd.argoproj.io/instance"]; ok {
		return "argocd"
	}
	if _, ok := secret.Labels["kustomize.toolkit.fluxcd.io/name"]; ok {
		return "flux"
	}

	// SA token secrets reference their SA.
	if _, ok := secret.Annotations["kubernetes.io/service-account.name"]; ok {
		return "kubernetes"
	}

	return "unknown"
}

// findCredentialKeys inspects the key names (not values) of an Opaque secret
// and returns those that match credential patterns.
func findCredentialKeys(secret *corev1.Secret) []string {
	var matches []string
	for key := range secret.Data {
		if IsCredentialKey(key) {
			matches = append(matches, key)
		}
	}
	return matches
}

// IsCredentialKey returns true if the given key name matches a credential pattern.
// Exported for testing.
func IsCredentialKey(key string) bool {
	lower := strings.ToLower(key)
	for _, pattern := range credentialKeyPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// secretKeys returns the list of data key names in a Secret (never values).
func secretKeys(secret *corev1.Secret) []string {
	keys := make([]string, 0, len(secret.Data))
	for k := range secret.Data {
		keys = append(keys, k)
	}
	return keys
}

// parseCertificate decodes a PEM-encoded certificate and returns the first
// valid x509 certificate found. Returns an error if parsing fails.
func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		// Try DER directly if PEM decode fails.
		cert, err := x509.ParseCertificate(certPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode certificate: neither PEM nor DER")
		}
		return cert, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing x509 certificate: %w", err)
	}

	return cert, nil
}