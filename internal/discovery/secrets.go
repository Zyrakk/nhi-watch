// Package discovery implements the detection and enumeration of
// Non-Human Identities (NHIs) across Kubernetes and OpenShift clusters.
//
// Phase 0: ServiceAccount enumeration.
// Phase 1: Secrets with credentials, TLS certificates, cert-manager certificates,
//
//	SA tokens, and registry credentials.
package discovery

import "time"

// NHIType classifies the kind of Non-Human Identity.
type NHIType string

const (
	// NHITypeServiceAccount represents a Kubernetes ServiceAccount.
	NHITypeServiceAccount NHIType = "service-account"

	// NHITypeSecretCredential represents a Secret containing credentials
	// (API keys, tokens, passwords — Opaque secrets with credential-like keys).
	NHITypeSecretCredential NHIType = "secret-credential"

	// NHITypeTLSCert represents a TLS certificate identity
	// (kubernetes.io/tls secrets with parsed x509 metadata).
	NHITypeTLSCert NHIType = "tls-certificate"

	// NHITypeSAToken represents a legacy ServiceAccount token secret
	// (kubernetes.io/service-account-token, pre-1.24).
	NHITypeSAToken NHIType = "sa-token"

	// NHITypeRegistryCredential represents a Docker registry credential
	// (kubernetes.io/dockerconfigjson or kubernetes.io/dockercfg).
	NHITypeRegistryCredential NHIType = "registry-credential"

	// NHITypeCertManagerCertificate represents a cert-manager Certificate resource.
	NHITypeCertManagerCertificate NHIType = "cert-manager-certificate"

	// NHITypeAgentIdentity represents an identity used by monitoring
	// or infrastructure agents (Wazuh, Falco, Datadog, ZCloud).
	NHITypeAgentIdentity NHIType = "agent-identity"

	// NHITypeCloudCredential represents cloud provider credentials
	// (AWS, OCI, Azure) stored in the cluster.
	NHITypeCloudCredential NHIType = "cloud-credential"
)

// AllNHITypes returns all discoverable NHI types (for --type flag validation).
func AllNHITypes() []NHIType {
	return []NHIType{
		NHITypeServiceAccount,
		NHITypeSecretCredential,
		NHITypeTLSCert,
		NHITypeSAToken,
		NHITypeRegistryCredential,
		NHITypeCertManagerCertificate,
	}
}

// NonHumanIdentity is the core model that represents any machine identity
// discovered in the cluster.
type NonHumanIdentity struct {
	// ID is a unique identifier (hash of type + namespace + name).
	ID string `json:"id"`

	// Type classifies this NHI.
	Type NHIType `json:"type"`

	// Name is the Kubernetes object name.
	Name string `json:"name"`

	// Namespace where this NHI lives.
	Namespace string `json:"namespace"`

	// CreatedAt is when the identity was created in the cluster.
	CreatedAt time.Time `json:"created_at"`

	// LastRotated indicates when the credential was last rotated (if applicable).
	// Zero value means rotation status is unknown or not applicable.
	LastRotated time.Time `json:"last_rotated,omitempty"`

	// ExpiresAt indicates expiration (for certs, tokens). Zero = no expiry.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Source describes the origin: "helm-chart:traefik", "manual",
	// "operator:cert-manager", etc.
	Source string `json:"source,omitempty"`

	// Stale indicates the credential has not been modified in more than 90 days.
	Stale bool `json:"stale,omitempty"`

	// SecretType holds the Kubernetes secret .type field (for secret-based NHIs).
	SecretType string `json:"secret_type,omitempty"`

	// Keys lists the data keys present in a Secret (NEVER the values).
	Keys []string `json:"keys,omitempty"`

	// Issuer is the certificate issuer (for cert-manager certificates).
	Issuer string `json:"issuer,omitempty"`

	// DNSNames lists the SAN DNS names (for TLS certs and cert-manager certificates).
	DNSNames []string `json:"dns_names,omitempty"`

	// Metadata holds type-specific details (secret count for SAs,
	// key names for secrets, issuer for certs, etc.).
	Metadata map[string]string `json:"metadata,omitempty"`

	// --- Populated in later phases ---
	// Permissions []Permission `json:"permissions,omitempty"` // Phase 2
	// RiskScore   RiskScore    `json:"risk_score,omitempty"`  // Phase 3
}

// IsStale returns true if the NHI was created more than 90 days ago
// and has not been rotated since.
func (n *NonHumanIdentity) IsStale() bool {
	return n.Stale
}

// DiscoveryResult groups everything returned by a single discovery run.
type DiscoveryResult struct {
	// ClusterName from the kubeconfig context.
	ClusterName string `json:"cluster_name"`

	// Timestamp of the scan.
	Timestamp time.Time `json:"timestamp"`

	// Identities is the full list of discovered NHIs.
	Identities []NonHumanIdentity `json:"identities"`
}

// CountByType returns a summary map of NHI type → count.
func (r *DiscoveryResult) CountByType() map[NHIType]int {
	counts := make(map[NHIType]int)
	for _, nhi := range r.Identities {
		counts[nhi.Type]++
	}
	return counts
}

// Total returns the total number of NHIs discovered.
func (r *DiscoveryResult) Total() int {
	return len(r.Identities)
}

// staleDays is the number of days after which a credential is considered stale.
const staleDays = 90