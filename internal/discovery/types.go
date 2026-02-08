// Package discovery implements the detection and enumeration of
// Non-Human Identities (NHIs) across Kubernetes and OpenShift clusters.
//
// Phase 0: ServiceAccount enumeration (proof of concept).
// Phase 1 will add: Secrets with credentials, TLS certificates (cert-manager),
//
//	agent identities (Wazuh, Falco, Datadog), ZCloud device keys,
//	and cloud provider credentials.
package discovery

import "time"

// NHIType classifies the kind of Non-Human Identity.
type NHIType string

const (
	// NHITypeServiceAccount represents a Kubernetes ServiceAccount.
	NHITypeServiceAccount NHIType = "service-account"

	// NHITypeSecretCredential represents a Secret containing credentials
	// (API keys, tokens, passwords, registry creds).
	NHITypeSecretCredential NHIType = "secret-credential"

	// NHITypeTLSCert represents a TLS certificate identity
	// (cert-manager or native kubernetes.io/tls secrets).
	NHITypeTLSCert NHIType = "tls-cert"

	// NHITypeAgentIdentity represents an identity used by monitoring
	// or infrastructure agents (Wazuh, Falco, Datadog, ZCloud).
	NHITypeAgentIdentity NHIType = "agent-identity"

	// NHITypeCloudCredential represents cloud provider credentials
	// (AWS, OCI, Azure) stored in the cluster.
	NHITypeCloudCredential NHIType = "cloud-credential"
)

// NonHumanIdentity is the core model that represents any machine identity
// discovered in the cluster. This struct is defined in the project description
// and will be progressively enriched across phases.
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

	// Metadata holds type-specific details (secret count for SAs,
	// key names for secrets, issuer for certs, etc.).
	Metadata map[string]string `json:"metadata,omitempty"`

	// --- Populated in later phases ---
	// Permissions []Permission `json:"permissions,omitempty"` // Phase 2
	// RiskScore   RiskScore    `json:"risk_score,omitempty"`  // Phase 3
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
