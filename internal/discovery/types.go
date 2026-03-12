// Package discovery implements the detection and enumeration of
// Non-Human Identities (NHIs) across Kubernetes and OpenShift clusters.
//
// Phase 0: ServiceAccount enumeration (proof of concept).
// Phase 1: Full NHI discovery (Secrets, certs, agents, cloud creds).
// Phase 2: RBAC permission resolution integrated into discovery results.
package discovery

import (
	"time"

	"github.com/Zyrakk/nhi-watch/internal/models"
)

// staleDays is the threshold (in days) after which a credential is
// considered stale and should be flagged for rotation.
const staleDays = 90

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

	// NHITypeSAToken represents a legacy ServiceAccount token Secret
	// (kubernetes.io/service-account-token).
	NHITypeSAToken NHIType = "sa-token"

	// NHITypeRegistryCredential represents a Docker registry credential
	// Secret (kubernetes.io/dockerconfigjson or kubernetes.io/dockercfg).
	NHITypeRegistryCredential NHIType = "registry-credential"

	// NHITypeCertManagerCertificate represents a cert-manager Certificate
	// resource (cert-manager.io/v1 Certificate CRD).
	NHITypeCertManagerCertificate NHIType = "cert-manager-certificate"

	// NHITypeAgentIdentity represents an identity used by monitoring
	// or infrastructure agents (Wazuh, Falco, Datadog, ZCloud).
	NHITypeAgentIdentity NHIType = "agent-identity"

	// NHITypeCloudCredential represents cloud provider credentials
	// (AWS, OCI, Azure) stored in the cluster.
	NHITypeCloudCredential NHIType = "cloud-credential"
)

// PodPosture captures the security-relevant configuration of a pod that
// references a specific ServiceAccount. Used to assess workload risk.
type PodPosture struct {
	PodName              string `json:"pod_name"`
	Namespace            string `json:"namespace"`
	Privileged           bool   `json:"privileged"`
	RunAsRoot            bool   `json:"run_as_root"`
	HostNetwork          bool   `json:"host_network"`
	HostPID              bool   `json:"host_pid"`
	HostIPC              bool   `json:"host_ipc"`
	HostPath             bool   `json:"host_path"`
	SCCName              string `json:"scc_name,omitempty"`               // OpenShift SecurityContextConstraint
	HasEgressRestriction bool   `json:"has_egress_restriction,omitempty"` // NetworkPolicy restricts egress
}

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

	// --- Phase 1 fields ---

	// SecretType is the Kubernetes secret type (e.g. "kubernetes.io/tls",
	// "Opaque"). Only populated for secret-based NHIs.
	SecretType string `json:"secret_type,omitempty"`

	// Keys lists the data key names present in the Secret (never values).
	Keys []string `json:"keys,omitempty"`

	// DNSNames contains the Subject Alternative Names from TLS certificates.
	DNSNames []string `json:"dns_names,omitempty"`

	// Issuer identifies the certificate issuer (e.g. "Issuer:letsencrypt-prod").
	// Populated for cert-manager Certificate NHIs.
	Issuer string `json:"issuer,omitempty"`

	// Stale indicates the credential has not been rotated in more than
	// staleDays (90 days).
	Stale bool `json:"stale,omitempty"`

	// --- Phase 2 fields ---

	// Permissions holds the resolved RBAC permission set (Phase 2).
	// Only populated for NHIs of type "service-account".
	Permissions *models.PermissionSet `json:"permissions,omitempty"`

	// AccessibleBy lists ServiceAccounts (as "namespace/name") that can
	// read this NHI's secrets. Only populated for secret-type NHIs
	// (secret-credential, tls-cert) during Phase 2 permission resolution.
	AccessibleBy []string `json:"accessible_by,omitempty"`

	// PodPostures holds the security posture of pods that reference this
	// ServiceAccount. Only populated for NHIs of type "service-account".
	PodPostures []PodPosture `json:"pod_postures,omitempty"`

	// --- Populated in later phases ---
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

// AllNHITypes returns every known NHI type. Used for CLI flag validation
// and help text generation.
func AllNHITypes() []NHIType {
	return []NHIType{
		NHITypeServiceAccount,
		NHITypeSecretCredential,
		NHITypeTLSCert,
		NHITypeSAToken,
		NHITypeRegistryCredential,
		NHITypeCertManagerCertificate,
		NHITypeAgentIdentity,
		NHITypeCloudCredential,
	}
}
