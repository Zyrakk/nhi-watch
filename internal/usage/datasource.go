package usage

import "context"

// UsageDataSource is the pluggable interface that all usage data providers
// must implement. Concrete implementations include:
//   - v2.0: Kubernetes audit webhook receiver
//   - v3.0: Wazuh log ingestion
//   - v3.0: Falco event stream
type UsageDataSource interface {
	// GetProfile returns the usage profile for a specific service account.
	// Returns nil and no error if the service account has no recorded data.
	GetProfile(ctx context.Context, namespace, serviceAccount string) (*UsageProfile, error)

	// ListProfiles returns all known usage profiles.
	ListProfiles(ctx context.Context) ([]UsageProfile, error)

	// IsAvailable reports whether this data source is reachable and ready.
	IsAvailable(ctx context.Context) bool
}
