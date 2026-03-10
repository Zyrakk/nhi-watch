// Package k8s provides a shared Kubernetes client configuration
// that works against k3s, vanilla Kubernetes, and OpenShift clusters.
package k8s

import (
	"fmt"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ClientOpts holds the options needed to build a Kubernetes client.
type ClientOpts struct {
	// Kubeconfig is the explicit path to a kubeconfig file (--kubeconfig flag).
	// If empty, the standard resolution order is used:
	//   1. In-cluster config
	//   2. $KUBECONFIG environment variable (supports multiple paths)
	//   3. ~/.kube/config
	Kubeconfig string

	// Context overrides the current-context in the kubeconfig.
	Context string
}

// Clients bundles all client types needed by NHI-Watch.
type Clients struct {
	// Clientset is the typed Kubernetes client for core resources.
	Clientset kubernetes.Interface

	// Dynamic is the untyped client for CRD resources (cert-manager, etc.).
	Dynamic dynamic.Interface

	// Discovery is used to check if CRDs/APIs exist before querying them.
	Discovery discovery.DiscoveryInterface
}

// IsOpenShift checks if the cluster is OpenShift by looking for the
// security.openshift.io API group.
func (c *Clients) IsOpenShift() bool {
	groups, err := c.Discovery.ServerGroups()
	if err != nil {
		return false
	}
	for _, g := range groups.Groups {
		if g.Name == "security.openshift.io" {
			return true
		}
	}
	return false
}

// NewClient returns a *kubernetes.Clientset configured from the given options.
// It supports in-cluster, explicit kubeconfig, $KUBECONFIG, and the default
// ~/.kube/config path, which makes it compatible with k3s, OpenShift, and
// any standard cluster.
func NewClient(opts ClientOpts) (*kubernetes.Clientset, error) {
	cfg, err := buildConfig(opts)
	if err != nil {
		return nil, fmt.Errorf("building kubernetes config: %w", err)
	}

	cfg.UserAgent = "nhi-watch/0.1"

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes clientset: %w", err)
	}

	return cs, nil
}

// NewClients returns all client types needed by NHI-Watch (typed, dynamic, discovery).
func NewClients(opts ClientOpts) (*Clients, error) {
	cfg, err := buildConfig(opts)
	if err != nil {
		return nil, fmt.Errorf("building kubernetes config: %w", err)
	}

	cfg.UserAgent = "nhi-watch/0.1"

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes clientset: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating dynamic client: %w", err)
	}

	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating discovery client: %w", err)
	}

	return &Clients{
		Clientset: cs,
		Dynamic:   dynClient,
		Discovery: dc,
	}, nil
}

// ClusterName extracts the current context name from the kubeconfig,
// which serves as a human-friendly cluster identifier in reports.
func ClusterName(opts ClientOpts) string {
	if opts.Context != "" {
		return opts.Context
	}

	loadingRules := loadingRulesFor(opts.Kubeconfig)
	overrides := &clientcmd.ConfigOverrides{}

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, overrides,
	).RawConfig()
	if err != nil {
		return "unknown"
	}

	return cfg.CurrentContext
}

// buildConfig resolves the rest.Config using the following priority:
//  1. In-cluster (when running inside a pod as a CronJob/controller)
//  2. --kubeconfig flag (explicit path)
//  3. $KUBECONFIG environment variable (handled by clientcmd defaults)
//  4. ~/.kube/config
func buildConfig(opts ClientOpts) (*rest.Config, error) {
	// Try in-cluster first — enables running NHI-Watch as a CronJob / Pod.
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}

	loadingRules := loadingRulesFor(opts.Kubeconfig)
	overrides := &clientcmd.ConfigOverrides{}

	if opts.Context != "" {
		overrides.CurrentContext = opts.Context
	}

	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, overrides,
	).ClientConfig()
}

// loadingRulesFor returns the appropriate ClientConfigLoadingRules.
// When an explicit path is given (--kubeconfig), it uses that directly.
// Otherwise it uses NewDefaultClientConfigLoadingRules which respects
// the $KUBECONFIG env var and falls back to ~/.kube/config.
func loadingRulesFor(explicitPath string) *clientcmd.ClientConfigLoadingRules {
	if explicitPath != "" {
		return &clientcmd.ClientConfigLoadingRules{ExplicitPath: explicitPath}
	}
	return clientcmd.NewDefaultClientConfigLoadingRules()
}
