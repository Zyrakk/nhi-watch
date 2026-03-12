package discovery

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// DiscoverOpts holds the options for a full discovery run.
type DiscoverOpts struct {
	// Namespace restricts discovery to a single namespace ("" = all).
	Namespace string

	// TypeFilter restricts discovery to a specific NHI type ("" = all).
	TypeFilter NHIType

	// StaleOnly filters to only show stale NHIs (> 90 days).
	StaleOnly bool

	// Verbose enables additional logging via the LogFunc.
	Verbose bool

	// LogFunc is called for verbose log messages. If nil, verbose logs are skipped.
	LogFunc func(format string, args ...interface{})
}

func (o *DiscoverOpts) logf(format string, args ...interface{}) {
	if o.Verbose && o.LogFunc != nil {
		o.LogFunc(format, args...)
	}
}

// discoveryError holds an error from a specific discovery phase.
type discoveryError struct {
	phase string
	err   error
}

// DiscoverAll runs all NHI discovery phases in parallel and returns
// the merged, sorted result.
//
// It requires:
//   - client: typed Kubernetes clientset (for ServiceAccounts and Secrets)
//   - dc: discovery client (to check if cert-manager CRDs exist)
//   - dynClient: dynamic client (to list cert-manager Certificate resources)
//
// If dynClient or dc are nil, cert-manager discovery is silently skipped.
func DiscoverAll(ctx context.Context, client kubernetes.Interface, dc discovery.DiscoveryInterface, dynClient dynamic.Interface, opts DiscoverOpts) ([]NonHumanIdentity, []error) {
	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		allNHIs   []NonHumanIdentity
		allErrors []error
	)

	collect := func(nhis []NonHumanIdentity) {
		mu.Lock()
		allNHIs = append(allNHIs, nhis...)
		mu.Unlock()
	}

	collectErr := func(de discoveryError) {
		mu.Lock()
		allErrors = append(allErrors, fmt.Errorf("%s: %w", de.phase, de.err))
		mu.Unlock()
	}

	// Phase 0: ServiceAccounts (always run unless filtered out).
	if opts.TypeFilter == "" || opts.TypeFilter == NHITypeServiceAccount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			opts.logf("[*] Discovering ServiceAccounts...")
			nhis, err := DiscoverServiceAccounts(ctx, client, opts.Namespace)
			if err != nil {
				collectErr(discoveryError{phase: "service-accounts", err: err})
				return
			}
			opts.logf("[*] Found %d ServiceAccounts", len(nhis))
			collect(nhis)
		}()
	}

	// Phase 1a: Secrets (SA tokens, TLS certs, credentials, registry creds).
	secretTypes := []NHIType{NHITypeSecretCredential, NHITypeTLSCert, NHITypeSAToken, NHITypeRegistryCredential}
	runSecrets := opts.TypeFilter == ""
	if !runSecrets {
		for _, st := range secretTypes {
			if opts.TypeFilter == st {
				runSecrets = true
				break
			}
		}
	}

	if runSecrets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			opts.logf("[*] Discovering Secrets (credentials, TLS, tokens, registry)...")
			nhis, err := DiscoverSecrets(ctx, client, opts.Namespace)
			if err != nil {
				collectErr(discoveryError{phase: "secrets", err: err})
				return
			}
			opts.logf("[*] Found %d Secret-based NHIs", len(nhis))
			collect(nhis)
		}()
	}

	// Phase 1b: cert-manager Certificates (only if dynamic client available).
	if (opts.TypeFilter == "" || opts.TypeFilter == NHITypeCertManagerCertificate) && dc != nil && dynClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			opts.logf("[*] Checking for cert-manager...")
			nhis, err := DiscoverCertManagerCertificates(ctx, dc, dynClient, opts.Namespace)
			if err != nil {
				collectErr(discoveryError{phase: "cert-manager", err: err})
				return
			}
			if len(nhis) > 0 {
				opts.logf("[*] Found %d cert-manager Certificates", len(nhis))
			} else {
				opts.logf("[*] cert-manager not installed or no certificates found")
			}
			collect(nhis)
		}()
	}

	wg.Wait()

	// Enrich ServiceAccount NHIs with pod posture data.
	// This is non-fatal: if pod discovery fails, log a warning and continue.
	opts.logf("[*] Discovering pod postures...")
	postures, posErr := DiscoverPodPostures(ctx, client, opts.Namespace)
	if posErr != nil {
		opts.logf("[!] Warning: pod posture discovery failed: %v", posErr)
	} else {
		for i := range allNHIs {
			if allNHIs[i].Type == NHITypeServiceAccount {
				key := fmt.Sprintf("%s/%s", allNHIs[i].Namespace, allNHIs[i].Name)
				if p, ok := postures[key]; ok {
					allNHIs[i].PodPostures = p
				}
			}
		}
		opts.logf("[*] Pod posture enrichment complete")
	}

	// Enrich pod postures with NetworkPolicy egress restriction data.
	opts.logf("[*] Checking NetworkPolicy egress restrictions...")
	egressRestrictions, egressErr := DiscoverEgressRestrictions(ctx, client, opts.Namespace)
	if egressErr != nil {
		opts.logf("[!] Warning: NetworkPolicy discovery failed: %v", egressErr)
	} else {
		for i := range allNHIs {
			if allNHIs[i].Type != NHITypeServiceAccount {
				continue
			}
			key := fmt.Sprintf("%s/%s", allNHIs[i].Namespace, allNHIs[i].Name)
			if egressRestrictions[key] {
				for j := range allNHIs[i].PodPostures {
					allNHIs[i].PodPostures[j].HasEgressRestriction = true
				}
			}
		}
		opts.logf("[*] NetworkPolicy enrichment complete")
	}

	// Apply type filter for secret subtypes (DiscoverSecrets returns mixed types).
	if opts.TypeFilter != "" {
		filtered := make([]NonHumanIdentity, 0)
		for _, nhi := range allNHIs {
			if nhi.Type == opts.TypeFilter {
				filtered = append(filtered, nhi)
			}
		}
		allNHIs = filtered
	}

	// Apply stale filter.
	if opts.StaleOnly {
		filtered := make([]NonHumanIdentity, 0)
		for _, nhi := range allNHIs {
			if nhi.Stale {
				filtered = append(filtered, nhi)
			}
		}
		allNHIs = filtered
	}

	// Sort by namespace, then name for consistent output.
	sort.Slice(allNHIs, func(i, j int) bool {
		if allNHIs[i].Namespace != allNHIs[j].Namespace {
			return allNHIs[i].Namespace < allNHIs[j].Namespace
		}
		return allNHIs[i].Name < allNHIs[j].Name
	})

	return allNHIs, allErrors
}
