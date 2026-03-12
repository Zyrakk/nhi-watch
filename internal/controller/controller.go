package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
	"github.com/Zyrakk/nhi-watch/internal/permissions"
	"github.com/Zyrakk/nhi-watch/internal/scoring"
)

// MutationEvent records a resource mutation detected by informers.
type MutationEvent struct {
	ResourceType string
	Action       string // "Added", "Updated", "Deleted"
	Name         string
	Namespace    string
	Timestamp    time.Time
}

// EventCallback is called by the controller to notify consumers about
// lifecycle events (scan.starting, scan.complete, mutation.detected, etc.).
type EventCallback func(event string, detail string)

// Controller watches Kubernetes resources via informers and triggers
// debounced re-scans when mutations are detected.
type Controller struct {
	client    kubernetes.Interface
	dynClient dynamic.Interface
	store     *StateStore
	factory   informers.SharedInformerFactory
	callback  EventCallback
	namespace string // "" = all namespaces

	debounceMu    sync.Mutex
	debounceTimer *time.Timer
	debounceDur   time.Duration

	stopCh chan struct{}
}

// NewController creates a controller that watches SA/Secret/RoleBinding/ClusterRoleBinding
// mutations and triggers debounced re-scans. If debounceDuration is 0, re-scans
// run immediately (useful for tests). The callback receives lifecycle event notifications.
func NewController(client kubernetes.Interface, dynClient dynamic.Interface, store *StateStore, namespace string, debounceDuration time.Duration, callback EventCallback) *Controller {
	if callback == nil {
		callback = func(event, detail string) {}
	}

	return &Controller{
		client:      client,
		dynClient:   dynClient,
		store:       store,
		namespace:   namespace,
		callback:    callback,
		debounceDur: debounceDuration,
		stopCh:      make(chan struct{}),
	}
}

// Start runs the initial scan, sets up informers for ServiceAccounts, Secrets,
// RoleBindings, and ClusterRoleBindings, and blocks until ctx is cancelled.
func (c *Controller) Start(ctx context.Context) error {
	// Run the initial scan before starting informers.
	if err := c.runScan(ctx); err != nil {
		c.callback("scan.error", fmt.Sprintf("initial scan failed: %v", err))
		// Continue to start informers even if initial scan fails — the cluster
		// state may be incomplete but mutations will trigger re-scans.
	}

	// Set up informer factory. For namespace-scoped resources, we use the
	// configured namespace filter. ClusterRoleBindings are cluster-scoped
	// and always watched.
	if c.namespace != "" {
		c.factory = informers.NewSharedInformerFactoryWithOptions(
			c.client, 0, informers.WithNamespace(c.namespace),
		)
	} else {
		c.factory = informers.NewSharedInformerFactory(c.client, 0)
	}

	// Register event handlers for watched resource types.
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.onMutation("Added", obj) },
		UpdateFunc: func(_, obj interface{}) { c.onMutation("Updated", obj) },
		DeleteFunc: func(obj interface{}) { c.onMutation("Deleted", obj) },
	}

	// ServiceAccounts
	saInformer := c.factory.Core().V1().ServiceAccounts().Informer()
	saInformer.AddEventHandler(handler)

	// Secrets
	secretInformer := c.factory.Core().V1().Secrets().Informer()
	secretInformer.AddEventHandler(handler)

	// RoleBindings
	rbInformer := c.factory.Rbac().V1().RoleBindings().Informer()
	rbInformer.AddEventHandler(handler)

	// ClusterRoleBindings (cluster-scoped, always watched regardless of namespace filter)
	crbInformer := c.factory.Rbac().V1().ClusterRoleBindings().Informer()
	crbInformer.AddEventHandler(handler)

	// Start all informers.
	c.factory.Start(c.stopCh)

	// Wait for caches to sync before processing events.
	c.factory.WaitForCacheSync(c.stopCh)

	c.callback("controller.started", fmt.Sprintf("namespace=%q", c.namespace))

	// Block until context is cancelled or Stop() is called.
	select {
	case <-ctx.Done():
		c.Stop()
		return ctx.Err()
	case <-c.stopCh:
		return nil
	}
}

// Stop shuts down the controller, cancelling any pending debounce timer and
// stopping the informer factory.
func (c *Controller) Stop() {
	c.debounceMu.Lock()
	if c.debounceTimer != nil {
		c.debounceTimer.Stop()
		c.debounceTimer = nil
	}
	c.debounceMu.Unlock()

	// Close stopCh to signal informers to stop. Use sync.Once semantics
	// via select to avoid double-close panic.
	select {
	case <-c.stopCh:
		// Already closed.
	default:
		close(c.stopCh)
	}
}

// onMutation is called by informer event handlers when a watched resource
// is added, updated, or deleted.
func (c *Controller) onMutation(action string, obj interface{}) {
	resourceType, name, namespace := extractResourceInfo(obj)
	if resourceType == "" {
		return
	}

	c.callback("mutation.detected", fmt.Sprintf("%s %s %s/%s", action, resourceType, namespace, name))
	c.scheduleRescan()
}

// scheduleRescan schedules a debounced re-scan. If debounceDur is 0, the scan
// runs immediately (synchronously, useful for tests). Otherwise a timer is used
// to coalesce rapid mutations into a single scan.
func (c *Controller) scheduleRescan() {
	c.debounceMu.Lock()
	defer c.debounceMu.Unlock()

	// Cancel any pending timer.
	if c.debounceTimer != nil {
		c.debounceTimer.Stop()
	}

	if c.debounceDur == 0 {
		// Immediate mode (tests): run scan synchronously.
		ctx := context.Background()
		if err := c.runScan(ctx); err != nil {
			c.callback("scan.error", err.Error())
		}
		return
	}

	c.debounceTimer = time.AfterFunc(c.debounceDur, func() {
		ctx := context.Background()
		if err := c.runScan(ctx); err != nil {
			c.callback("scan.error", err.Error())
		}
	})
}

// runScan executes the full NHI pipeline: discover -> resolve RBAC -> score -> persist.
func (c *Controller) runScan(ctx context.Context) error {
	c.callback("scan.starting", "")

	// Phase 1: Discovery.
	discoverOpts := discovery.DiscoverOpts{
		Namespace: c.namespace,
	}

	// The discovery client and dynamic client may be nil in tests; DiscoverAll
	// handles nil gracefully (skips cert-manager discovery).
	nhis, errs := discovery.DiscoverAll(ctx, c.client, nil, c.dynClient, discoverOpts)
	for _, e := range errs {
		c.callback("scan.warning", e.Error())
	}

	// Phase 2: RBAC resolution.
	resolver, err := permissions.NewResolver(ctx, c.client)
	if err != nil {
		c.callback("scan.warning", fmt.Sprintf("RBAC resolution failed: %v", err))
	} else {
		for i := range nhis {
			if nhis[i].Type != discovery.NHITypeServiceAccount {
				continue
			}
			ps := resolver.ResolveServiceAccount(nhis[i].Name, nhis[i].Namespace)
			permissions.Analyze(ps, nhis[i].Name, nhis[i].Namespace)
			nhis[i].Permissions = ps
		}
	}

	// Phase 3: Scoring.
	engine := scoring.NewEngine(scoring.DefaultRules())
	results := engine.ScoreAll(nhis)

	// Build snapshots from scoring results.
	now := time.Now().UTC().Format(time.RFC3339)
	snapshots := make([]NHISnapshot, 0, len(results))
	for _, r := range results {
		snapshots = append(snapshots, NHISnapshot{
			NHIID:     r.NHIID,
			Name:      r.Name,
			Namespace: r.Namespace,
			Type:      r.Type,
			Score:     r.FinalScore,
			Severity:  string(r.FinalSeverity),
			RulesHash: hashRuleResults(r.Results),
			Timestamp: now,
		})
	}

	// Phase: drift detection (Task 4 -- drift.go)
	previous, loadErr := c.store.LoadSnapshots(ctx)
	if loadErr != nil {
		c.callback("scan.warning", fmt.Sprintf("failed to load previous state: %v", loadErr))
	} else if previous != nil {
		driftEvents := detectDrift(previous, snapshots)
		for _, de := range driftEvents {
			c.callback("drift.detected", fmt.Sprintf("%s %s/%s: %s", de.Type, de.Namespace, de.Name, de.Detail))
		}
	}

	// Persist current snapshots.
	if err := c.store.SaveSnapshots(ctx, snapshots); err != nil {
		c.callback("scan.error", fmt.Sprintf("failed to save state: %v", err))
		return fmt.Errorf("saving state: %w", err)
	}

	c.callback("scan.complete", fmt.Sprintf("scored %d NHIs", len(results)))
	return nil
}

// hashRuleResults produces a deterministic hash from a set of rule results.
// Rule IDs are sorted, joined with commas, and SHA-256 hashed. The first 8
// bytes of the hex digest are returned.
func hashRuleResults(results []scoring.RuleResult) string {
	ids := make([]string, 0, len(results))
	for _, r := range results {
		ids = append(ids, r.RuleID)
	}
	sort.Strings(ids)
	joined := strings.Join(ids, ",")
	sum := sha256.Sum256([]byte(joined))
	return fmt.Sprintf("%x", sum[:8])
}

// extractResourceInfo returns (resourceType, name, namespace) for a Kubernetes
// object received by an informer handler.
func extractResourceInfo(obj interface{}) (string, string, string) {
	switch o := obj.(type) {
	case *corev1.ServiceAccount:
		return "ServiceAccount", o.Name, o.Namespace
	case *corev1.Secret:
		return "Secret", o.Name, o.Namespace
	case *rbacv1.RoleBinding:
		return "RoleBinding", o.Name, o.Namespace
	case *rbacv1.ClusterRoleBinding:
		return "ClusterRoleBinding", o.Name, ""
	default:
		return "", "", ""
	}
}
