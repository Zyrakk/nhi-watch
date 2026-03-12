package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Zyrakk/nhi-watch/internal/controller"
	"github.com/Zyrakk/nhi-watch/internal/k8s"
	"github.com/Zyrakk/nhi-watch/internal/usage"
)

var (
	ctrlStateNamespace string
	ctrlStateConfigMap string
	ctrlWebhookPort    int
	ctrlEnableWebhook  bool
	ctrlDebounceSecs   int

	ctrlStatusNamespace string
	ctrlStatusConfigMap string
)

var controllerCmd = &cobra.Command{
	Use:   "controller",
	Short: "Run the NHI-Watch real-time controller",
	Long: `Start the NHI-Watch controller that watches for NHI-related resource
mutations in real-time and detects configuration drift.

Layer 1 (Watch API): Watches ServiceAccount, Secret, RoleBinding, and
ClusterRoleBinding mutations via client-go informers. Zero extra config.

Layer 2 (Audit Webhook): Optionally receives API server audit events to
build per-NHI usage profiles. Requires --enable-webhook and API server
audit configuration.`,
}

var controllerStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the real-time controller",
	RunE:  runControllerStart,
}

var controllerAuditPolicyCmd = &cobra.Command{
	Use:   "audit-policy",
	Short: "Generate optimized audit policy for API server",
	Long: `Print a Kubernetes audit policy YAML that captures only NHI-relevant
events (service account API calls at Metadata level). This typically
reduces audit volume by 95%+ compared to a default policy.

Apply via: --audit-policy-file=<path> on the API server.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Print(usage.GenerateAuditPolicy())
		return nil
	},
}

var controllerStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show controller state and scan statistics",
	RunE:  runControllerStatus,
}

func init() {
	controllerStartCmd.Flags().StringVar(&ctrlStateNamespace, "state-namespace", "nhi-watch", "namespace for state ConfigMap")
	controllerStartCmd.Flags().StringVar(&ctrlStateConfigMap, "state-configmap", "nhi-watch-state", "name of state ConfigMap")
	controllerStartCmd.Flags().IntVar(&ctrlWebhookPort, "webhook-port", 8443, "port for audit webhook endpoint")
	controllerStartCmd.Flags().BoolVar(&ctrlEnableWebhook, "enable-webhook", false, "enable audit webhook receiver (Layer 2)")
	controllerStartCmd.Flags().IntVar(&ctrlDebounceSecs, "debounce", 5, "seconds to wait after mutation before re-scanning")

	controllerStatusCmd.Flags().StringVar(&ctrlStatusNamespace, "state-namespace", "nhi-watch", "namespace for state ConfigMap")
	controllerStatusCmd.Flags().StringVar(&ctrlStatusConfigMap, "state-configmap", "nhi-watch-state", "name of state ConfigMap")

	controllerCmd.AddCommand(controllerStartCmd)
	controllerCmd.AddCommand(controllerAuditPolicyCmd)
	controllerCmd.AddCommand(controllerStatusCmd)
	rootCmd.AddCommand(controllerCmd)
}

func runControllerStart(cmd *cobra.Command, args []string) error {
	// Build Kubernetes clients.
	clients, err := k8s.NewClients(k8s.ClientOpts{
		Kubeconfig: kubeconfig,
		Context:    kubeCtx,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to cluster: %w", err)
	}

	// Create the state store for drift detection.
	store := controller.NewStateStore(clients.Clientset, ctrlStateNamespace, ctrlStateConfigMap)

	// Event callback logs lifecycle events to stderr.
	callback := func(event, detail string) {
		if detail != "" {
			fmt.Fprintf(os.Stderr, "[%s] %s: %s\n", time.Now().Format(time.RFC3339), event, detail)
		} else {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", time.Now().Format(time.RFC3339), event)
		}
	}

	debounceDur := time.Duration(ctrlDebounceSecs) * time.Second

	ctrl := controller.NewController(clients.Clientset, clients.Dynamic, store, namespace, debounceDur, callback)

	// Set up graceful shutdown on SIGINT/SIGTERM.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Layer 2: Audit webhook (optional).
	var (
		webhookSource *usage.AuditWebhookSource
		httpServer    *http.Server
	)

	if ctrlEnableWebhook {
		profileStore := usage.NewProfileStore(clients.Clientset, ctrlStateNamespace, ctrlStateConfigMap+"-profiles")
		webhookSource = usage.NewAuditWebhookSource(profileStore)

		// Load existing profiles from the ConfigMap.
		if err := webhookSource.LoadExisting(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to load existing profiles: %v\n", err)
		}

		mux := http.NewServeMux()
		mux.Handle("/webhook/audit", webhookSource.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})

		httpServer = &http.Server{
			Addr:              fmt.Sprintf(":%d", ctrlWebhookPort),
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}

		// Start HTTP server in a goroutine.
		go func() {
			fmt.Fprintf(os.Stderr, "[%s] webhook.listening: port=%d\n", time.Now().Format(time.RFC3339), ctrlWebhookPort)
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "webhook server error: %v\n", err)
			}
		}()

		// Periodic profile persistence (every 60 seconds).
		go func() {
			ticker := time.NewTicker(60 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := webhookSource.Persist(ctx); err != nil {
						fmt.Fprintf(os.Stderr, "warning: failed to persist profiles: %v\n", err)
					}
				}
			}
		}()
	}

	// Run the controller in a goroutine so we can handle signals.
	errCh := make(chan error, 1)
	go func() {
		errCh <- ctrl.Start(ctx)
	}()

	// Wait for signal or controller error.
	select {
	case sig := <-sigCh:
		fmt.Fprintf(os.Stderr, "\n[%s] shutdown: received %s\n", time.Now().Format(time.RFC3339), sig)
		cancel()
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			return fmt.Errorf("controller error: %w", err)
		}
		return nil
	}

	// Graceful shutdown: persist webhook profiles and stop HTTP server.
	if webhookSource != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		if err := webhookSource.Persist(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "warning: final profile persist failed: %v\n", err)
		}

		if httpServer != nil {
			if err := httpServer.Shutdown(shutdownCtx); err != nil {
				fmt.Fprintf(os.Stderr, "warning: webhook server shutdown error: %v\n", err)
			}
		}
	}

	// Wait for controller to finish after cancel.
	if err := <-errCh; err != nil && err != context.Canceled {
		return fmt.Errorf("controller error: %w", err)
	}

	return nil
}

func runControllerStatus(cmd *cobra.Command, args []string) error {
	clients, err := k8s.NewClients(k8s.ClientOpts{
		Kubeconfig: kubeconfig,
		Context:    kubeCtx,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to cluster: %w", err)
	}

	store := controller.NewStateStore(clients.Clientset, ctrlStatusNamespace, ctrlStatusConfigMap)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	state, err := store.LoadState(ctx)
	if err != nil {
		return fmt.Errorf("failed to load controller state: %w", err)
	}

	if state == nil {
		fmt.Fprintln(os.Stderr, "Controller has not run yet or state not found")
		return nil
	}

	// Parse timestamps for duration calculations.
	now := time.Now().UTC()

	lastScanTime, err := time.Parse(time.RFC3339, state.LastScan)
	if err != nil {
		return fmt.Errorf("invalid last_scan timestamp: %w", err)
	}
	lastScanAgo := formatDuration(now.Sub(lastScanTime))

	var observationPeriod string
	if state.StartedAt != "" {
		startedAtTime, err := time.Parse(time.RFC3339, state.StartedAt)
		if err != nil {
			return fmt.Errorf("invalid started_at timestamp: %w", err)
		}
		observationPeriod = formatDuration(now.Sub(startedAtTime))
	}

	// Count severities across all snapshots.
	sevCounts := map[string]int{}
	for _, snap := range state.Snapshots {
		if snap.Severity != "" {
			sevCounts[snap.Severity]++
		}
	}

	// Build severity breakdown string.
	sevOrder := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	var sevParts []string
	for _, sev := range sevOrder {
		if count, ok := sevCounts[sev]; ok && count > 0 {
			sevParts = append(sevParts, fmt.Sprintf("%d %s", count, sev))
		}
	}
	sevBreakdown := strings.Join(sevParts, ", ")
	if sevBreakdown == "" {
		sevBreakdown = "none"
	}

	// Print formatted status table.
	fmt.Println("Controller Status")
	fmt.Printf("  ConfigMap:          %s/%s\n", ctrlStatusNamespace, ctrlStatusConfigMap)
	if state.StartedAt != "" {
		fmt.Printf("  Started at:         %s\n", state.StartedAt)
	}
	fmt.Printf("  Last scan:          %s (%s ago)\n", state.LastScan, lastScanAgo)
	fmt.Printf("  Scans completed:    %d\n", state.ScanCount)
	fmt.Printf("  NHIs tracked:       %d\n", len(state.Snapshots))
	if observationPeriod != "" {
		fmt.Printf("  Observation period: %s\n", observationPeriod)
	}
	fmt.Printf("  Severity breakdown: %s\n", sevBreakdown)

	return nil
}

// formatDuration formats a duration as "Xd Xh Xm" for human readability.
// Days > 0 shows all three components, hours > 0 shows hours+minutes,
// otherwise just minutes. For durations < 1 minute it falls back to d.String().
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return d.String()
	}

	totalMinutes := int(d.Minutes())
	days := totalMinutes / (60 * 24)
	hours := (totalMinutes % (60 * 24)) / 60
	minutes := totalMinutes % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
