package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
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

func init() {
	controllerStartCmd.Flags().StringVar(&ctrlStateNamespace, "state-namespace", "nhi-watch", "namespace for state ConfigMap")
	controllerStartCmd.Flags().StringVar(&ctrlStateConfigMap, "state-configmap", "nhi-watch-state", "name of state ConfigMap")
	controllerStartCmd.Flags().IntVar(&ctrlWebhookPort, "webhook-port", 8443, "port for audit webhook endpoint")
	controllerStartCmd.Flags().BoolVar(&ctrlEnableWebhook, "enable-webhook", false, "enable audit webhook receiver (Layer 2)")
	controllerStartCmd.Flags().IntVar(&ctrlDebounceSecs, "debounce", 5, "seconds to wait after mutation before re-scanning")

	controllerCmd.AddCommand(controllerStartCmd)
	controllerCmd.AddCommand(controllerAuditPolicyCmd)
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
