package discovery

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DiscoverServiceAccounts enumerates every ServiceAccount across all namespaces
// (or a specific one) and returns them as NonHumanIdentity entries.
//
// This works identically on k3s, vanilla Kubernetes, and OpenShift because
// ServiceAccount is a core/v1 resource available on every conformant cluster.
func DiscoverServiceAccounts(ctx context.Context, client kubernetes.Interface, namespace string) ([]NonHumanIdentity, error) {
	saList, err := client.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing service accounts: %w", err)
	}

	nhis := make([]NonHumanIdentity, 0, len(saList.Items))
	for i := range saList.Items {
		nhis = append(nhis, serviceAccountToNHI(&saList.Items[i]))
	}

	return nhis, nil
}

// serviceAccountToNHI converts a Kubernetes ServiceAccount to the shared
// NonHumanIdentity model.
func serviceAccountToNHI(sa *corev1.ServiceAccount) NonHumanIdentity {
	nhi := NonHumanIdentity{
		ID:        generateID(NHITypeServiceAccount, sa.Namespace, sa.Name),
		Type:      NHITypeServiceAccount,
		Name:      sa.Name,
		Namespace: sa.Namespace,
		CreatedAt: sa.CreationTimestamp.Time,
		Metadata:  make(map[string]string),
	}

	// Secret count (legacy token secrets mounted to this SA).
	nhi.Metadata["secret_count"] = fmt.Sprintf("%d", len(sa.Secrets))

	// AutomountServiceAccountToken — critical for security posture.
	// nil means not explicitly set, which defaults to true (insecure default).
	if sa.AutomountServiceAccountToken != nil {
		nhi.Metadata["automount_token"] = fmt.Sprintf("%t", *sa.AutomountServiceAccountToken)
	} else {
		nhi.Metadata["automount_token"] = "default (true)"
	}

	// Flag default SA — any RoleBinding on a default SA is a red flag
	// that should be caught by scoring in Phase 3.
	if sa.Name == "default" {
		nhi.Metadata["is_default_sa"] = "true"
	}

	// Try to detect source from common annotations/labels.
	nhi.Source = detectSource(sa)

	return nhi
}

// detectSource attempts to determine the origin of a ServiceAccount
// by inspecting common labels and annotations left by Helm, operators, etc.
func detectSource(sa *corev1.ServiceAccount) string {
	// Helm chart origin.
	if chart, ok := sa.Labels["helm.sh/chart"]; ok {
		return "helm-chart:" + chart
	}
	if chart, ok := sa.Labels["app.kubernetes.io/managed-by"]; ok {
		if name, ok2 := sa.Labels["app.kubernetes.io/name"]; ok2 {
			return chart + ":" + name
		}
		return chart
	}

	// Operator-managed.
	if owner, ok := sa.Annotations["operator-sdk/primary-resource"]; ok {
		return "operator:" + owner
	}

	// ArgoCD / Flux managed.
	if _, ok := sa.Labels["argocd.argoproj.io/instance"]; ok {
		return "argocd"
	}
	if _, ok := sa.Labels["kustomize.toolkit.fluxcd.io/name"]; ok {
		return "flux"
	}

	return "unknown"
}

// generateID creates a deterministic unique ID for an NHI based on its
// type, namespace, and name. This ensures the same NHI always gets the
// same ID across scans.
func generateID(nhiType NHIType, namespace, name string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%s", nhiType, namespace, name)))
	return fmt.Sprintf("%x", h[:8]) // 16-char hex string
}

// formatAge formats a duration into a human-readable age string.
func FormatAge(d time.Duration) string {
	switch {
	case d.Hours() > 24*365:
		return fmt.Sprintf("%dy", int(d.Hours()/(24*365)))
	case d.Hours() > 24*30:
		return fmt.Sprintf("%dmo", int(d.Hours()/(24*30)))
	case d.Hours() > 24:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d.Hours() >= 1:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}
