package discovery

import (
	"context"
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// DiscoverEgressRestrictions checks which ServiceAccount pods have
// NetworkPolicies restricting egress. It returns a map of
// "namespace/saName" → true for every SA whose pods are covered by at
// least one NetworkPolicy that includes Egress in its PolicyTypes.
func DiscoverEgressRestrictions(ctx context.Context, client kubernetes.Interface, namespace string) (map[string]bool, error) {
	// List all pods (scoped to namespace when non-empty).
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}

	// List all NetworkPolicies (same namespace scope).
	netpols, err := client.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing network policies: %w", err)
	}

	// Build a per-namespace index of egress policies.
	egressByNS := make(map[string][]networkingv1.NetworkPolicy)
	for i := range netpols.Items {
		np := &netpols.Items[i]
		if hasEgressPolicyType(np) {
			egressByNS[np.Namespace] = append(egressByNS[np.Namespace], *np)
		}
	}

	result := make(map[string]bool)
	for i := range pods.Items {
		pod := &pods.Items[i]
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		key := fmt.Sprintf("%s/%s", pod.Namespace, saName)

		// Already marked restricted by a previous pod for this SA.
		if result[key] {
			continue
		}

		// Check if any egress policy in this namespace selects this pod.
		for _, np := range egressByNS[pod.Namespace] {
			sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
			if err != nil {
				continue // malformed selector — skip
			}
			if sel.Matches(labels.Set(pod.Labels)) {
				result[key] = true
				break
			}
		}
	}

	return result, nil
}

// hasEgressPolicyType returns true when the NetworkPolicy declares
// Egress in its PolicyTypes list.
func hasEgressPolicyType(np *networkingv1.NetworkPolicy) bool {
	for _, pt := range np.Spec.PolicyTypes {
		if pt == networkingv1.PolicyTypeEgress {
			return true
		}
	}
	return false
}
