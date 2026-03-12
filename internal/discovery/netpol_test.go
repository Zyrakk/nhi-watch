package discovery

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDiscoverEgressRestrictions_NoNetPol(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-pod",
				Namespace: "default",
				Labels:    map[string]string{"app": "web"},
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: "web-sa",
			},
		},
	)

	result, err := DiscoverEgressRestrictions(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["default/web-sa"] {
		t.Error("expected default/web-sa to NOT be restricted (no NetworkPolicy)")
	}
}

func TestDiscoverEgressRestrictions_WithEgressPolicy(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-pod",
				Namespace: "production",
				Labels:    map[string]string{"app": "api"},
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: "api-sa",
			},
		},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "restrict-egress",
				Namespace: "production",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "api"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeEgress,
				},
			},
		},
	)

	result, err := DiscoverEgressRestrictions(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result["production/api-sa"] {
		t.Error("expected production/api-sa to be restricted by egress NetworkPolicy")
	}
}

func TestDiscoverEgressRestrictions_IngressOnlyDoesNotCount(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-pod",
				Namespace: "default",
				Labels:    map[string]string{"app": "web"},
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: "web-sa",
			},
		},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ingress-only",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
				},
			},
		},
	)

	result, err := DiscoverEgressRestrictions(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["default/web-sa"] {
		t.Error("expected default/web-sa to NOT be restricted (ingress-only policy)")
	}
}

func TestDiscoverEgressRestrictions_NamespaceFilter(t *testing.T) {
	client := fake.NewSimpleClientset(
		// Pod in ns1 with egress policy.
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod-ns1",
				Namespace: "ns1",
				Labels:    map[string]string{"app": "svc"},
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: "sa1",
			},
		},
		// Pod in ns2 without egress policy.
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod-ns2",
				Namespace: "ns2",
				Labels:    map[string]string{"app": "svc"},
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: "sa2",
			},
		},
		// Egress policy only in ns1.
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "egress-ns1",
				Namespace: "ns1",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "svc"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeEgress,
				},
			},
		},
	)

	// Filter to ns1 only.
	result, err := DiscoverEgressRestrictions(context.Background(), client, "ns1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result["ns1/sa1"] {
		t.Error("expected ns1/sa1 to be restricted")
	}
	if result["ns2/sa2"] {
		t.Error("expected ns2/sa2 to NOT be in results (filtered to ns1)")
	}
}
