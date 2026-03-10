package discovery

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEnrichWithSCC_AnnotationPresent(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-app-1",
			Namespace: "production",
			Annotations: map[string]string{
				"openshift.io/scc": "privileged",
			},
		},
	}

	var p PodPosture
	enrichWithSCC(&p, pod)

	if p.SCCName != "privileged" {
		t.Errorf("expected SCCName %q, got %q", "privileged", p.SCCName)
	}
}

func TestEnrichWithSCC_NoAnnotation(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-app-2",
			Namespace: "production",
			Annotations: map[string]string{
				"some-other-annotation": "value",
			},
		},
	}

	var p PodPosture
	enrichWithSCC(&p, pod)

	if p.SCCName != "" {
		t.Errorf("expected empty SCCName, got %q", p.SCCName)
	}
}

func TestEnrichWithSCC_NilAnnotations(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-app-3",
			Namespace: "production",
		},
	}

	var p PodPosture
	// Must not panic.
	enrichWithSCC(&p, pod)

	if p.SCCName != "" {
		t.Errorf("expected empty SCCName, got %q", p.SCCName)
	}
}

func TestSCCIsPrivileged(t *testing.T) {
	tests := []struct {
		scc  string
		want bool
	}{
		{"privileged", true},
		{"anyuid", true},
		{"restricted", false},
		{"restricted-v2", false},
		{"nonroot", false},
		{"nonroot-v2", false},
		{"hostaccess", true},
		{"hostnetwork", true},
		{"hostmount-anyuid", true},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.scc, func(t *testing.T) {
			got := SCCIsPrivileged(tt.scc)
			if got != tt.want {
				t.Errorf("SCCIsPrivileged(%q) = %v, want %v", tt.scc, got, tt.want)
			}
		})
	}
}
