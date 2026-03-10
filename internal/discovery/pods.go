package discovery

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DiscoverPodPostures lists all pods in the given namespace (or all
// namespaces if namespace is empty) and returns a map keyed by
// "namespace/saName" to the security postures of pods referencing
// that ServiceAccount.
func DiscoverPodPostures(ctx context.Context, client kubernetes.Interface, namespace string) (map[string][]PodPosture, error) {
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}

	result := make(map[string][]PodPosture)
	for i := range pods.Items {
		pod := &pods.Items[i]
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		key := fmt.Sprintf("%s/%s", pod.Namespace, saName)
		posture := extractPodPosture(pod)
		result[key] = append(result[key], posture)
	}
	return result, nil
}

// extractPodPosture inspects a pod's security context and volumes to
// determine its security posture.
func extractPodPosture(pod *corev1.Pod) PodPosture {
	p := PodPosture{
		PodName:     pod.Name,
		Namespace:   pod.Namespace,
		HostNetwork: pod.Spec.HostNetwork,
		HostPID:     pod.Spec.HostPID,
		HostIPC:     pod.Spec.HostIPC,
		HostPath:    hasHostPathVolume(pod.Spec.Volumes),
	}

	// Check pod-level security context for RunAsUser == 0.
	if psc := pod.Spec.SecurityContext; psc != nil {
		if psc.RunAsUser != nil && *psc.RunAsUser == 0 {
			p.RunAsRoot = true
		}
	}

	// Check container-level security contexts (both regular and init containers).
	allContainers := make([]corev1.Container, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers))
	allContainers = append(allContainers, pod.Spec.Containers...)
	allContainers = append(allContainers, pod.Spec.InitContainers...)

	for _, c := range allContainers {
		if c.SecurityContext == nil {
			continue
		}
		if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			p.Privileged = true
		}
		if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
			p.RunAsRoot = true
		}
	}

	// OpenShift SCC enrichment (safe on vanilla K8s — annotation just won't exist)
	enrichWithSCC(&p, pod)

	return p
}

// hasHostPathVolume returns true if any volume in the list uses a HostPath source.
func hasHostPathVolume(volumes []corev1.Volume) bool {
	for _, v := range volumes {
		if v.HostPath != nil {
			return true
		}
	}
	return false
}
