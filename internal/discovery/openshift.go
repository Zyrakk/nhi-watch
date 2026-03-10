package discovery

import corev1 "k8s.io/api/core/v1"

const sccAnnotation = "openshift.io/scc"

// enrichWithSCC reads the SCC annotation from a pod and sets it on the posture.
// This is safe to call on any cluster — on vanilla K8s the annotation won't exist.
func enrichWithSCC(posture *PodPosture, pod *corev1.Pod) {
	if pod.Annotations == nil {
		return
	}
	posture.SCCName = pod.Annotations[sccAnnotation]
}

// SCCIsPrivileged returns true for OpenShift SCCs that grant elevated privileges.
func SCCIsPrivileged(scc string) bool {
	switch scc {
	case "privileged", "anyuid", "hostaccess", "hostnetwork", "hostmount-anyuid":
		return true
	}
	return false
}
