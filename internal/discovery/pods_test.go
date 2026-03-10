package discovery

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDiscoverPodPostures_Privileged(t *testing.T) {
	priv := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "evil-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "admin-sa",
			Containers: []corev1.Container{{
				Name:  "c1",
				Image: "evil:latest",
				SecurityContext: &corev1.SecurityContext{
					Privileged: &priv,
				},
			}},
		},
	}
	client := fake.NewSimpleClientset(pod)
	postures, err := DiscoverPodPostures(context.Background(), client, "")
	if err != nil {
		t.Fatal(err)
	}
	key := "default/admin-sa"
	if len(postures[key]) != 1 {
		t.Fatalf("expected 1 posture for %s, got %d", key, len(postures[key]))
	}
	if !postures[key][0].Privileged {
		t.Error("expected Privileged=true")
	}
	if postures[key][0].PodName != "evil-pod" {
		t.Errorf("expected PodName=evil-pod, got %s", postures[key][0].PodName)
	}
	if postures[key][0].Namespace != "default" {
		t.Errorf("expected Namespace=default, got %s", postures[key][0].Namespace)
	}
}

func TestDiscoverPodPostures_HostAccess(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "host-pod", Namespace: "kube-system"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "node-agent",
			HostNetwork:        true,
			HostPID:            true,
			Volumes: []corev1.Volume{{
				Name: "hostfs",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/"},
				},
			}},
		},
	}
	client := fake.NewSimpleClientset(pod)
	postures, err := DiscoverPodPostures(context.Background(), client, "")
	if err != nil {
		t.Fatal(err)
	}
	key := "kube-system/node-agent"
	if len(postures[key]) != 1 {
		t.Fatalf("expected 1 posture for %s, got %d", key, len(postures[key]))
	}
	p := postures[key][0]
	if !p.HostNetwork {
		t.Error("expected HostNetwork=true")
	}
	if !p.HostPID {
		t.Error("expected HostPID=true")
	}
	if !p.HostPath {
		t.Error("expected HostPath=true")
	}
	// HostIPC was not set
	if p.HostIPC {
		t.Error("expected HostIPC=false")
	}
}

func TestDiscoverPodPostures_RunAsRoot(t *testing.T) {
	rootUID := int64(0)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "root-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "app-sa",
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser: &rootUID,
			},
		},
	}
	client := fake.NewSimpleClientset(pod)
	postures, err := DiscoverPodPostures(context.Background(), client, "")
	if err != nil {
		t.Fatal(err)
	}
	if !postures["default/app-sa"][0].RunAsRoot {
		t.Error("expected RunAsRoot=true for UID 0")
	}
}

func TestDiscoverPodPostures_RunAsRootContainer(t *testing.T) {
	rootUID := int64(0)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "root-container-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "app-sa",
			Containers: []corev1.Container{{
				Name:  "c1",
				Image: "app:latest",
				SecurityContext: &corev1.SecurityContext{
					RunAsUser: &rootUID,
				},
			}},
		},
	}
	client := fake.NewSimpleClientset(pod)
	postures, err := DiscoverPodPostures(context.Background(), client, "")
	if err != nil {
		t.Fatal(err)
	}
	if !postures["default/app-sa"][0].RunAsRoot {
		t.Error("expected RunAsRoot=true for container with UID 0")
	}
}

func TestDiscoverPodPostures_RunAsRootInitContainer(t *testing.T) {
	rootUID := int64(0)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "init-root-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "app-sa",
			InitContainers: []corev1.Container{{
				Name:  "init",
				Image: "init:latest",
				SecurityContext: &corev1.SecurityContext{
					RunAsUser: &rootUID,
				},
			}},
			Containers: []corev1.Container{{
				Name:  "c1",
				Image: "app:latest",
			}},
		},
	}
	client := fake.NewSimpleClientset(pod)
	postures, err := DiscoverPodPostures(context.Background(), client, "")
	if err != nil {
		t.Fatal(err)
	}
	if !postures["default/app-sa"][0].RunAsRoot {
		t.Error("expected RunAsRoot=true for init container with UID 0")
	}
}

func TestDiscoverPodPostures_NoPods(t *testing.T) {
	client := fake.NewSimpleClientset()
	postures, err := DiscoverPodPostures(context.Background(), client, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(postures) != 0 {
		t.Errorf("expected empty map, got %d entries", len(postures))
	}
}

func TestDiscoverPodPostures_NamespaceFilter(t *testing.T) {
	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "ns1"},
		Spec:       corev1.PodSpec{ServiceAccountName: "sa1"},
	}
	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: "ns2"},
		Spec:       corev1.PodSpec{ServiceAccountName: "sa2"},
	}
	client := fake.NewSimpleClientset(pod1, pod2)
	postures, err := DiscoverPodPostures(context.Background(), client, "ns1")
	if err != nil {
		t.Fatal(err)
	}
	if len(postures) != 1 {
		t.Errorf("expected 1 SA, got %d", len(postures))
	}
	if _, ok := postures["ns1/sa1"]; !ok {
		t.Error("expected ns1/sa1 in results")
	}
}

func TestDiscoverPodPostures_MultiplePodsPerSA(t *testing.T) {
	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-a", Namespace: "default"},
		Spec:       corev1.PodSpec{ServiceAccountName: "shared-sa"},
	}
	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-b", Namespace: "default"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "shared-sa",
			HostNetwork:        true,
		},
	}
	client := fake.NewSimpleClientset(pod1, pod2)
	postures, err := DiscoverPodPostures(context.Background(), client, "")
	if err != nil {
		t.Fatal(err)
	}
	key := "default/shared-sa"
	if len(postures[key]) != 2 {
		t.Fatalf("expected 2 postures for %s, got %d", key, len(postures[key]))
	}
	// Verify both pod names are present
	names := map[string]bool{}
	for _, p := range postures[key] {
		names[p.PodName] = true
	}
	if !names["pod-a"] || !names["pod-b"] {
		t.Error("expected both pod-a and pod-b in results")
	}
}

func TestDiscoverPodPostures_DefaultSAName(t *testing.T) {
	// Pod with empty ServiceAccountName should default to "default"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "no-sa-pod", Namespace: "myns"},
		Spec: corev1.PodSpec{
			// ServiceAccountName intentionally left empty
			Containers: []corev1.Container{{
				Name:  "c1",
				Image: "app:latest",
			}},
		},
	}
	client := fake.NewSimpleClientset(pod)
	postures, err := DiscoverPodPostures(context.Background(), client, "")
	if err != nil {
		t.Fatal(err)
	}
	key := "myns/default"
	if len(postures[key]) != 1 {
		t.Fatalf("expected 1 posture for %s, got %d", key, len(postures[key]))
	}
	if postures[key][0].PodName != "no-sa-pod" {
		t.Errorf("expected PodName=no-sa-pod, got %s", postures[key][0].PodName)
	}
}

func TestDiscoverPodPostures_HostIPC(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "ipc-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "ipc-sa",
			HostIPC:            true,
		},
	}
	client := fake.NewSimpleClientset(pod)
	postures, err := DiscoverPodPostures(context.Background(), client, "")
	if err != nil {
		t.Fatal(err)
	}
	if !postures["default/ipc-sa"][0].HostIPC {
		t.Error("expected HostIPC=true")
	}
}

func TestDiscoverPodPostures_PrivilegedInitContainer(t *testing.T) {
	priv := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "init-priv-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "priv-sa",
			InitContainers: []corev1.Container{{
				Name:  "init",
				Image: "init:latest",
				SecurityContext: &corev1.SecurityContext{
					Privileged: &priv,
				},
			}},
			Containers: []corev1.Container{{
				Name:  "c1",
				Image: "app:latest",
			}},
		},
	}
	client := fake.NewSimpleClientset(pod)
	postures, err := DiscoverPodPostures(context.Background(), client, "")
	if err != nil {
		t.Fatal(err)
	}
	if !postures["default/priv-sa"][0].Privileged {
		t.Error("expected Privileged=true from init container")
	}
}

func TestDiscoverPodPostures_CleanPod(t *testing.T) {
	// Pod with no risky settings should have all posture fields false
	nonRoot := int64(1000)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "clean-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "clean-sa",
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser: &nonRoot,
			},
			Containers: []corev1.Container{{
				Name:  "c1",
				Image: "app:latest",
			}},
		},
	}
	client := fake.NewSimpleClientset(pod)
	postures, err := DiscoverPodPostures(context.Background(), client, "")
	if err != nil {
		t.Fatal(err)
	}
	p := postures["default/clean-sa"][0]
	if p.Privileged || p.RunAsRoot || p.HostNetwork || p.HostPID || p.HostIPC || p.HostPath {
		t.Errorf("expected all posture flags false for clean pod, got %+v", p)
	}
}
