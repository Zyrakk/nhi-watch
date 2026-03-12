package usage

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const profileDataKey = "profiles.json"

// ProfileStore persists usage profiles to a Kubernetes ConfigMap.
// The pattern matches controller.StateStore from the controller package.
type ProfileStore struct {
	client    kubernetes.Interface
	namespace string
	name      string
}

// NewProfileStore creates a ProfileStore that reads and writes the named
// ConfigMap in the given namespace.
func NewProfileStore(client kubernetes.Interface, namespace, name string) *ProfileStore {
	return &ProfileStore{client: client, namespace: namespace, name: name}
}

// profileLabels returns the standard labels applied to the profile ConfigMap.
func profileLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "nhi-watch",
		"app.kubernetes.io/component": "usage-profiles",
	}
}

// Save writes the profile map to the ConfigMap, creating it if it does not yet
// exist. The ConfigMap is labelled with app.kubernetes.io/name=nhi-watch and
// app.kubernetes.io/component=usage-profiles.
func (s *ProfileStore) Save(ctx context.Context, profiles map[string]*UsageProfile) error {
	raw, err := json.Marshal(profiles)
	if err != nil {
		return fmt.Errorf("marshaling profiles: %w", err)
	}

	existing, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.name,
				Namespace: s.namespace,
				Labels:    profileLabels(),
			},
			Data: map[string]string{
				profileDataKey: string(raw),
			},
		}
		if _, err := s.client.CoreV1().ConfigMaps(s.namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("creating profiles configmap: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("getting profiles configmap: %w", err)
	}

	// Update existing ConfigMap.
	if existing.Data == nil {
		existing.Data = make(map[string]string)
	}
	existing.Data[profileDataKey] = string(raw)
	// Ensure labels are present on updates too.
	if existing.Labels == nil {
		existing.Labels = make(map[string]string)
	}
	for k, v := range profileLabels() {
		existing.Labels[k] = v
	}

	if _, err := s.client.CoreV1().ConfigMaps(s.namespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("updating profiles configmap: %w", err)
	}
	return nil
}

// Load reads profiles from the ConfigMap. If the ConfigMap does not exist
// (first run), it returns an empty map (never nil).
func (s *ProfileStore) Load(ctx context.Context) (map[string]*UsageProfile, error) {
	cm, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return make(map[string]*UsageProfile), nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting profiles configmap: %w", err)
	}

	raw, ok := cm.Data[profileDataKey]
	if !ok {
		return make(map[string]*UsageProfile), nil
	}

	var profiles map[string]*UsageProfile
	if err := json.Unmarshal([]byte(raw), &profiles); err != nil {
		return nil, fmt.Errorf("parsing profiles data: %w", err)
	}
	if profiles == nil {
		profiles = make(map[string]*UsageProfile)
	}
	return profiles, nil
}
