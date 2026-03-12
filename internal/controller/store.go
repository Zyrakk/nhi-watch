// Package controller implements the NHI-Watch real-time monitoring controller.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NHISnapshot represents a point-in-time record of a single Non-Human Identity
// used by the controller for drift detection between scan cycles.
type NHISnapshot struct {
	NHIID     string `json:"nhi_id"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Type      string `json:"type"`
	Score     int    `json:"score"`
	Severity  string `json:"severity"`
	RulesHash string `json:"rules_hash"`
	Timestamp string `json:"timestamp"`
}

// stateData is the internal envelope stored in the ConfigMap's data key.
type stateData struct {
	Version   string        `json:"version"`
	LastScan  string        `json:"last_scan"`
	Snapshots []NHISnapshot `json:"snapshots"`
}

const stateDataKey = "state.json"

// StateStore persists NHI snapshots in a Kubernetes ConfigMap so the controller
// can detect drift between scan cycles without external storage.
type StateStore struct {
	client    kubernetes.Interface
	namespace string
	name      string
}

// NewStateStore creates a StateStore that reads and writes the named ConfigMap
// in the given namespace.
func NewStateStore(client kubernetes.Interface, namespace, name string) *StateStore {
	return &StateStore{client: client, namespace: namespace, name: name}
}

// configMapLabels returns the standard labels applied to the state ConfigMap.
func configMapLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "nhi-watch",
		"app.kubernetes.io/component": "controller-state",
	}
}

// SaveSnapshots writes NHI snapshots to the ConfigMap, creating it if it does
// not yet exist. The ConfigMap is labelled with app.kubernetes.io/name=nhi-watch
// and app.kubernetes.io/component=controller-state.
func (s *StateStore) SaveSnapshots(ctx context.Context, snapshots []NHISnapshot) error {
	sd := stateData{
		Version:   "v2",
		LastScan:  time.Now().UTC().Format(time.RFC3339),
		Snapshots: snapshots,
	}

	raw, err := json.Marshal(sd)
	if err != nil {
		return fmt.Errorf("marshaling state data: %w", err)
	}

	existing, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.name,
				Namespace: s.namespace,
				Labels:    configMapLabels(),
			},
			Data: map[string]string{
				stateDataKey: string(raw),
			},
		}
		if _, err := s.client.CoreV1().ConfigMaps(s.namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("creating state configmap: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("getting state configmap: %w", err)
	}

	// Update existing ConfigMap.
	if existing.Data == nil {
		existing.Data = make(map[string]string)
	}
	existing.Data[stateDataKey] = string(raw)
	// Ensure labels are present on updates too.
	if existing.Labels == nil {
		existing.Labels = make(map[string]string)
	}
	for k, v := range configMapLabels() {
		existing.Labels[k] = v
	}

	if _, err := s.client.CoreV1().ConfigMaps(s.namespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("updating state configmap: %w", err)
	}
	return nil
}

// LoadSnapshots reads NHI snapshots from the ConfigMap. If the ConfigMap does
// not exist (first run), it returns nil, nil.
func (s *StateStore) LoadSnapshots(ctx context.Context) ([]NHISnapshot, error) {
	cm, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting state configmap: %w", err)
	}

	raw, ok := cm.Data[stateDataKey]
	if !ok {
		return nil, nil
	}

	var sd stateData
	if err := json.Unmarshal([]byte(raw), &sd); err != nil {
		return nil, fmt.Errorf("parsing state data: %w", err)
	}
	return sd.Snapshots, nil
}
