package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestStateStore_SaveAndLoad(t *testing.T) {
	client := fake.NewSimpleClientset()
	store := NewStateStore(client, "nhi-system", "nhi-watch-state")

	snapshots := []NHISnapshot{
		{
			NHIID:     "sa:default:admin",
			Name:      "admin",
			Namespace: "default",
			Type:      "service-account",
			Score:     85,
			Severity:  "CRITICAL",
			RulesHash: "abc123",
			Timestamp: "2026-03-12T00:00:00Z",
		},
		{
			NHIID:     "sa:kube-system:coredns",
			Name:      "coredns",
			Namespace: "kube-system",
			Type:      "service-account",
			Score:     30,
			Severity:  "LOW",
			RulesHash: "def456",
			Timestamp: "2026-03-12T00:00:00Z",
		},
	}

	ctx := context.Background()

	if err := store.SaveSnapshots(ctx, snapshots); err != nil {
		t.Fatalf("SaveSnapshots: %v", err)
	}

	loaded, err := store.LoadSnapshots(ctx)
	if err != nil {
		t.Fatalf("LoadSnapshots: %v", err)
	}

	if len(loaded) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(loaded))
	}

	if loaded[0].NHIID != "sa:default:admin" {
		t.Errorf("expected NHIID sa:default:admin, got %s", loaded[0].NHIID)
	}
	if loaded[0].Score != 85 {
		t.Errorf("expected score 85, got %d", loaded[0].Score)
	}
	if loaded[1].Name != "coredns" {
		t.Errorf("expected name coredns, got %s", loaded[1].Name)
	}
	if loaded[1].Severity != "LOW" {
		t.Errorf("expected severity LOW, got %s", loaded[1].Severity)
	}
}

func TestStateStore_LoadEmpty(t *testing.T) {
	client := fake.NewSimpleClientset()
	store := NewStateStore(client, "nhi-system", "nhi-watch-state")

	ctx := context.Background()

	loaded, err := store.LoadSnapshots(ctx)
	if err != nil {
		t.Fatalf("LoadSnapshots should not error on missing ConfigMap: %v", err)
	}
	if loaded != nil {
		t.Fatalf("expected nil snapshots for nonexistent ConfigMap, got %v", loaded)
	}
}

func TestStateStore_UpdateExisting(t *testing.T) {
	client := fake.NewSimpleClientset()
	store := NewStateStore(client, "nhi-system", "nhi-watch-state")

	ctx := context.Background()

	// First save.
	initial := []NHISnapshot{
		{
			NHIID:    "sa:default:admin",
			Name:     "admin",
			Score:    85,
			Severity: "CRITICAL",
		},
	}
	if err := store.SaveSnapshots(ctx, initial); err != nil {
		t.Fatalf("first SaveSnapshots: %v", err)
	}

	// Second save with different data.
	updated := []NHISnapshot{
		{
			NHIID:    "sa:default:viewer",
			Name:     "viewer",
			Score:    20,
			Severity: "LOW",
		},
		{
			NHIID:    "sa:default:editor",
			Name:     "editor",
			Score:    55,
			Severity: "MEDIUM",
		},
	}
	if err := store.SaveSnapshots(ctx, updated); err != nil {
		t.Fatalf("second SaveSnapshots: %v", err)
	}

	loaded, err := store.LoadSnapshots(ctx)
	if err != nil {
		t.Fatalf("LoadSnapshots: %v", err)
	}

	if len(loaded) != 2 {
		t.Fatalf("expected 2 snapshots after update, got %d", len(loaded))
	}
	if loaded[0].NHIID != "sa:default:viewer" {
		t.Errorf("expected NHIID sa:default:viewer, got %s", loaded[0].NHIID)
	}
	if loaded[1].Score != 55 {
		t.Errorf("expected score 55, got %d", loaded[1].Score)
	}
}

func TestStateStore_ConfigMapLabels(t *testing.T) {
	client := fake.NewSimpleClientset()
	store := NewStateStore(client, "nhi-system", "nhi-watch-state")

	ctx := context.Background()

	snapshots := []NHISnapshot{
		{
			NHIID: "sa:default:test",
			Name:  "test",
		},
	}
	if err := store.SaveSnapshots(ctx, snapshots); err != nil {
		t.Fatalf("SaveSnapshots: %v", err)
	}

	cm, err := client.CoreV1().ConfigMaps("nhi-system").Get(ctx, "nhi-watch-state", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting ConfigMap directly: %v", err)
	}

	expectedLabels := map[string]string{
		"app.kubernetes.io/name":      "nhi-watch",
		"app.kubernetes.io/component": "controller-state",
	}

	for key, want := range expectedLabels {
		got, ok := cm.Labels[key]
		if !ok {
			t.Errorf("missing label %s", key)
			continue
		}
		if got != want {
			t.Errorf("label %s: expected %q, got %q", key, want, got)
		}
	}
}
