package controller

import (
	"context"
	"testing"
	"time"

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

func TestStateStore_LoadState(t *testing.T) {
	client := fake.NewSimpleClientset()
	store := NewStateStore(client, "nhi-system", "nhi-watch-state")

	ctx := context.Background()

	// LoadState returns nil for missing ConfigMap.
	sd, err := store.LoadState(ctx)
	if err != nil {
		t.Fatalf("LoadState should not error on missing ConfigMap: %v", err)
	}
	if sd != nil {
		t.Fatalf("expected nil StateData for nonexistent ConfigMap, got %+v", sd)
	}

	// Save once, then verify full StateData is returned.
	snapshots := []NHISnapshot{
		{
			NHIID:    "sa:default:admin",
			Name:     "admin",
			Score:    85,
			Severity: "CRITICAL",
		},
	}
	if err := store.SaveSnapshots(ctx, snapshots); err != nil {
		t.Fatalf("SaveSnapshots: %v", err)
	}

	sd, err = store.LoadState(ctx)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if sd == nil {
		t.Fatal("expected non-nil StateData after save")
	}

	if sd.Version != "v2" {
		t.Errorf("expected version v2, got %s", sd.Version)
	}
	if sd.LastScan == "" {
		t.Error("expected non-empty LastScan")
	}
	if sd.StartedAt == "" {
		t.Error("expected non-empty StartedAt")
	}
	if sd.ScanCount != 1 {
		t.Errorf("expected ScanCount 1, got %d", sd.ScanCount)
	}
	if len(sd.Snapshots) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(sd.Snapshots))
	}
	if sd.Snapshots[0].NHIID != "sa:default:admin" {
		t.Errorf("expected NHIID sa:default:admin, got %s", sd.Snapshots[0].NHIID)
	}
}

func TestStateStore_ScanCountIncrements(t *testing.T) {
	client := fake.NewSimpleClientset()
	store := NewStateStore(client, "nhi-system", "nhi-watch-state")

	ctx := context.Background()

	snapshots := []NHISnapshot{
		{NHIID: "sa:default:test", Name: "test"},
	}

	for i := 0; i < 3; i++ {
		if err := store.SaveSnapshots(ctx, snapshots); err != nil {
			t.Fatalf("SaveSnapshots iteration %d: %v", i+1, err)
		}
	}

	sd, err := store.LoadState(ctx)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if sd == nil {
		t.Fatal("expected non-nil StateData")
	}
	if sd.ScanCount != 3 {
		t.Errorf("expected ScanCount 3 after 3 saves, got %d", sd.ScanCount)
	}
}

func TestStateStore_StartedAtPreserved(t *testing.T) {
	client := fake.NewSimpleClientset()
	store := NewStateStore(client, "nhi-system", "nhi-watch-state")

	ctx := context.Background()

	snapshots := []NHISnapshot{
		{NHIID: "sa:default:test", Name: "test"},
	}

	// First save.
	if err := store.SaveSnapshots(ctx, snapshots); err != nil {
		t.Fatalf("first SaveSnapshots: %v", err)
	}

	sd1, err := store.LoadState(ctx)
	if err != nil {
		t.Fatalf("first LoadState: %v", err)
	}
	if sd1 == nil {
		t.Fatal("expected non-nil StateData after first save")
	}
	firstStartedAt := sd1.StartedAt

	// Verify StartedAt is a valid RFC3339 timestamp.
	if _, err := time.Parse(time.RFC3339, firstStartedAt); err != nil {
		t.Fatalf("StartedAt is not valid RFC3339: %s", firstStartedAt)
	}

	// Second save.
	if err := store.SaveSnapshots(ctx, snapshots); err != nil {
		t.Fatalf("second SaveSnapshots: %v", err)
	}

	sd2, err := store.LoadState(ctx)
	if err != nil {
		t.Fatalf("second LoadState: %v", err)
	}
	if sd2 == nil {
		t.Fatal("expected non-nil StateData after second save")
	}

	if sd2.StartedAt != firstStartedAt {
		t.Errorf("StartedAt changed: %q → %q", firstStartedAt, sd2.StartedAt)
	}
	// LastScan should have been updated (or at least still set).
	if sd2.LastScan == "" {
		t.Error("expected non-empty LastScan after second save")
	}
}
