package controller

import (
	"context"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/Zyrakk/nhi-watch/internal/scoring"
)

// eventRecord stores an event name and its detail string.
type eventRecord struct {
	event  string
	detail string
}

// collectingCallback returns a callback that records all events, and a function
// to retrieve the collected events.
func collectingCallback() (EventCallback, func() []string) {
	var mu sync.Mutex
	var events []string

	cb := func(event, detail string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	}

	get := func() []string {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]string, len(events))
		copy(cp, events)
		return cp
	}

	return cb, get
}

// collectingCallbackWithDetails returns a callback that records events with their
// details, and a function to retrieve the collected records.
func collectingCallbackWithDetails() (EventCallback, func() []eventRecord) {
	var mu sync.Mutex
	var records []eventRecord

	cb := func(event, detail string) {
		mu.Lock()
		defer mu.Unlock()
		records = append(records, eventRecord{event: event, detail: detail})
	}

	get := func() []eventRecord {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]eventRecord, len(records))
		copy(cp, records)
		return cp
	}

	return cb, get
}

func TestNewController(t *testing.T) {
	client := fake.NewSimpleClientset()
	store := NewStateStore(client, "nhi-system", "nhi-watch-state")

	ctrl := NewController(client, nil, store, "", 5*time.Second, nil)
	if ctrl == nil {
		t.Fatal("expected non-nil controller")
	}
	if ctrl.client != client {
		t.Error("expected controller client to match provided client")
	}
	if ctrl.store != store {
		t.Error("expected controller store to match provided store")
	}
	if ctrl.debounceDur != 5*time.Second {
		t.Errorf("expected debounce duration 5s, got %v", ctrl.debounceDur)
	}
	if ctrl.namespace != "" {
		t.Errorf("expected empty namespace, got %q", ctrl.namespace)
	}
}

func TestController_RunScan(t *testing.T) {
	// Create a fake client with a ServiceAccount.
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-sa",
			Namespace:         "default",
			CreationTimestamp: metav1.Now(),
		},
	}

	client := fake.NewSimpleClientset(sa)
	store := NewStateStore(client, "default", "nhi-watch-state")
	cb, getEvents := collectingCallback()

	ctrl := NewController(client, nil, store, "default", 0, cb)

	ctx := context.Background()
	if err := ctrl.runScan(ctx); err != nil {
		t.Fatalf("runScan failed: %v", err)
	}

	// Verify callback received scan.starting and scan.complete events.
	events := getEvents()
	hasStarting := false
	hasComplete := false
	for _, e := range events {
		if e == "scan.starting" {
			hasStarting = true
		}
		if e == "scan.complete" {
			hasComplete = true
		}
	}
	if !hasStarting {
		t.Error("expected scan.starting event")
	}
	if !hasComplete {
		t.Error("expected scan.complete event")
	}

	// Verify state was persisted.
	snapshots, err := store.LoadSnapshots(ctx)
	if err != nil {
		t.Fatalf("LoadSnapshots: %v", err)
	}
	if snapshots == nil {
		t.Fatal("expected snapshots to be persisted, got nil")
	}

	// Should have at least 1 snapshot for the test-sa.
	found := false
	for _, snap := range snapshots {
		if snap.Name == "test-sa" && snap.Namespace == "default" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find test-sa in persisted snapshots")
	}
}

func TestController_DriftDetection(t *testing.T) {
	// Seed initial state by running a scan, then run again with different
	// data to exercise the drift detection code path (stub returns nil).
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "drift-sa",
			Namespace:         "default",
			CreationTimestamp: metav1.Now(),
		},
	}

	client := fake.NewSimpleClientset(sa)
	store := NewStateStore(client, "default", "nhi-watch-state")
	cb, getEvents := collectingCallback()

	ctrl := NewController(client, nil, store, "default", 0, cb)

	ctx := context.Background()

	// First scan: establishes baseline state.
	if err := ctrl.runScan(ctx); err != nil {
		t.Fatalf("first runScan failed: %v", err)
	}

	// Second scan: should load previous state and call detectDrift.
	// With the stub implementation, no drift events will be emitted,
	// but the code path must not panic.
	if err := ctrl.runScan(ctx); err != nil {
		t.Fatalf("second runScan failed: %v", err)
	}

	// Verify both scans completed successfully.
	events := getEvents()
	completeCount := 0
	for _, e := range events {
		if e == "scan.complete" {
			completeCount++
		}
	}
	if completeCount != 2 {
		t.Errorf("expected 2 scan.complete events, got %d", completeCount)
	}
}

func TestHashRuleResults_Deterministic(t *testing.T) {
	// {A, B} should produce the same hash as {B, A}.
	resultsAB := []scoring.RuleResult{
		{RuleID: "RULE_A"},
		{RuleID: "RULE_B"},
	}
	resultsBA := []scoring.RuleResult{
		{RuleID: "RULE_B"},
		{RuleID: "RULE_A"},
	}

	hashAB := hashRuleResults(resultsAB)
	hashBA := hashRuleResults(resultsBA)

	if hashAB != hashBA {
		t.Errorf("expected same hash for {A,B} and {B,A}, got %q vs %q", hashAB, hashBA)
	}

	// Hash should be non-empty and 16 hex chars (8 bytes).
	if len(hashAB) != 16 {
		t.Errorf("expected 16-char hex hash, got %d chars: %q", len(hashAB), hashAB)
	}
}

func TestHashRuleResults_DifferentRules(t *testing.T) {
	// {A} should produce a different hash than {B}.
	resultsA := []scoring.RuleResult{
		{RuleID: "RULE_A"},
	}
	resultsB := []scoring.RuleResult{
		{RuleID: "RULE_B"},
	}

	hashA := hashRuleResults(resultsA)
	hashB := hashRuleResults(resultsB)

	if hashA == hashB {
		t.Errorf("expected different hashes for {A} and {B}, both got %q", hashA)
	}
}

func TestController_InitialAddSuppressed(t *testing.T) {
	// Before initialSyncDone is set, Add events should be suppressed.
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-sa",
			Namespace: "default",
		},
	}

	client := fake.NewSimpleClientset()
	store := NewStateStore(client, "default", "nhi-watch-state")
	cb, getEvents := collectingCallback()

	ctrl := NewController(client, nil, store, "default", 0, cb)

	// Verify the flag is false by default.
	_ = getEvents // not needed for this part of the test
	if ctrl.initialSyncDone.Load() {
		t.Error("expected initialSyncDone to be false by default")
	}

	// Clear events and test: with flag false, the AddFunc wrapper should not call onMutation.
	cb2, getEvents2 := collectingCallbackWithDetails()
	ctrl2 := NewController(client, nil, store, "default", 0, cb2)

	// Simulate what AddFunc does.
	addFunc := func(obj interface{}) {
		if !ctrl2.initialSyncDone.Load() {
			return
		}
		ctrl2.onMutation("Added", obj)
	}

	// Call with initialSyncDone=false: should be suppressed.
	addFunc(sa)
	events2 := getEvents2()
	for _, r := range events2 {
		if r.event == "mutation.detected" {
			t.Error("expected Add to be suppressed during initial sync, but got mutation.detected")
		}
	}

	// Set initialSyncDone=true: Add should now be logged.
	ctrl2.initialSyncDone.Store(true)
	addFunc(sa)
	events2 = getEvents2()
	hasMutation := false
	for _, r := range events2 {
		if r.event == "mutation.detected" {
			hasMutation = true
			if r.detail != "Added ServiceAccount default/existing-sa" {
				t.Errorf("unexpected mutation detail: %q", r.detail)
			}
		}
	}
	if !hasMutation {
		t.Error("expected mutation.detected after initialSyncDone=true")
	}
}

func TestController_StateRecovery(t *testing.T) {
	// Simulate a restart: save state from a "previous run", then create a new
	// controller and verify it emits state.loaded on Start().
	client := fake.NewSimpleClientset(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "sa-1",
			Namespace:         "default",
			CreationTimestamp: metav1.Now(),
		},
	})
	store := NewStateStore(client, "default", "nhi-watch-state")
	ctx := context.Background()

	// Save state as if a previous run completed.
	previousSnapshots := []NHISnapshot{
		{NHIID: "sa:default:sa-1", Name: "sa-1", Namespace: "default", Type: "service-account", Score: 40, Severity: "MEDIUM"},
		{NHIID: "sa:default:sa-2", Name: "sa-2", Namespace: "default", Type: "service-account", Score: 80, Severity: "CRITICAL"},
	}
	if err := store.SaveSnapshots(ctx, previousSnapshots); err != nil {
		t.Fatalf("failed to save previous state: %v", err)
	}

	// Create a new controller (simulates restart) and start it.
	cb, getEvents := collectingCallbackWithDetails()
	ctrl := NewController(client, nil, store, "default", 5*time.Second, cb)

	// Start in a goroutine with a cancellable context since Start() blocks.
	startCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		errCh <- ctrl.Start(startCtx)
	}()

	// Give it time to start, then cancel.
	time.Sleep(500 * time.Millisecond)
	cancel()

	// Wait for Start to return.
	if err := <-errCh; err != nil && err != context.Canceled {
		t.Fatalf("Start returned unexpected error: %v", err)
	}

	// Verify state.loaded event was emitted with correct count.
	records := getEvents()
	hasStateLoaded := false
	for _, r := range records {
		if r.event == "state.loaded" {
			hasStateLoaded = true
			expected := "restored 2 findings from previous run"
			if r.detail != expected {
				t.Errorf("state.loaded detail = %q, want %q", r.detail, expected)
			}
		}
	}
	if !hasStateLoaded {
		t.Error("expected state.loaded event on restart with existing state")
	}

	// Verify no mutation.detected events from initial informer Add storm.
	for _, r := range records {
		if r.event == "mutation.detected" {
			t.Errorf("unexpected mutation.detected during restart: %q", r.detail)
		}
	}
}
