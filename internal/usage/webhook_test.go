package usage

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

func newTestSource() *AuditWebhookSource {
	client := fake.NewSimpleClientset()
	store := NewProfileStore(client, "nhi-system", "nhi-watch-profiles")
	return NewAuditWebhookSource(store)
}

func TestAuditWebhookSource_Handler_SingleEvent(t *testing.T) {
	src := newTestSource()
	handler := src.Handler()

	now := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)
	event := auditEvent{
		User: auditUser{
			Username: "system:serviceaccount:default:my-sa",
		},
		Verb: "get",
		ObjectRef: &objectRef{
			Resource:  "pods",
			Namespace: "default",
		},
		RequestReceivedAt: now,
	}

	body, _ := json.Marshal(event)
	req := httptest.NewRequest(http.MethodPost, "/audit", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	ctx := context.Background()
	profile, err := src.GetProfile(ctx, "default", "my-sa")
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if profile == nil {
		t.Fatal("expected profile to be created, got nil")
	}
	if profile.ServiceAccount != "my-sa" {
		t.Errorf("expected ServiceAccount 'my-sa', got %q", profile.ServiceAccount)
	}
	if profile.Namespace != "default" {
		t.Errorf("expected Namespace 'default', got %q", profile.Namespace)
	}
	if len(profile.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(profile.Records))
	}
	if profile.Records[0].Verb != "get" {
		t.Errorf("expected verb 'get', got %q", profile.Records[0].Verb)
	}
	if profile.Records[0].Resource != "pods" {
		t.Errorf("expected resource 'pods', got %q", profile.Records[0].Resource)
	}
	if profile.Records[0].Count != 1 {
		t.Errorf("expected count 1, got %d", profile.Records[0].Count)
	}
	if profile.TotalCalls != 1 {
		t.Errorf("expected TotalCalls 1, got %d", profile.TotalCalls)
	}
}

func TestAuditWebhookSource_Handler_BatchEvents(t *testing.T) {
	src := newTestSource()
	handler := src.Handler()

	now := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)
	batch := auditEventList{
		Items: []auditEvent{
			{
				User: auditUser{Username: "system:serviceaccount:default:sa1"},
				Verb: "get",
				ObjectRef: &objectRef{
					Resource:  "pods",
					Namespace: "default",
				},
				RequestReceivedAt: now,
			},
			{
				User: auditUser{Username: "system:serviceaccount:default:sa1"},
				Verb: "get",
				ObjectRef: &objectRef{
					Resource:  "pods",
					Namespace: "default",
				},
				RequestReceivedAt: now.Add(time.Second),
			},
			{
				User: auditUser{Username: "system:serviceaccount:kube-system:sa2"},
				Verb: "list",
				ObjectRef: &objectRef{
					Resource:  "secrets",
					Namespace: "kube-system",
				},
				RequestReceivedAt: now,
			},
		},
	}

	body, _ := json.Marshal(batch)
	req := httptest.NewRequest(http.MethodPost, "/audit", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	ctx := context.Background()

	// Verify sa1: 2 events for the same verb+resource should aggregate into 1 record with count=2.
	p1, err := src.GetProfile(ctx, "default", "sa1")
	if err != nil {
		t.Fatalf("GetProfile sa1: %v", err)
	}
	if p1 == nil {
		t.Fatal("expected sa1 profile, got nil")
	}
	if len(p1.Records) != 1 {
		t.Fatalf("expected 1 aggregated record for sa1, got %d", len(p1.Records))
	}
	if p1.Records[0].Count != 2 {
		t.Errorf("expected sa1 record count 2, got %d", p1.Records[0].Count)
	}
	if p1.TotalCalls != 2 {
		t.Errorf("expected sa1 TotalCalls 2, got %d", p1.TotalCalls)
	}

	// Verify sa2: 1 event should produce 1 record.
	p2, err := src.GetProfile(ctx, "kube-system", "sa2")
	if err != nil {
		t.Fatalf("GetProfile sa2: %v", err)
	}
	if p2 == nil {
		t.Fatal("expected sa2 profile, got nil")
	}
	if p2.Records[0].Resource != "secrets" {
		t.Errorf("expected sa2 resource 'secrets', got %q", p2.Records[0].Resource)
	}
	if p2.TotalCalls != 1 {
		t.Errorf("expected sa2 TotalCalls 1, got %d", p2.TotalCalls)
	}
}

func TestAuditWebhookSource_IgnoresNonSA(t *testing.T) {
	src := newTestSource()
	handler := src.Handler()

	event := auditEvent{
		User: auditUser{Username: "admin"},
		Verb: "get",
		ObjectRef: &objectRef{
			Resource:  "pods",
			Namespace: "default",
		},
		RequestReceivedAt: time.Now(),
	}

	body, _ := json.Marshal(event)
	req := httptest.NewRequest(http.MethodPost, "/audit", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	ctx := context.Background()
	profiles, err := src.ListProfiles(ctx)
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles for non-SA user, got %d", len(profiles))
	}
}

func TestAuditWebhookSource_MethodNotAllowed(t *testing.T) {
	src := newTestSource()
	handler := src.Handler()

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rr.Code)
	}
}

func TestAuditWebhookSource_ListProfiles(t *testing.T) {
	src := newTestSource()

	now := time.Now().UTC()
	src.mu.Lock()
	src.profiles["default/sa-a"] = &UsageProfile{
		ServiceAccount:  "sa-a",
		Namespace:       "default",
		FirstSeen:       now,
		LastUpdated:     now,
		ObservationDays: 10,
		TotalCalls:      50,
		Records: []UsageRecord{
			{Verb: "get", Resource: "configmaps", Count: 50, LastSeen: now},
		},
	}
	src.profiles["kube-system/sa-b"] = &UsageProfile{
		ServiceAccount:  "sa-b",
		Namespace:       "kube-system",
		FirstSeen:       now,
		LastUpdated:     now,
		ObservationDays: 5,
		TotalCalls:      20,
	}
	src.mu.Unlock()

	ctx := context.Background()
	profiles, err := src.ListProfiles(ctx)
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}

	// Verify both SAs are present (map iteration order is non-deterministic).
	found := map[string]bool{}
	for _, p := range profiles {
		found[p.Namespace+"/"+p.ServiceAccount] = true
	}
	if !found["default/sa-a"] {
		t.Error("expected profile for default/sa-a")
	}
	if !found["kube-system/sa-b"] {
		t.Error("expected profile for kube-system/sa-b")
	}
}

func TestAuditWebhookSource_IsAvailable(t *testing.T) {
	src := newTestSource()
	ctx := context.Background()

	// Empty source should not be available.
	if src.IsAvailable(ctx) {
		t.Error("expected IsAvailable=false for empty source")
	}

	// Add a profile — should become available.
	src.mu.Lock()
	src.profiles["default/test-sa"] = &UsageProfile{
		ServiceAccount: "test-sa",
		Namespace:      "default",
		TotalCalls:     1,
	}
	src.mu.Unlock()

	if !src.IsAvailable(ctx) {
		t.Error("expected IsAvailable=true after adding a profile")
	}
}
