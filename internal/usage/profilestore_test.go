package usage

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

func TestProfileStore_SaveAndLoad(t *testing.T) {
	client := fake.NewSimpleClientset()
	store := NewProfileStore(client, "nhi-system", "nhi-watch-profiles")

	ctx := context.Background()

	now := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)
	profiles := map[string]*UsageProfile{
		"default/my-sa": {
			ServiceAccount:  "my-sa",
			Namespace:       "default",
			FirstSeen:       now.Add(-48 * time.Hour),
			LastUpdated:     now,
			ObservationDays: 2,
			TotalCalls:      15,
			Records: []UsageRecord{
				{
					Verb:     "get",
					Resource: "pods",
					Count:    10,
					LastSeen: now,
				},
				{
					Verb:      "list",
					Resource:  "secrets",
					Namespace: "default",
					Count:     5,
					LastSeen:  now,
				},
			},
		},
	}

	if err := store.Save(ctx, profiles); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(loaded) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(loaded))
	}

	p, ok := loaded["default/my-sa"]
	if !ok {
		t.Fatal("expected profile key 'default/my-sa' not found")
	}

	if p.ServiceAccount != "my-sa" {
		t.Errorf("expected ServiceAccount 'my-sa', got %q", p.ServiceAccount)
	}
	if p.TotalCalls != 15 {
		t.Errorf("expected TotalCalls 15, got %d", p.TotalCalls)
	}
	if len(p.Records) != 2 {
		t.Errorf("expected 2 records, got %d", len(p.Records))
	}
	if p.Records[0].Verb != "get" || p.Records[0].Resource != "pods" {
		t.Errorf("unexpected first record: %+v", p.Records[0])
	}
	if p.Records[0].Count != 10 {
		t.Errorf("expected first record count 10, got %d", p.Records[0].Count)
	}
}

func TestProfileStore_LoadEmpty(t *testing.T) {
	client := fake.NewSimpleClientset()
	store := NewProfileStore(client, "nhi-system", "nhi-watch-profiles")

	ctx := context.Background()

	loaded, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load should not error on missing ConfigMap: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil empty map for nonexistent ConfigMap, got nil")
	}
	if len(loaded) != 0 {
		t.Fatalf("expected 0 profiles for nonexistent ConfigMap, got %d", len(loaded))
	}
}
