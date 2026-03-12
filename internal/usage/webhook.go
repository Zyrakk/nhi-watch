package usage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// auditEvent is an internal representation of a Kubernetes API server audit
// event. Only the fields needed for usage profiling are included.
type auditEvent struct {
	User              auditUser  `json:"user"`
	Verb              string     `json:"verb"`
	ObjectRef         *objectRef `json:"objectRef,omitempty"`
	RequestReceivedAt time.Time  `json:"requestReceivedTimestamp"`
}

// auditUser identifies the actor that triggered the audit event.
type auditUser struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

// objectRef identifies the Kubernetes resource targeted by the audit event.
type objectRef struct {
	Resource  string `json:"resource"`
	Namespace string `json:"namespace,omitempty"`
	APIGroup  string `json:"apiGroup,omitempty"`
}

// auditEventList wraps a batch of audit events, matching the Kubernetes
// audit.k8s.io/v1 EventList shape.
type auditEventList struct {
	Items []auditEvent `json:"items"`
}

// maxBodySize limits the request body to 10 MB to prevent resource exhaustion.
const maxBodySize = 10 * 1024 * 1024

// AuditWebhookSource receives Kubernetes API server audit events via an HTTP
// webhook and builds per-NHI usage profiles. It implements UsageDataSource.
type AuditWebhookSource struct {
	mu       sync.RWMutex
	profiles map[string]*UsageProfile // key: "namespace/serviceAccount"
	store    *ProfileStore
}

// NewAuditWebhookSource creates an AuditWebhookSource backed by the given
// ProfileStore for persistence.
func NewAuditWebhookSource(store *ProfileStore) *AuditWebhookSource {
	return &AuditWebhookSource{
		profiles: make(map[string]*UsageProfile),
		store:    store,
	}
}

// LoadExisting hydrates in-memory profiles from the ConfigMap-backed store.
// If no store was configured (nil), this is a no-op.
func (s *AuditWebhookSource) LoadExisting(ctx context.Context) error {
	if s.store == nil {
		return nil
	}
	loaded, err := s.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("loading existing profiles: %w", err)
	}
	s.mu.Lock()
	s.profiles = loaded
	s.mu.Unlock()
	return nil
}

// Handler returns an http.Handler that accepts audit webhook POST requests.
// It rejects non-POST methods with 405 and limits the request body to 10 MB.
// The handler accepts both single audit events and batches (auditEventList).
func (s *AuditWebhookSource) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}

		var events []auditEvent

		// Try batch format first.
		var list auditEventList
		if err := json.Unmarshal(body, &list); err == nil && len(list.Items) > 0 {
			events = list.Items
		} else {
			// Fall back to single event.
			var single auditEvent
			if err := json.Unmarshal(body, &single); err != nil {
				http.Error(w, "invalid audit event", http.StatusBadRequest)
				return
			}
			events = []auditEvent{single}
		}

		s.processEvents(events)
		w.WriteHeader(http.StatusOK)
	})
}

// Persist saves the current in-memory profiles to the ConfigMap-backed store.
// If no store was configured (nil), this is a no-op.
func (s *AuditWebhookSource) Persist(ctx context.Context) error {
	if s.store == nil {
		return nil
	}
	s.mu.RLock()
	snapshot := make(map[string]*UsageProfile, len(s.profiles))
	for k, v := range s.profiles {
		cp := *v
		cp.Records = make([]UsageRecord, len(v.Records))
		copy(cp.Records, v.Records)
		snapshot[k] = &cp
	}
	s.mu.RUnlock()
	return s.store.Save(ctx, snapshot)
}

// GetProfile returns the usage profile for a specific service account.
// Returns nil and no error if the service account has no recorded data.
func (s *AuditWebhookSource) GetProfile(_ context.Context, namespace, serviceAccount string) (*UsageProfile, error) {
	key := namespace + "/" + serviceAccount
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[key]
	if !ok {
		return nil, nil
	}
	cp := *p
	cp.Records = make([]UsageRecord, len(p.Records))
	copy(cp.Records, p.Records)
	return &cp, nil
}

// ListProfiles returns all known usage profiles.
func (s *AuditWebhookSource) ListProfiles(_ context.Context) ([]UsageProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]UsageProfile, 0, len(s.profiles))
	for _, p := range s.profiles {
		result = append(result, *p)
	}
	return result, nil
}

// IsAvailable reports whether this data source has any profiles loaded.
func (s *AuditWebhookSource) IsAvailable(_ context.Context) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.profiles) > 0
}

// processEvents ingests a batch of audit events, creating or updating usage
// profiles for each service account observed.
func (s *AuditWebhookSource) processEvents(events []auditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ev := range events {
		// Only process service account users.
		// Format: "system:serviceaccount:<namespace>:<name>"
		if !strings.HasPrefix(ev.User.Username, "system:serviceaccount:") {
			continue
		}
		parts := strings.SplitN(ev.User.Username, ":", 4)
		if len(parts) != 4 {
			continue
		}
		ns := parts[2]
		sa := parts[3]

		// Skip events with no object reference.
		if ev.ObjectRef == nil {
			continue
		}

		key := ns + "/" + sa
		profile, ok := s.profiles[key]
		if !ok {
			profile = &UsageProfile{
				ServiceAccount: sa,
				Namespace:      ns,
				FirstSeen:      ev.RequestReceivedAt,
			}
			s.profiles[key] = profile
		}

		now := ev.RequestReceivedAt
		if now.IsZero() {
			now = time.Now().UTC()
		}

		s.updateRecord(profile, ev)
		profile.LastUpdated = now
		profile.TotalCalls++

		// Recalculate observation days.
		if !profile.FirstSeen.IsZero() && !profile.LastUpdated.IsZero() {
			days := int(profile.LastUpdated.Sub(profile.FirstSeen).Hours() / 24)
			if days < 1 && profile.TotalCalls > 0 {
				days = 1
			}
			profile.ObservationDays = days
		}
	}
}

// updateRecord finds an existing record matching the event's
// verb+resource+apiGroup+namespace and increments its count, or appends a
// new record if no match exists.
func (s *AuditWebhookSource) updateRecord(profile *UsageProfile, ev auditEvent) {
	for i := range profile.Records {
		r := &profile.Records[i]
		if r.Verb == ev.Verb &&
			r.Resource == ev.ObjectRef.Resource &&
			r.APIGroup == ev.ObjectRef.APIGroup &&
			r.Namespace == ev.ObjectRef.Namespace {
			r.Count++
			r.LastSeen = ev.RequestReceivedAt
			return
		}
	}
	profile.Records = append(profile.Records, UsageRecord{
		Verb:      ev.Verb,
		Resource:  ev.ObjectRef.Resource,
		APIGroup:  ev.ObjectRef.APIGroup,
		Namespace: ev.ObjectRef.Namespace,
		Count:     1,
		LastSeen:  ev.RequestReceivedAt,
	})
}
