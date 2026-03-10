# NHI-Watch v1.0 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete NHI-Watch v1.0 — a CLI auditor that discovers, scores, and reports on Non-Human Identity risks in Kubernetes/OpenShift clusters, with CI/CD integration, remediation guidance, and Gatekeeper policy export.

**Architecture:** Extends the existing pipeline (Discover → Resolve RBAC → Score → Report) with a new workload posture enrichment phase between RBAC resolution and scoring. Pod security context and OpenShift SCC data feed into the scoring engine as a risk multiplier. Output is handled by a dedicated reporter package supporting table/JSON/SARIF formats. Baseline save/load enables incremental CI/CD adoption.

**Tech Stack:** Go 1.22+, client-go v0.31.1, Cobra CLI, OPA/Gatekeeper ConstraintTemplate CRDs, SARIF v2.1.0 JSON schema.

**Existing codebase state:** Phases 0-3 complete. Discovery (ServiceAccounts, Secrets, TLS certs, cert-manager CRDs), RBAC chain resolution (7 overprivilege patterns), and scoring engine (16 deterministic rules) are implemented with tests.

---

## Task 1: CIS Kubernetes Benchmark Mapping

**Purpose:** Add CIS control references to every scoring rule. Low effort, high audit credibility.

**Files:**
- Modify: `internal/scoring/engine.go` — add `CISControls` field to `Rule` and `RuleResult` structs
- Modify: `internal/scoring/rules.go` — populate CIS mapping for all 16 rules
- Test: `internal/scoring/rules_test.go` — verify every rule has CIS mapping (or explicitly empty)

**Step 1: Add CISControls field to Rule and RuleResult structs**

In `internal/scoring/engine.go`, add to `Rule`:

```go
type Rule struct {
	ID          string
	Description string
	Severity    Severity
	Score       int
	AppliesTo   []discovery.NHIType
	CISControls []string // CIS Kubernetes Benchmark controls (e.g., "5.1.2")
	Evaluate    func(nhi *discovery.NonHumanIdentity) (bool, string)
}
```

Add to `RuleResult`:

```go
type RuleResult struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Score       int      `json:"score"`
	Matched     bool     `json:"matched"`
	Detail      string   `json:"detail,omitempty"`
	CISControls []string `json:"cis_controls,omitempty"`
}
```

Update `Score()` method to propagate `CISControls` into each `RuleResult`.

**Step 2: Write test verifying CIS mapping exists**

In `internal/scoring/rules_test.go`, add:

```go
func TestAllRulesHaveCISMapping(t *testing.T) {
	rules := DefaultRules()
	rulesWithCIS := map[string]bool{
		"CLUSTER_ADMIN_BINDING":        true, // 5.1.1
		"WILDCARD_PERMISSIONS":         true, // 5.1.3
		"DEFAULT_SA_HAS_BINDINGS":      true, // 5.1.5
		"SECRET_ACCESS_CLUSTER_WIDE":   true, // 5.1.2
		"CROSS_NAMESPACE_SECRET_ACCESS":true, // 5.1.2
		"AUTOMOUNT_TOKEN_ENABLED":      true, // 5.1.6
		"NO_BINDINGS_BUT_AUTOMOUNT":    true, // 5.1.6
		"CONTAINS_PRIVATE_KEY":         true, // 5.4.1
	}
	for _, rule := range rules {
		if rulesWithCIS[rule.ID] {
			if len(rule.CISControls) == 0 {
				t.Errorf("Rule %s should have CIS controls mapped", rule.ID)
			}
		}
	}
}
```

**Step 3: Run test, verify it fails**

Run: `go test ./internal/scoring/ -run TestAllRulesHaveCISMapping -v`
Expected: FAIL — no rule has CIS controls yet.

**Step 4: Populate CIS mapping in rules.go**

Add `CISControls` to each rule in `DefaultRules()`:

| Rule ID | CIS Controls |
|---------|-------------|
| CLUSTER_ADMIN_BINDING | 5.1.1 |
| WILDCARD_PERMISSIONS | 5.1.3 |
| DEFAULT_SA_HAS_BINDINGS | 5.1.5 |
| SECRET_ACCESS_CLUSTER_WIDE | 5.1.2 |
| CROSS_NAMESPACE_SECRET_ACCESS | 5.1.2 |
| AUTOMOUNT_TOKEN_ENABLED | 5.1.6 |
| NO_BINDINGS_BUT_AUTOMOUNT | 5.1.6 |
| SECRET_NOT_ROTATED_180D | (none — no direct CIS control) |
| SECRET_NOT_ROTATED_90D | (none) |
| TLS_CERT_EXPIRED | (none) |
| TLS_CERT_EXPIRES_30D | (none) |
| TLS_CERT_EXPIRES_90D | (none) |
| CONTAINS_PRIVATE_KEY | 5.4.1 |
| CERT_NOT_READY | (none) |
| CERT_EXPIRES_30D | (none) |
| CERT_EXPIRES_90D | (none) |

**Step 5: Run test, verify it passes**

Run: `go test ./internal/scoring/ -run TestAllRulesHaveCISMapping -v`
Expected: PASS

**Step 6: Run all tests**

Run: `go test -race ./...`
Expected: All existing tests still pass.

**Step 7: Commit**

```bash
git add internal/scoring/engine.go internal/scoring/rules.go internal/scoring/rules_test.go
git commit -m "feat(scoring): add CIS Kubernetes Benchmark mapping to scoring rules"
```

---

## Task 2: Pod Posture Discovery

**Purpose:** Discover which pods reference each ServiceAccount and inspect their securityContext. This feeds the risk multiplier in Task 3.

**Files:**
- Modify: `internal/discovery/types.go` — add `PodPosture` struct and field on `NonHumanIdentity`
- Create: `internal/discovery/pods.go` — pod posture discovery functions
- Create: `internal/discovery/pods_test.go` — tests with fake clientset
- Modify: `internal/discovery/discover.go` — wire pod discovery into `DiscoverAll()`

**Step 1: Define PodPosture type**

In `internal/discovery/types.go`, add:

```go
type PodPosture struct {
	PodName     string `json:"pod_name"`
	Namespace   string `json:"namespace"`
	Privileged  bool   `json:"privileged"`
	RunAsRoot   bool   `json:"run_as_root"`
	HostNetwork bool   `json:"host_network"`
	HostPID     bool   `json:"host_pid"`
	HostIPC     bool   `json:"host_ipc"`
	HostPath    bool   `json:"host_path"`
}
```

Add to `NonHumanIdentity`:

```go
type NonHumanIdentity struct {
	// ... existing fields ...
	PodPostures []PodPosture `json:"pod_postures,omitempty"`
}
```

**Step 2: Write failing tests for pod posture discovery**

Create `internal/discovery/pods_test.go`:

```go
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
```

**Step 3: Run tests, verify they fail**

Run: `go test ./internal/discovery/ -run TestDiscoverPodPostures -v`
Expected: FAIL — `DiscoverPodPostures` not defined.

**Step 4: Implement pod posture discovery**

Create `internal/discovery/pods.go`:

```go
package discovery

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DiscoverPodPostures returns a map of "namespace/saName" → []PodPosture.
// If namespace is empty, all namespaces are scanned.
func DiscoverPodPostures(ctx context.Context, client kubernetes.Interface, namespace string) (map[string][]PodPosture, error) {
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}

	result := make(map[string][]PodPosture)
	for _, pod := range pods.Items {
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		key := fmt.Sprintf("%s/%s", pod.Namespace, saName)
		posture := extractPodPosture(pod)
		result[key] = append(result[key], posture)
	}
	return result, nil
}

func extractPodPosture(pod corev1.Pod) PodPosture {
	p := PodPosture{
		PodName:     pod.Name,
		Namespace:   pod.Namespace,
		HostNetwork: pod.Spec.HostNetwork,
		HostPID:     pod.Spec.HostPID,
		HostIPC:     pod.Spec.HostIPC,
		HostPath:    hasHostPathVolume(pod.Spec.Volumes),
	}

	// Check pod-level security context
	if psc := pod.Spec.SecurityContext; psc != nil {
		if psc.RunAsUser != nil && *psc.RunAsUser == 0 {
			p.RunAsRoot = true
		}
	}

	// Check container-level security contexts
	for _, c := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
		if c.SecurityContext == nil {
			continue
		}
		if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			p.Privileged = true
		}
		if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
			p.RunAsRoot = true
		}
	}

	return p
}

func hasHostPathVolume(volumes []corev1.Volume) bool {
	for _, v := range volumes {
		if v.HostPath != nil {
			return true
		}
	}
	return false
}
```

**Step 5: Run tests, verify they pass**

Run: `go test ./internal/discovery/ -run TestDiscoverPodPostures -v`
Expected: PASS

**Step 6: Wire into DiscoverAll**

In `internal/discovery/discover.go`, add pod posture discovery as a parallel phase in `DiscoverAll()`. After all NHIs are collected, enrich ServiceAccount NHIs with their pod postures:

```go
// Inside DiscoverAll, after all discovery phases complete:
// Enrich ServiceAccounts with pod posture data
postures, err := DiscoverPodPostures(ctx, clients.Clientset, namespace)
if err != nil {
    // Non-fatal: log warning, continue without posture data
}
for i := range result.Identities {
    nhi := &result.Identities[i]
    if nhi.Type == string(NHITypeServiceAccount) {
        key := fmt.Sprintf("%s/%s", nhi.Namespace, nhi.Name)
        if p, ok := postures[key]; ok {
            nhi.PodPostures = p
        }
    }
}
```

**Step 7: Run all tests**

Run: `go test -race ./...`
Expected: All tests pass.

**Step 8: Commit**

```bash
git add internal/discovery/types.go internal/discovery/pods.go internal/discovery/pods_test.go internal/discovery/discover.go
git commit -m "feat(discovery): add pod posture discovery for SA workload security context"
```

---

## Task 3: Pod Security Risk Multiplier

**Purpose:** Factor pod security posture into risk scoring as a multiplier on the base score. A cluster-admin SA in a privileged pod is worse than the same SA in a restricted pod.

**Files:**
- Modify: `internal/scoring/engine.go` — add multiplier calculation and fields to `ScoringResult`
- Create: `internal/scoring/posture.go` — multiplier logic
- Create: `internal/scoring/posture_test.go` — tests
- Modify: `internal/scoring/engine_test.go` — update existing tests for new fields

**Step 1: Write failing tests for posture multiplier**

Create `internal/scoring/posture_test.go`:

```go
package scoring

import (
	"testing"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
)

func TestCalculatePostureMultiplier_NoPods(t *testing.T) {
	m := CalculatePostureMultiplier(nil)
	if m != 1.0 {
		t.Errorf("expected 1.0, got %f", m)
	}
}

func TestCalculatePostureMultiplier_RestrictedPod(t *testing.T) {
	postures := []discovery.PodPosture{{PodName: "safe", Namespace: "default"}}
	m := CalculatePostureMultiplier(postures)
	if m != 1.0 {
		t.Errorf("expected 1.0 for restricted pod, got %f", m)
	}
}

func TestCalculatePostureMultiplier_PrivilegedPod(t *testing.T) {
	postures := []discovery.PodPosture{{
		PodName:    "evil",
		Namespace:  "default",
		Privileged: true,
	}}
	m := CalculatePostureMultiplier(postures)
	if m <= 1.0 {
		t.Errorf("expected >1.0 for privileged pod, got %f", m)
	}
}

func TestCalculatePostureMultiplier_FullHostAccess(t *testing.T) {
	postures := []discovery.PodPosture{{
		PodName:     "worst",
		Namespace:   "default",
		Privileged:  true,
		HostPID:     true,
		HostNetwork: true,
		HostPath:    true,
		RunAsRoot:   true,
	}}
	m := CalculatePostureMultiplier(postures)
	// Should be the highest possible multiplier
	if m < 1.3 {
		t.Errorf("expected >=1.3 for full host access, got %f", m)
	}
}

func TestCalculatePostureMultiplier_WorstPodWins(t *testing.T) {
	postures := []discovery.PodPosture{
		{PodName: "safe", Namespace: "default"},
		{PodName: "bad", Namespace: "default", Privileged: true},
	}
	m := CalculatePostureMultiplier(postures)
	if m <= 1.0 {
		t.Error("should use worst pod, not average")
	}
}

func TestApplyMultiplier_CappedAt100(t *testing.T) {
	score := applyMultiplier(95, 1.3)
	if score > 100 {
		t.Errorf("score should be capped at 100, got %d", score)
	}
	if score != 100 {
		t.Errorf("expected 100, got %d", score)
	}
}

func TestApplyMultiplier_NoChange(t *testing.T) {
	score := applyMultiplier(60, 1.0)
	if score != 60 {
		t.Errorf("expected 60, got %d", score)
	}
}
```

**Step 2: Run tests, verify they fail**

Run: `go test ./internal/scoring/ -run TestCalculatePostureMultiplier -v`
Expected: FAIL

**Step 3: Implement posture multiplier**

Create `internal/scoring/posture.go`:

```go
package scoring

import (
	"math"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
)

// CalculatePostureMultiplier returns a risk multiplier based on the worst
// pod security posture among all pods referencing an NHI.
// Returns 1.0 if no pods or all pods are restricted.
func CalculatePostureMultiplier(postures []discovery.PodPosture) float64 {
	if len(postures) == 0 {
		return 1.0
	}
	worst := 1.0
	for _, p := range postures {
		m := 1.0
		if p.Privileged {
			m += 0.20
		}
		if p.HostPID {
			m += 0.10
		}
		if p.HostNetwork {
			m += 0.05
		}
		if p.HostIPC {
			m += 0.05
		}
		if p.HostPath {
			m += 0.05
		}
		if p.RunAsRoot {
			m += 0.05
		}
		if m > worst {
			worst = m
		}
	}
	return worst
}

func applyMultiplier(baseScore int, multiplier float64) int {
	result := int(math.Round(float64(baseScore) * multiplier))
	if result > 100 {
		return 100
	}
	return result
}
```

**Step 4: Update ScoringResult and Engine.Score()**

In `internal/scoring/engine.go`, add to `ScoringResult`:

```go
type ScoringResult struct {
	// ... existing fields ...
	BaseScore         int     `json:"base_score"`
	PostureMultiplier float64 `json:"posture_multiplier"`
	PostureDetail     string  `json:"posture_detail,omitempty"`
}
```

Update `Score()` to:
1. Calculate base score as before (max of matching rules)
2. Call `CalculatePostureMultiplier(nhi.PodPostures)`
3. Set `FinalScore = applyMultiplier(baseScore, multiplier)`
4. Recalculate `FinalSeverity` from the adjusted score

**Step 5: Run tests, verify they pass**

Run: `go test -race ./internal/scoring/ -v`
Expected: All tests pass (new and existing).

**Step 6: Commit**

```bash
git add internal/scoring/posture.go internal/scoring/posture_test.go internal/scoring/engine.go internal/scoring/engine_test.go
git commit -m "feat(scoring): add pod security posture risk multiplier"
```

---

## Task 4: OpenShift Auto-Detection and SCC Analysis

**Purpose:** Auto-detect OpenShift clusters and analyze SecurityContextConstraints as an extension of pod posture.

**Files:**
- Modify: `internal/k8s/client.go` — add `IsOpenShift()` method
- Create: `internal/discovery/openshift.go` — SCC discovery
- Create: `internal/discovery/openshift_test.go` — tests
- Modify: `internal/discovery/pods.go` — enrich PodPosture with SCC name
- Modify: `internal/discovery/types.go` — add SCC field to PodPosture

**Step 1: Add SCC field to PodPosture**

In `internal/discovery/types.go`:

```go
type PodPosture struct {
	// ... existing fields ...
	SCCName string `json:"scc_name,omitempty"` // OpenShift SecurityContextConstraint
}
```

**Step 2: Implement OpenShift detection**

In `internal/k8s/client.go`, add:

```go
// IsOpenShift checks if the cluster is OpenShift by looking for the
// security.openshift.io API group.
func (c *Clients) IsOpenShift() bool {
	groups, err := c.Discovery.ServerGroups()
	if err != nil {
		return false
	}
	for _, g := range groups.Groups {
		if g.Name == "security.openshift.io" {
			return true
		}
	}
	return false
}
```

**Step 3: Write failing tests for SCC enrichment**

Create `internal/discovery/openshift_test.go`:

```go
package discovery

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestEnrichWithSCC_AnnotationPresent(t *testing.T) {
	pod := corev1.Pod{}
	pod.Annotations = map[string]string{
		"openshift.io/scc": "privileged",
	}
	posture := PodPosture{PodName: "test"}
	enrichWithSCC(&posture, pod)
	if posture.SCCName != "privileged" {
		t.Errorf("expected SCCName=privileged, got %s", posture.SCCName)
	}
}

func TestEnrichWithSCC_NoAnnotation(t *testing.T) {
	pod := corev1.Pod{}
	posture := PodPosture{PodName: "test"}
	enrichWithSCC(&posture, pod)
	if posture.SCCName != "" {
		t.Errorf("expected empty SCCName, got %s", posture.SCCName)
	}
}

func TestSCCIsPrivileged(t *testing.T) {
	tests := []struct {
		scc  string
		want bool
	}{
		{"privileged", true},
		{"anyuid", true},
		{"restricted", false},
		{"restricted-v2", false},
		{"nonroot", false},
		{"nonroot-v2", false},
		{"hostaccess", true},
		{"hostnetwork", true},
		{"", false},
	}
	for _, tt := range tests {
		if got := sccIsPrivileged(tt.scc); got != tt.want {
			t.Errorf("sccIsPrivileged(%q) = %v, want %v", tt.scc, got, tt.want)
		}
	}
}
```

**Step 4: Run tests, verify they fail**

Run: `go test ./internal/discovery/ -run TestEnrichWithSCC -v`
Run: `go test ./internal/discovery/ -run TestSCCIsPrivileged -v`
Expected: FAIL

**Step 5: Implement SCC enrichment**

Create `internal/discovery/openshift.go`:

```go
package discovery

import (
	corev1 "k8s.io/api/core/v1"
)

const sccAnnotation = "openshift.io/scc"

// enrichWithSCC reads the SCC annotation from a pod and enriches the posture.
func enrichWithSCC(posture *PodPosture, pod corev1.Pod) {
	if pod.Annotations == nil {
		return
	}
	posture.SCCName = pod.Annotations[sccAnnotation]
}

// sccIsPrivileged returns true for SCCs that grant elevated privileges.
func sccIsPrivileged(scc string) bool {
	switch scc {
	case "privileged", "anyuid", "hostaccess", "hostnetwork", "hostmount-anyuid":
		return true
	}
	return false
}
```

**Step 6: Wire SCC enrichment into extractPodPosture**

In `internal/discovery/pods.go`, update `extractPodPosture()` to call `enrichWithSCC()`:

```go
func extractPodPosture(pod corev1.Pod) PodPosture {
	p := PodPosture{
		// ... existing logic ...
	}
	// OpenShift SCC enrichment (safe on vanilla K8s — annotation just won't exist)
	enrichWithSCC(&p, pod)
	return p
}
```

**Step 7: Update posture multiplier to consider SCC**

In `internal/scoring/posture.go`, add SCC consideration:

```go
// In CalculatePostureMultiplier, after checking container fields:
if p.SCCName != "" && sccIsPrivileged(p.SCCName) {
    m += 0.15
}
```

Note: Import `discovery` package's `sccIsPrivileged` or duplicate the logic in the scoring package. Prefer keeping it in discovery and exposing it with a capital letter (`SCCIsPrivileged`).

**Step 8: Run all tests**

Run: `go test -race ./...`
Expected: All pass.

**Step 9: Commit**

```bash
git add internal/k8s/client.go internal/discovery/openshift.go internal/discovery/openshift_test.go internal/discovery/pods.go internal/discovery/types.go internal/scoring/posture.go
git commit -m "feat(openshift): add auto-detection and SCC analysis for pod posture"
```

---

## Task 5: Reporter Package

**Purpose:** Refactor output generation into a dedicated reporter package supporting table, JSON, and SARIF formats. Currently output logic is inline in CLI commands.

**Files:**
- Rewrite: `internal/reporter/reporter.go` — define interface and types
- Create: `internal/reporter/table.go` — table format
- Create: `internal/reporter/json.go` — JSON format
- Create: `internal/reporter/sarif.go` — SARIF v2.1.0 format
- Create: `internal/reporter/table_test.go`
- Create: `internal/reporter/json_test.go`
- Create: `internal/reporter/sarif_test.go`
- Modify: `internal/cli/audit.go` — use reporter instead of inline rendering

### Step 1: Define reporter interface and types

Rewrite `internal/reporter/reporter.go`:

```go
package reporter

import (
	"github.com/Zyrakk/nhi-watch/internal/scoring"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

type AuditReport struct {
	ClusterName string
	Timestamp   string
	Results     []scoring.ScoringResult
	Summary     ReportSummary
}

type ReportSummary struct {
	TotalNHIs    int            `json:"total_nhis"`
	TotalFindings int           `json:"total_findings"`
	BySeverity   map[string]int `json:"by_severity"`
}

type Reporter interface {
	Render(report *AuditReport) ([]byte, error)
}

func New(format Format) Reporter {
	switch format {
	case FormatJSON:
		return &JSONReporter{}
	case FormatSARIF:
		return &SARIFReporter{}
	default:
		return &TableReporter{}
	}
}
```

### Step 2: Implement and test JSON reporter

Create `internal/reporter/json.go`:

```go
package reporter

import "encoding/json"

type JSONReporter struct{}

type jsonOutput struct {
	ClusterName string                  `json:"cluster_name"`
	Timestamp   string                  `json:"timestamp"`
	Summary     ReportSummary           `json:"summary"`
	Findings    []jsonFinding           `json:"findings"`
}

type jsonFinding struct {
	NHIID             string   `json:"nhi_id"`
	Name              string   `json:"name"`
	Namespace         string   `json:"namespace"`
	Type              string   `json:"type"`
	Score             int      `json:"score"`
	Severity          string   `json:"severity"`
	BaseScore         int      `json:"base_score"`
	PostureMultiplier float64  `json:"posture_multiplier"`
	MatchedRules      []string `json:"matched_rules"`
	CISControls       []string `json:"cis_controls,omitempty"`
	Recommendation    string   `json:"recommendation"`
}

func (r *JSONReporter) Render(report *AuditReport) ([]byte, error) {
	// Convert ScoringResults to jsonFindings
	// Marshal with json.MarshalIndent
}
```

Create `internal/reporter/json_test.go`:

```go
func TestJSONReporter_ValidJSON(t *testing.T) {
	report := makeTestReport()
	r := &JSONReporter{}
	out, err := r.Render(report)
	if err != nil {
		t.Fatal(err)
	}
	var parsed jsonOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed.ClusterName != "test-cluster" {
		t.Error("cluster name mismatch")
	}
	if len(parsed.Findings) != len(report.Results) {
		t.Error("finding count mismatch")
	}
}
```

### Step 3: Implement and test Table reporter

Create `internal/reporter/table.go` — extract table rendering from current `internal/cli/audit.go`. Use `fmt.Fprintf` with tabwriter or manual padding (matching the existing style in CLI commands).

Create `internal/reporter/table_test.go`:

```go
func TestTableReporter_ContainsSeverity(t *testing.T) {
	report := makeTestReport()
	r := &TableReporter{}
	out, err := r.Render(report)
	if err != nil {
		t.Fatal(err)
	}
	output := string(out)
	if !strings.Contains(output, "CRITICAL") {
		t.Error("expected CRITICAL in table output")
	}
}
```

### Step 4: Implement and test SARIF reporter

Create `internal/reporter/sarif.go`. SARIF v2.1.0 schema:

```go
package reporter

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string           `json:"name"`
	Version        string           `json:"version"`
	InformationURI string           `json:"informationUri"`
	Rules          []sarifRuleDef   `json:"rules"`
}

type sarifRuleDef struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Tags []string `json:"tags,omitempty"` // CIS controls go here
}

type sarifResult struct {
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"` // error, warning, note
	Message   sarifMessage   `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"` // "namespace", "resource"
}
```

Severity → SARIF level mapping:
- CRITICAL/HIGH → "error"
- MEDIUM → "warning"
- LOW/INFO → "note"

Create `internal/reporter/sarif_test.go`:

```go
func TestSARIFReporter_ValidSchema(t *testing.T) {
	report := makeTestReport()
	r := &SARIFReporter{}
	out, err := r.Render(report)
	if err != nil {
		t.Fatal(err)
	}
	var sarif sarifLog
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("expected SARIF 2.1.0, got %s", sarif.Version)
	}
	if sarif.Runs[0].Tool.Driver.Name != "nhi-watch" {
		t.Error("expected tool name nhi-watch")
	}
}

func TestSARIFReporter_SeverityMapping(t *testing.T) {
	// Test CRITICAL → "error", MEDIUM → "warning", LOW → "note"
}

func TestSARIFReporter_CISInTags(t *testing.T) {
	// Verify CIS controls appear in rule properties.tags
}
```

### Step 5: Refactor CLI audit command

Update `internal/cli/audit.go` to use the reporter package instead of inline rendering. The `--output/-o` flag values change to "table", "json", "sarif" (drop "markdown" support for now).

### Step 6: Run all tests

Run: `go test -race ./...`
Expected: All pass.

### Step 7: Commit

```bash
git add internal/reporter/ internal/cli/audit.go
git commit -m "feat(reporter): add table, JSON, SARIF reporters with CLI integration"
```

---

## Task 6: Baseline Save/Load/Diff

**Purpose:** Enable incremental CI/CD adoption by comparing current scan results against a saved baseline. Only new or regressed findings trigger failures.

**Files:**
- Create: `internal/baseline/baseline.go` — save, load, diff logic
- Create: `internal/baseline/baseline_test.go` — tests
- Modify: `internal/cli/audit.go` — add `--save-baseline` and `--baseline` flags

**Step 1: Write failing tests**

Create `internal/baseline/baseline_test.go`:

```go
package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Zyrakk/nhi-watch/internal/scoring"
)

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	results := []scoring.ScoringResult{
		{NHIID: "abc123", Name: "admin-sa", Namespace: "default",
			FinalScore: 95, FinalSeverity: scoring.SeverityCritical},
	}

	if err := Save(path, results, "test-cluster"); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ClusterName != "test-cluster" {
		t.Error("cluster name mismatch")
	}
	if len(loaded.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(loaded.Findings))
	}
}

func TestDiff_NewFinding(t *testing.T) {
	bl := &Baseline{
		Findings: map[string]BaselineFinding{
			"abc123": {NHIID: "abc123", Score: 95, Severity: "CRITICAL"},
		},
	}
	current := []scoring.ScoringResult{
		{NHIID: "abc123", FinalScore: 95, FinalSeverity: scoring.SeverityCritical},
		{NHIID: "def456", FinalScore: 80, FinalSeverity: scoring.SeverityHigh},
	}
	diff := Diff(current, bl)
	if len(diff.New) != 1 {
		t.Errorf("expected 1 new finding, got %d", len(diff.New))
	}
	if diff.New[0].NHIID != "def456" {
		t.Error("expected def456 as new finding")
	}
}

func TestDiff_ResolvedFinding(t *testing.T) {
	bl := &Baseline{
		Findings: map[string]BaselineFinding{
			"abc123": {NHIID: "abc123", Score: 95, Severity: "CRITICAL"},
			"def456": {NHIID: "def456", Score: 80, Severity: "HIGH"},
		},
	}
	current := []scoring.ScoringResult{
		{NHIID: "abc123", FinalScore: 95, FinalSeverity: scoring.SeverityCritical},
	}
	diff := Diff(current, bl)
	if len(diff.Resolved) != 1 {
		t.Errorf("expected 1 resolved finding, got %d", len(diff.Resolved))
	}
}

func TestDiff_RegressionDetected(t *testing.T) {
	bl := &Baseline{
		Findings: map[string]BaselineFinding{
			"abc123": {NHIID: "abc123", Score: 60, Severity: "MEDIUM"},
		},
	}
	current := []scoring.ScoringResult{
		{NHIID: "abc123", FinalScore: 95, FinalSeverity: scoring.SeverityCritical},
	}
	diff := Diff(current, bl)
	if len(diff.Regressed) != 1 {
		t.Errorf("expected 1 regressed finding, got %d", len(diff.Regressed))
	}
}

func TestDiff_NoBaseline(t *testing.T) {
	current := []scoring.ScoringResult{
		{NHIID: "abc123", FinalScore: 95, FinalSeverity: scoring.SeverityCritical},
	}
	diff := Diff(current, nil)
	if len(diff.New) != 1 {
		t.Error("all findings should be new when no baseline")
	}
}

func TestLoad_NonexistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
```

**Step 2: Run tests, verify they fail**

Run: `go test ./internal/baseline/ -v`
Expected: FAIL — package doesn't exist.

**Step 3: Implement baseline package**

Create `internal/baseline/baseline.go`:

```go
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Zyrakk/nhi-watch/internal/scoring"
)

type Baseline struct {
	Version     string                    `json:"version"`
	Timestamp   time.Time                 `json:"timestamp"`
	ClusterName string                    `json:"cluster_name"`
	Findings    map[string]BaselineFinding `json:"findings"`
}

type BaselineFinding struct {
	NHIID    string `json:"nhi_id"`
	Name     string `json:"name"`
	Score    int    `json:"score"`
	Severity string `json:"severity"`
}

type DiffResult struct {
	New       []scoring.ScoringResult // Findings not in baseline
	Resolved  []BaselineFinding       // Baseline findings no longer present
	Regressed []scoring.ScoringResult // Findings with worse score than baseline
	Unchanged []scoring.ScoringResult // Same or better
}

func Save(path string, results []scoring.ScoringResult, clusterName string) error {
	bl := Baseline{
		Version:     "1",
		Timestamp:   time.Now().UTC(),
		ClusterName: clusterName,
		Findings:    make(map[string]BaselineFinding, len(results)),
	}
	for _, r := range results {
		if r.FinalScore == 0 {
			continue // Don't baseline zero-score findings
		}
		bl.Findings[r.NHIID] = BaselineFinding{
			NHIID:    r.NHIID,
			Name:     r.Name,
			Score:    r.FinalScore,
			Severity: string(r.FinalSeverity),
		}
	}
	data, err := json.MarshalIndent(bl, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline: %w", err)
	}
	var bl Baseline
	if err := json.Unmarshal(data, &bl); err != nil {
		return nil, fmt.Errorf("parsing baseline: %w", err)
	}
	return &bl, nil
}

func Diff(current []scoring.ScoringResult, bl *Baseline) DiffResult {
	var diff DiffResult
	if bl == nil {
		diff.New = current
		return diff
	}
	seen := make(map[string]bool)
	for _, r := range current {
		if r.FinalScore == 0 {
			continue
		}
		seen[r.NHIID] = true
		prev, existed := bl.Findings[r.NHIID]
		if !existed {
			diff.New = append(diff.New, r)
		} else if r.FinalScore > prev.Score {
			diff.Regressed = append(diff.Regressed, r)
		} else {
			diff.Unchanged = append(diff.Unchanged, r)
		}
	}
	for id, f := range bl.Findings {
		if !seen[id] {
			diff.Resolved = append(diff.Resolved, f)
		}
	}
	return diff
}

// HasFailures returns true if there are new or regressed findings at or above
// the given minimum severity.
func (d DiffResult) HasFailures(minSeverity scoring.Severity) bool {
	for _, r := range d.New {
		if scoring.SeverityAtLeast(r.FinalSeverity, minSeverity) {
			return true
		}
	}
	for _, r := range d.Regressed {
		if scoring.SeverityAtLeast(r.FinalSeverity, minSeverity) {
			return true
		}
	}
	return false
}
```

Note: `scoring.SeverityAtLeast(a, min)` may need to be added to `internal/scoring/scoring.go` — a helper that compares severity levels:

```go
func SeverityAtLeast(s, min Severity) bool {
	order := map[Severity]int{
		SeverityInfo: 0, SeverityLow: 1, SeverityMedium: 2,
		SeverityHigh: 3, SeverityCritical: 4,
	}
	return order[s] >= order[min]
}
```

**Step 4: Run tests, verify they pass**

Run: `go test -race ./internal/baseline/ -v`
Expected: All pass.

**Step 5: Commit**

```bash
git add internal/baseline/ internal/scoring/scoring.go
git commit -m "feat(baseline): add save/load/diff for incremental CI/CD adoption"
```

---

## Task 7: CI/CD Integration

**Purpose:** Add `--fail-on`, `--save-baseline`, and `--baseline` flags to the audit command. Exit code 2 when threshold breached.

**Files:**
- Modify: `internal/cli/audit.go` — add flags and exit code logic

**Step 1: Add flags to audit command**

```go
auditCmd.Flags().String("fail-on", "", "Exit with code 2 if findings at or above this severity exist (critical|high|medium|low)")
auditCmd.Flags().String("save-baseline", "", "Save current results as baseline to this file path")
auditCmd.Flags().String("baseline", "", "Compare results against this baseline file (only new/regressed findings trigger --fail-on)")
```

**Step 2: Implement exit code logic in audit RunE**

After scoring and reporting:

```go
// Save baseline if requested
if savePath, _ := cmd.Flags().GetString("save-baseline"); savePath != "" {
    if err := baseline.Save(savePath, results, clusterName); err != nil {
        return fmt.Errorf("saving baseline: %w", err)
    }
    fmt.Fprintf(os.Stderr, "Baseline saved to %s (%d findings)\n", savePath, len(results))
}

// Check fail-on threshold
if failOn, _ := cmd.Flags().GetString("fail-on"); failOn != "" {
    minSev := scoring.ParseSeverity(failOn)
    if minSev == "" {
        return fmt.Errorf("invalid severity for --fail-on: %s", failOn)
    }

    blPath, _ := cmd.Flags().GetString("baseline")
    if blPath != "" {
        bl, err := baseline.Load(blPath)
        if err != nil {
            return fmt.Errorf("loading baseline: %w", err)
        }
        diff := baseline.Diff(results, bl)
        if diff.HasFailures(minSev) {
            fmt.Fprintf(os.Stderr, "FAIL: %d new, %d regressed findings at %s or above\n",
                len(diff.New), len(diff.Regressed), failOn)
            os.Exit(2)
        }
    } else {
        // No baseline: fail on any finding at threshold
        filtered := scoring.FilterBySeverity(results, minSev)
        if len(filtered) > 0 {
            fmt.Fprintf(os.Stderr, "FAIL: %d findings at %s or above\n", len(filtered), failOn)
            os.Exit(2)
        }
    }
}
```

Note: `scoring.ParseSeverity(string)` helper may need to be added — converts "critical" → SeverityCritical.

**Step 3: Write test for exit code behavior**

This is best tested as an integration test or by extracting the logic into a testable function (e.g., `shouldFail(results, failOn, baseline) bool`). Add to `internal/cli/audit_test.go` or as a function test in the baseline package.

**Step 4: Run all tests**

Run: `go test -race ./...`

**Step 5: Commit**

```bash
git add internal/cli/audit.go internal/scoring/scoring.go
git commit -m "feat(ci): add --fail-on and --baseline flags for CI/CD pipeline gating"
```

---

## Task 8: Enhanced Remediation

**Purpose:** Improve text recommendations to be specific and actionable. Add YAML generation for Traefik and cert-manager only.

**Files:**
- Modify: `internal/scoring/recommendations.go` — enhance text recommendations
- Create: `internal/remediation/remediation.go` — YAML generation logic
- Create: `internal/remediation/templates.go` — Traefik and cert-manager templates
- Create: `internal/remediation/remediation_test.go` — tests
- Create: `internal/cli/remediate.go` — `nhi-watch remediate` command

### Step 1: Enhance text recommendations

In `internal/scoring/recommendations.go`, update the `recommendationMap` entries to be more specific. Instead of:

```
"Remove the cluster-admin ClusterRoleBinding"
```

Use:

```
"Replace ClusterRoleBinding '%s' with a scoped ClusterRole. Identify the minimum verbs and resources this ServiceAccount actually needs. Run: kubectl get clusterrolebinding <name> -o yaml"
```

The `GenerateRecommendation()` function should now accept the `ScoringResult` context (including matched rule details and binding names) to generate specific, actionable text.

### Step 2: Write tests for YAML generation

Create `internal/remediation/remediation_test.go`:

```go
package remediation

import (
	"strings"
	"testing"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
	"github.com/Zyrakk/nhi-watch/internal/models"
)

func TestGenerateRemediationYAML_Traefik(t *testing.T) {
	nhi := &discovery.NonHumanIdentity{
		Name:      "traefik",
		Namespace: "kube-system",
		Type:      string(discovery.NHITypeServiceAccount),
		Source:    "helm:traefik",
	}
	yaml, err := GenerateYAML(nhi)
	if err != nil {
		t.Fatal(err)
	}
	if yaml == "" {
		t.Fatal("expected YAML output for traefik")
	}
	if !strings.Contains(yaml, "# PROPOSAL") {
		t.Error("generated YAML must be marked as proposal")
	}
	if !strings.Contains(yaml, "traefik") {
		t.Error("YAML should reference traefik")
	}
}

func TestGenerateRemediationYAML_UnknownWorkload(t *testing.T) {
	nhi := &discovery.NonHumanIdentity{
		Name:      "custom-app",
		Namespace: "default",
		Type:      string(discovery.NHITypeServiceAccount),
	}
	yaml, err := GenerateYAML(nhi)
	if err != nil {
		t.Fatal(err)
	}
	if yaml != "" {
		t.Error("should return empty YAML for unknown workloads")
	}
}

func TestGenerateRemediationYAML_CertManager(t *testing.T) {
	nhi := &discovery.NonHumanIdentity{
		Name:      "cert-manager",
		Namespace: "cert-manager",
		Type:      string(discovery.NHITypeServiceAccount),
		Source:    "helm:cert-manager",
	}
	yaml, err := GenerateYAML(nhi)
	if err != nil {
		t.Fatal(err)
	}
	if yaml == "" {
		t.Fatal("expected YAML output for cert-manager")
	}
}
```

### Step 3: Implement remediation package

Create `internal/remediation/remediation.go`:

```go
package remediation

import (
	"github.com/Zyrakk/nhi-watch/internal/discovery"
)

// GenerateYAML returns a remediation YAML proposal for known workloads.
// Returns empty string for unknown workloads (text recommendations only).
func GenerateYAML(nhi *discovery.NonHumanIdentity) (string, error) {
	tmpl := matchTemplate(nhi)
	if tmpl == nil {
		return "", nil
	}
	return tmpl.render(nhi)
}

func matchTemplate(nhi *discovery.NonHumanIdentity) *workloadTemplate {
	// Match by SA name or Helm source label
	for _, t := range knownTemplates {
		if t.matches(nhi) {
			return &t
		}
	}
	return nil
}
```

Create `internal/remediation/templates.go` with Traefik and cert-manager templates:

```go
package remediation

// Traefik least-privilege ClusterRole (verified against k3s default installation)
// cert-manager least-privilege ClusterRole (verified against cert-manager v1.x)
```

Each template outputs a complete ClusterRole + ClusterRoleBinding YAML with:
- `# PROPOSAL — Review before applying. Generated by nhi-watch.` header
- `# Verified against: <workload> <version> on k3s` comment
- The minimum verbs/resources the workload needs

### Step 4: Add remediate CLI command

Create `internal/cli/remediate.go`:

```go
// nhi-watch remediate [sa-name] -n <namespace> [--output-dir=./fixes/] [--dry-run=true]
// Without sa-name: generates recommendations for all scored NHIs
// With sa-name: generates for specific SA
// --dry-run=true (default): only print, don't write files
// --output-dir: write YAML files to directory
```

### Step 5: Run all tests

Run: `go test -race ./...`

### Step 6: Commit

```bash
git add internal/scoring/recommendations.go internal/remediation/ internal/cli/remediate.go
git commit -m "feat(remediation): add enhanced recommendations and YAML generation for traefik/cert-manager"
```

---

## Task 9: Gatekeeper Policy Export

**Purpose:** Generate OPA/Gatekeeper ConstraintTemplates from NHI-Watch scoring rules. Turns detection into prevention via ecosystem tooling.

**Files:**
- Create: `internal/policy/gatekeeper.go` — ConstraintTemplate generation
- Create: `internal/policy/gatekeeper_test.go` — tests
- Create: `internal/cli/policy.go` — `nhi-watch policy export` command

### Step 1: Write failing tests

Create `internal/policy/gatekeeper_test.go`:

```go
package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGenerateConstraintTemplates_ValidYAML(t *testing.T) {
	templates, err := GenerateGatekeeperTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if len(templates) == 0 {
		t.Fatal("expected at least one template")
	}
	for _, tmpl := range templates {
		var parsed map[string]interface{}
		if err := yaml.Unmarshal([]byte(tmpl), &parsed); err != nil {
			t.Errorf("invalid YAML in template: %v", err)
		}
		kind, _ := parsed["kind"].(string)
		if kind != "ConstraintTemplate" {
			t.Errorf("expected kind ConstraintTemplate, got %s", kind)
		}
	}
}

func TestGenerateConstraintTemplates_ClusterAdminRule(t *testing.T) {
	templates, _ := GenerateGatekeeperTemplates()
	found := false
	for _, tmpl := range templates {
		if strings.Contains(tmpl, "cluster-admin") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a template for cluster-admin detection")
	}
}
```

### Step 2: Implement Gatekeeper template generation

Create `internal/policy/gatekeeper.go`:

Not every scoring rule maps to an admission-time check. Rules that can be enforced at admission time:

| Rule | Gatekeeper enforceable? | Reason |
|------|------------------------|--------|
| CLUSTER_ADMIN_BINDING | Yes | Block RoleBinding/ClusterRoleBinding to cluster-admin |
| WILDCARD_PERMISSIONS | Yes | Block Role/ClusterRole with wildcard verbs/resources |
| DEFAULT_SA_HAS_BINDINGS | Yes | Block RoleBinding targeting default SA |
| SECRET_ACCESS_CLUSTER_WIDE | Yes | Block ClusterRoleBinding granting secret access |
| AUTOMOUNT_TOKEN_ENABLED | Yes | Block pods/SAs with automountServiceAccountToken=true |
| SECRET_NOT_ROTATED_* | No | Time-based, not admission-time |
| TLS_CERT_EXPIRED | No | Time-based |
| CERT_NOT_READY | No | Status-based |

Generate ConstraintTemplates for the enforceable rules. Each template uses Rego in the `spec.targets[].rego` field.

Example for cluster-admin binding prevention:

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: nhiwatch-no-cluster-admin-binding
  annotations:
    nhi-watch.io/rule-id: CLUSTER_ADMIN_BINDING
    nhi-watch.io/cis-control: "5.1.1"
spec:
  crd:
    spec:
      names:
        kind: NHIWatchNoClusterAdminBinding
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package nhiwatch.noclusteradminbinding
        violation[{"msg": msg}] {
          input.review.kind.kind == "ClusterRoleBinding"
          input.review.object.roleRef.name == "cluster-admin"
          msg := sprintf("ClusterRoleBinding %s binds to cluster-admin (CIS 5.1.1)", [input.review.object.metadata.name])
        }
        violation[{"msg": msg}] {
          input.review.kind.kind == "RoleBinding"
          input.review.object.roleRef.name == "cluster-admin"
          msg := sprintf("RoleBinding %s binds to cluster-admin (CIS 5.1.1)", [input.review.object.metadata.name])
        }
```

### Step 3: Add CLI command

Create `internal/cli/policy.go`:

```go
// nhi-watch policy export --format=gatekeeper [--output-dir=./policies/]
// Outputs all ConstraintTemplates as multi-document YAML to stdout
// or writes individual files to output-dir
```

### Step 4: Run all tests

Run: `go test -race ./...`

### Step 5: Commit

```bash
git add internal/policy/ internal/cli/policy.go
git commit -m "feat(policy): add Gatekeeper ConstraintTemplate export from scoring rules"
```

---

## Task 10: Packaging

**Purpose:** Docker image, Helm chart, and install script for distribution.

**Files:**
- Create: `Dockerfile` — multi-stage build, distroless final image
- Create: `deploy/helm/nhi-watch/Chart.yaml`
- Create: `deploy/helm/nhi-watch/values.yaml`
- Create: `deploy/helm/nhi-watch/templates/cronjob.yaml`
- Create: `deploy/helm/nhi-watch/templates/serviceaccount.yaml`
- Create: `deploy/helm/nhi-watch/templates/clusterrole.yaml`
- Create: `deploy/helm/nhi-watch/templates/clusterrolebinding.yaml`
- Create: `scripts/install.sh` — curl-pipe installer
- Modify: `.github/workflows/ci.yml` — add Docker build step, release workflow

### Step 1: Create Dockerfile

```dockerfile
# Build stage
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build \
    -ldflags "-X github.com/Zyrakk/nhi-watch/internal/cli.Version=${VERSION} \
              -X github.com/Zyrakk/nhi-watch/internal/cli.Commit=${COMMIT} \
              -X github.com/Zyrakk/nhi-watch/internal/cli.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /nhi-watch ./cmd/nhi-watch

# Final stage
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /nhi-watch /nhi-watch
USER nonroot:nonroot
ENTRYPOINT ["/nhi-watch"]
```

### Step 2: Create Helm chart

**Chart.yaml:**
```yaml
apiVersion: v2
name: nhi-watch
description: Kubernetes Non-Human Identity security auditor
version: 0.1.0
appVersion: "1.0.0"
```

**values.yaml:**
```yaml
image:
  repository: ghcr.io/zyrakk/nhi-watch
  tag: latest
  pullPolicy: IfNotPresent
schedule: "0 2 * * *"  # Daily at 2 AM
failOn: ""  # Set to "critical" to fail CronJob on critical findings
baseline:
  enabled: false
  pvcName: ""
serviceAccount:
  create: true
  name: nhi-watch
```

**templates/cronjob.yaml:** CronJob running `nhi-watch audit` with configurable schedule, output format, and fail-on threshold.

**templates/clusterrole.yaml:** Read-only ClusterRole:
```yaml
rules:
  - apiGroups: [""]
    resources: [serviceaccounts, secrets, pods, namespaces]
    verbs: [get, list, watch]
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [roles, clusterroles, rolebindings, clusterrolebindings]
    verbs: [get, list, watch]
  - apiGroups: [cert-manager.io]
    resources: [certificates]
    verbs: [get, list, watch]
  - apiGroups: [security.openshift.io]
    resources: [securitycontextconstraints]
    verbs: [get, list, watch]
```

### Step 3: Create install script

`scripts/install.sh` — detects OS/arch, downloads latest release binary from GitHub Releases, installs to `/usr/local/bin/nhi-watch`.

### Step 4: Update CI workflow

Add to `.github/workflows/ci.yml`:
- Docker build step (build but don't push on PRs, build and push on tag)
- Release workflow triggered on `v*` tags: build binaries for linux/darwin × amd64/arm64, create GitHub Release with assets

### Step 5: Test Docker build locally

Run: `docker build -t nhi-watch:test .`
Run: `docker run nhi-watch:test version`
Expected: version output with correct metadata.

### Step 6: Test Helm chart lint

Run: `helm lint deploy/helm/nhi-watch/`
Expected: No errors.

### Step 7: Commit

```bash
git add Dockerfile deploy/ scripts/install.sh .github/workflows/ci.yml
git commit -m "feat(packaging): add Dockerfile, Helm chart, and install script"
```

---

## Dependency Graph

```
Task 1 (CIS mapping)          ──────────────────────────────────┐
Task 2 (Pod posture discovery) → Task 3 (Risk multiplier) ──────┤
Task 4 (OpenShift SCC)         ──────────────────────────────────┤
                                                                 ├→ Task 5 (Reporter)
                                                                 │   → Task 6 (Baseline)
                                                                 │     → Task 7 (CI/CD)
Task 8 (Remediation)           ──────────────────────────────────┘
Task 9 (Gatekeeper export)     ─── (can run in parallel with 5-7)
Task 10 (Packaging)            ─── (last, after all features)
```

**Parallelizable groups:**
- Tasks 1, 2, 8 can start in parallel (independent)
- Task 3 depends on Task 2
- Task 4 depends on Task 2 infrastructure (PodPosture type)
- Task 5 depends on Tasks 1-4 (needs final data model)
- Tasks 6-7 depend on Task 5
- Task 9 can run in parallel with Tasks 5-7
- Task 10 is last

## Estimated Effort

| Task | Effort | Notes |
|------|--------|-------|
| 1. CIS mapping | 1-2 hours | Metadata addition only |
| 2. Pod posture discovery | 3-4 hours | New discovery phase + tests |
| 3. Risk multiplier | 2-3 hours | Scoring engine extension |
| 4. OpenShift SCC | 2-3 hours | Extends pod posture |
| 5. Reporter (table/JSON/SARIF) | 6-8 hours | Significant refactor + SARIF spec |
| 6. Baseline | 3-4 hours | New package + tests |
| 7. CI/CD integration | 2-3 hours | CLI flag wiring |
| 8. Remediation | 4-6 hours | Templates need k3s verification |
| 9. Gatekeeper export | 4-6 hours | Rego policy writing |
| 10. Packaging | 4-6 hours | Docker + Helm + CI |
| **Total** | **~32-45 hours** | **~8-12 weeks spare time** |
