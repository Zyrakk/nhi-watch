package discovery

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCertManagerCertToNHI_FullSpec(t *testing.T) {
	notAfter := time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339)

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "cert-manager.io/v1",
			"kind":       "Certificate",
			"metadata": map[string]interface{}{
				"name":              "web-cert",
				"namespace":         "production",
				"creationTimestamp": metav1.Now().Format(time.RFC3339),
			},
			"spec": map[string]interface{}{
				"secretName": "web-tls",
				"issuerRef": map[string]interface{}{
					"name": "letsencrypt-prod",
					"kind": "ClusterIssuer",
				},
				"dnsNames": []interface{}{
					"example.com",
					"www.example.com",
				},
			},
			"status": map[string]interface{}{
				"notAfter":    notAfter,
				"renewalTime": time.Now().Add(335 * 24 * time.Hour).Format(time.RFC3339),
				"conditions": []interface{}{
					map[string]interface{}{
						"type":   "Ready",
						"status": "True",
						"reason": "Ready",
					},
				},
			},
		},
	}

	// Set name/namespace via standard accessors (the unstructured fields above
	// are for nested access; actual Name/Namespace come from ObjectMeta).
	obj.SetName("web-cert")
	obj.SetNamespace("production")
	obj.SetCreationTimestamp(metav1.Now())

	nhi := certManagerCertToNHI(obj)

	if nhi.Type != NHITypeCertManagerCertificate {
		t.Errorf("expected type %q, got %q", NHITypeCertManagerCertificate, nhi.Type)
	}
	if nhi.Name != "web-cert" {
		t.Errorf("expected name 'web-cert', got %q", nhi.Name)
	}
	if nhi.Namespace != "production" {
		t.Errorf("expected namespace 'production', got %q", nhi.Namespace)
	}
	if nhi.Issuer != "ClusterIssuer:letsencrypt-prod" {
		t.Errorf("expected issuer 'ClusterIssuer:letsencrypt-prod', got %q", nhi.Issuer)
	}
	if len(nhi.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(nhi.DNSNames))
	}
	if nhi.Metadata["secret_name"] != "web-tls" {
		t.Errorf("expected secret_name 'web-tls', got %q", nhi.Metadata["secret_name"])
	}
	if nhi.Metadata["ready"] != "True" {
		t.Errorf("expected ready 'True', got %q", nhi.Metadata["ready"])
	}
	if nhi.ExpiresAt.IsZero() {
		t.Error("expected non-zero ExpiresAt")
	}
	if nhi.Source != "cert-manager" {
		t.Errorf("expected source 'cert-manager', got %q", nhi.Source)
	}
}

func TestCertManagerCertToNHI_MinimalSpec(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "cert-manager.io/v1",
			"kind":       "Certificate",
			"metadata":   map[string]interface{}{},
			"spec": map[string]interface{}{
				"secretName": "minimal-tls",
				"issuerRef": map[string]interface{}{
					"name": "self-signed",
				},
			},
		},
	}
	obj.SetName("minimal-cert")
	obj.SetNamespace("default")
	obj.SetCreationTimestamp(metav1.Now())

	nhi := certManagerCertToNHI(obj)

	if nhi.Type != NHITypeCertManagerCertificate {
		t.Errorf("expected type %q, got %q", NHITypeCertManagerCertificate, nhi.Type)
	}
	// Default kind is "Issuer" when not specified.
	if nhi.Issuer != "Issuer:self-signed" {
		t.Errorf("expected issuer 'Issuer:self-signed', got %q", nhi.Issuer)
	}
	if nhi.ExpiresAt.IsZero() == false {
		t.Error("expected zero ExpiresAt when no status")
	}
}

func TestCertManagerCertToNHI_ExpiringSoon(t *testing.T) {
	// Certificate expiring in 15 days.
	notAfter := time.Now().Add(15 * 24 * time.Hour).Format(time.RFC3339)

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "cert-manager.io/v1",
			"kind":       "Certificate",
			"metadata":   map[string]interface{}{},
			"spec": map[string]interface{}{
				"secretName": "expiring-tls",
				"issuerRef":  map[string]interface{}{"name": "le", "kind": "ClusterIssuer"},
			},
			"status": map[string]interface{}{
				"notAfter": notAfter,
			},
		},
	}
	obj.SetName("expiring-cert")
	obj.SetNamespace("default")
	obj.SetCreationTimestamp(metav1.Now())

	nhi := certManagerCertToNHI(obj)

	if nhi.Metadata["expiring_soon"] != "true" {
		t.Error("expected expiring_soon=true for cert expiring in 15 days")
	}
}

// --- Unstructured helper tests ---

func TestNestedHelpers(t *testing.T) {
	obj := map[string]interface{}{
		"spec": map[string]interface{}{
			"name": "test",
			"tags": []interface{}{"a", "b"},
		},
		"count": "5",
	}

	// nestedMap
	spec, ok := nestedMap(obj, "spec")
	if !ok || spec == nil {
		t.Error("expected to find spec map")
	}

	_, ok = nestedMap(obj, "missing")
	if ok {
		t.Error("expected missing key to return false")
	}

	// nestedString
	name, ok := nestedString(spec, "name")
	if !ok || name != "test" {
		t.Errorf("expected 'test', got %q", name)
	}

	// nestedStringSlice
	tags, ok := nestedStringSlice(spec, "tags")
	if !ok || len(tags) != 2 {
		t.Errorf("expected 2 tags, got %v", tags)
	}
}