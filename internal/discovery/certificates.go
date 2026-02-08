package discovery

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
)

// certManagerGVR is the GroupVersionResource for cert-manager Certificate objects.
var certManagerGVR = schema.GroupVersionResource{
	Group:    "cert-manager.io",
	Version:  "v1",
	Resource: "certificates",
}

// DiscoverCertManagerCertificates discovers cert-manager Certificate resources
// using the dynamic client. This avoids importing cert-manager as a Go dependency.
//
// If cert-manager is not installed (CRD not found), it returns an empty slice
// with no error (silent skip).
func DiscoverCertManagerCertificates(ctx context.Context, discoveryClient discovery.DiscoveryInterface, dynClient dynamic.Interface, namespace string) ([]NonHumanIdentity, error) {
	// Check if cert-manager CRD exists before attempting to list.
	if !isCertManagerInstalled(discoveryClient) {
		return nil, nil
	}

	var certList *unstructured.UnstructuredList
	var err error

	if namespace != "" {
		certList, err = dynClient.Resource(certManagerGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	} else {
		certList, err = dynClient.Resource(certManagerGVR).List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil, fmt.Errorf("listing cert-manager certificates: %w", err)
	}

	nhis := make([]NonHumanIdentity, 0, len(certList.Items))
	for i := range certList.Items {
		nhis = append(nhis, certManagerCertToNHI(&certList.Items[i]))
	}

	return nhis, nil
}

// isCertManagerInstalled checks if the cert-manager Certificate CRD exists
// by querying the discovery API for the cert-manager.io API group.
func isCertManagerInstalled(dc discovery.DiscoveryInterface) bool {
	resources, err := dc.ServerResourcesForGroupVersion("cert-manager.io/v1")
	if err != nil {
		return false
	}
	for _, r := range resources.APIResources {
		if r.Name == "certificates" {
			return true
		}
	}
	return false
}

// certManagerCertToNHI converts an unstructured cert-manager Certificate to a NonHumanIdentity.
func certManagerCertToNHI(obj *unstructured.Unstructured) NonHumanIdentity {
	name := obj.GetName()
	namespace := obj.GetNamespace()
	created := obj.GetCreationTimestamp().Time

	nhi := NonHumanIdentity{
		ID:        generateID(NHITypeCertManagerCertificate, namespace, name),
		Type:      NHITypeCertManagerCertificate,
		Name:      name,
		Namespace: namespace,
		CreatedAt: created,
		Source:    "cert-manager",
		Metadata:  make(map[string]string),
	}

	spec, _ := nestedMap(obj.Object, "spec")
	status, _ := nestedMap(obj.Object, "status")

	// IssuerRef.
	if issuerRef, ok := nestedMap(spec, "issuerRef"); ok {
		issuerName, _ := nestedString(issuerRef, "name")
		issuerKind, _ := nestedString(issuerRef, "kind")
		if issuerKind == "" {
			issuerKind = "Issuer"
		}
		nhi.Issuer = issuerKind + ":" + issuerName
		nhi.Metadata["issuer_name"] = issuerName
		nhi.Metadata["issuer_kind"] = issuerKind
	}

	// DNS names.
	if dnsNames, ok := nestedStringSlice(spec, "dnsNames"); ok {
		nhi.DNSNames = dnsNames
	}

	// Secret name (the TLS secret this Certificate manages).
	if secretName, ok := nestedString(spec, "secretName"); ok {
		nhi.Metadata["secret_name"] = secretName
	}

	// Renewal time from status.
	if renewalTime, ok := nestedString(status, "renewalTime"); ok {
		nhi.Metadata["renewal_time"] = renewalTime
	}

	// NotAfter from status.
	if notAfter, ok := nestedString(status, "notAfter"); ok {
		nhi.Metadata["not_after"] = notAfter
		if t, err := time.Parse(time.RFC3339, notAfter); err == nil {
			nhi.ExpiresAt = t
			if time.Until(t) < 30*24*time.Hour {
				nhi.Metadata["expiring_soon"] = "true"
			}
			if time.Now().After(t) {
				nhi.Metadata["expired"] = "true"
			}
		}
	}

	// NotBefore from status.
	if notBefore, ok := nestedString(status, "notBefore"); ok {
		nhi.Metadata["not_before"] = notBefore
	}

	// Ready condition.
	if conditions, ok := nestedSlice(status, "conditions"); ok {
		for _, c := range conditions {
			cond, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			condType, _ := cond["type"].(string)
			if condType == "Ready" {
				condStatus, _ := cond["status"].(string)
				nhi.Metadata["ready"] = condStatus
				if reason, ok := cond["reason"].(string); ok {
					nhi.Metadata["ready_reason"] = reason
				}
				break
			}
		}
	}

	return nhi
}

// --- Unstructured helper functions ---
// These avoid importing nested-field utilities and handle type assertions safely.

func nestedMap(obj map[string]interface{}, key string) (map[string]interface{}, bool) {
	val, ok := obj[key]
	if !ok {
		return nil, false
	}
	m, ok := val.(map[string]interface{})
	return m, ok
}

func nestedString(obj map[string]interface{}, key string) (string, bool) {
	val, ok := obj[key]
	if !ok {
		return "", false
	}
	s, ok := val.(string)
	return s, ok
}

func nestedStringSlice(obj map[string]interface{}, key string) ([]string, bool) {
	val, ok := obj[key]
	if !ok {
		return nil, false
	}
	slice, ok := val.([]interface{})
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(slice))
	for _, v := range slice {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result, true
}

func nestedSlice(obj map[string]interface{}, key string) ([]interface{}, bool) {
	val, ok := obj[key]
	if !ok {
		return nil, false
	}
	slice, ok := val.([]interface{})
	return slice, ok
}