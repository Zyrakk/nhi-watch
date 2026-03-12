package usage

import "fmt"

// auditPolicyTemplate is a Kubernetes audit Policy that captures only
// NHI-relevant events (service account API calls at Metadata level),
// filtering out health checks, system components, and watch streams.
// This typically reduces audit volume by 95%+ compared to a default policy.
const auditPolicyTemplate = `# NHI-Watch Optimized Audit Policy
# Captures only service account API activity at Metadata level.
# Apply via: --audit-policy-file=<path>
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Skip non-resource URLs (health checks, API discovery).
  - level: None
    nonResourceURLs:
      - "/healthz*"
      - "/readyz*"
      - "/livez*"
      - "/openapi*"
      - "/api"
      - "/api/*"
      - "/apis"
      - "/apis/*"
      - "/version"

  # Skip system component users whose traffic is infrastructure noise.
  - level: None
    users:
      - "system:kube-proxy"
      - "system:kube-controller-manager"
      - "system:kube-scheduler"
      - "system:apiserver"

  # Skip watch and proxy verbs — they generate continuous event streams
  # that add volume without useful NHI signal.
  - level: None
    verbs:
      - "watch"
      - "proxy"

  # Capture service account activity at Metadata level.
  - level: Metadata
    userGroups:
      - "system:serviceaccounts"
    omitStages:
      - "RequestReceived"

  # Catch-all: skip everything else.
  - level: None
`

// GenerateAuditPolicy returns a Kubernetes audit Policy YAML that only
// captures NHI-relevant events, filtering out health checks, system
// component noise, and continuous watch streams.
func GenerateAuditPolicy() string {
	return auditPolicyTemplate
}

// webhookConfigTemplate is a kubeconfig-style YAML used with the
// --audit-webhook-config-file flag to send audit events to nhi-watch.
const webhookConfigTemplate = `apiVersion: v1
kind: Config
clusters:
  - name: nhi-watch
    cluster:
      server: %s/webhook/audit
contexts:
  - name: nhi-watch
    context:
      cluster: nhi-watch
current-context: nhi-watch
`

// GenerateAuditPolicyForWebhook returns a kubeconfig-style YAML for the
// --audit-webhook-config-file API server flag, configured to send audit
// events to the given webhook URL.
func GenerateAuditPolicyForWebhook(webhookURL string) string {
	return fmt.Sprintf(webhookConfigTemplate, webhookURL)
}
