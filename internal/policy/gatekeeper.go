// Package policy generates OPA/Gatekeeper ConstraintTemplates from NHI-Watch
// scoring rules, turning detection into admission-time prevention.
package policy

// GatekeeperTemplate holds a generated ConstraintTemplate.
type GatekeeperTemplate struct {
	RuleID     string
	CISControl string
	YAML       string
}

// GenerateGatekeeperTemplates returns all admission-enforceable ConstraintTemplates.
// Only rules that can be evaluated at admission time are included; time-based
// rules (secret rotation, cert expiry) and status-based rules are skipped.
func GenerateGatekeeperTemplates() ([]GatekeeperTemplate, error) {
	return []GatekeeperTemplate{
		clusterAdminBindingTemplate(),
		wildcardPermissionsTemplate(),
		defaultSABindingsTemplate(),
		secretAccessClusterWideTemplate(),
		automountTokenTemplate(),
	}, nil
}

func clusterAdminBindingTemplate() GatekeeperTemplate {
	return GatekeeperTemplate{
		RuleID:     "CLUSTER_ADMIN_BINDING",
		CISControl: "5.1.1",
		YAML: `apiVersion: templates.gatekeeper.sh/v1
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
`,
	}
}

func wildcardPermissionsTemplate() GatekeeperTemplate {
	return GatekeeperTemplate{
		RuleID:     "WILDCARD_PERMISSIONS",
		CISControl: "5.1.3",
		YAML: `apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: nhiwatch-no-wildcard-permissions
  annotations:
    nhi-watch.io/rule-id: WILDCARD_PERMISSIONS
    nhi-watch.io/cis-control: "5.1.3"
spec:
  crd:
    spec:
      names:
        kind: NHIWatchNoWildcardPermissions
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package nhiwatch.nowildcardpermissions
        violation[{"msg": msg}] {
          input.review.kind.kind == "ClusterRole"
          rule := input.review.object.rules[_]
          rule.verbs[_] == "*"
          msg := sprintf("ClusterRole %s uses wildcard verbs (CIS 5.1.3)", [input.review.object.metadata.name])
        }
        violation[{"msg": msg}] {
          input.review.kind.kind == "ClusterRole"
          rule := input.review.object.rules[_]
          rule.resources[_] == "*"
          msg := sprintf("ClusterRole %s uses wildcard resources (CIS 5.1.3)", [input.review.object.metadata.name])
        }
        violation[{"msg": msg}] {
          input.review.kind.kind == "Role"
          rule := input.review.object.rules[_]
          rule.verbs[_] == "*"
          msg := sprintf("Role %s uses wildcard verbs (CIS 5.1.3)", [input.review.object.metadata.name])
        }
        violation[{"msg": msg}] {
          input.review.kind.kind == "Role"
          rule := input.review.object.rules[_]
          rule.resources[_] == "*"
          msg := sprintf("Role %s uses wildcard resources (CIS 5.1.3)", [input.review.object.metadata.name])
        }
`,
	}
}

func defaultSABindingsTemplate() GatekeeperTemplate {
	return GatekeeperTemplate{
		RuleID:     "DEFAULT_SA_HAS_BINDINGS",
		CISControl: "5.1.5",
		YAML: `apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: nhiwatch-no-default-sa-binding
  annotations:
    nhi-watch.io/rule-id: DEFAULT_SA_HAS_BINDINGS
    nhi-watch.io/cis-control: "5.1.5"
spec:
  crd:
    spec:
      names:
        kind: NHIWatchNoDefaultSABinding
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package nhiwatch.nodefaultsabinding
        violation[{"msg": msg}] {
          input.review.kind.kind == "RoleBinding"
          subject := input.review.object.subjects[_]
          subject.kind == "ServiceAccount"
          subject.name == "default"
          msg := sprintf("RoleBinding %s targets the default ServiceAccount (CIS 5.1.5)", [input.review.object.metadata.name])
        }
        violation[{"msg": msg}] {
          input.review.kind.kind == "ClusterRoleBinding"
          subject := input.review.object.subjects[_]
          subject.kind == "ServiceAccount"
          subject.name == "default"
          msg := sprintf("ClusterRoleBinding %s targets the default ServiceAccount (CIS 5.1.5)", [input.review.object.metadata.name])
        }
`,
	}
}

func secretAccessClusterWideTemplate() GatekeeperTemplate {
	return GatekeeperTemplate{
		RuleID:     "SECRET_ACCESS_CLUSTER_WIDE",
		CISControl: "5.1.2",
		YAML: `apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: nhiwatch-no-secret-access-cluster-wide
  annotations:
    nhi-watch.io/rule-id: SECRET_ACCESS_CLUSTER_WIDE
    nhi-watch.io/cis-control: "5.1.2"
spec:
  crd:
    spec:
      names:
        kind: NHIWatchNoSecretAccessClusterWide
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package nhiwatch.nosecretaccessclusterwide
        violation[{"msg": msg}] {
          input.review.kind.kind == "ClusterRole"
          rule := input.review.object.rules[_]
          rule.resources[_] == "secrets"
          rule.verbs[_] == verb
          verb_grants_read(verb)
          msg := sprintf("ClusterRole %s grants cluster-wide secret access (CIS 5.1.2)", [input.review.object.metadata.name])
        }
        verb_grants_read(verb) {
          verb == "get"
        }
        verb_grants_read(verb) {
          verb == "list"
        }
        verb_grants_read(verb) {
          verb == "watch"
        }
        verb_grants_read(verb) {
          verb == "*"
        }
`,
	}
}

func automountTokenTemplate() GatekeeperTemplate {
	return GatekeeperTemplate{
		RuleID:     "AUTOMOUNT_TOKEN_ENABLED",
		CISControl: "5.1.6",
		YAML: `apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: nhiwatch-no-automount-token
  annotations:
    nhi-watch.io/rule-id: AUTOMOUNT_TOKEN_ENABLED
    nhi-watch.io/cis-control: "5.1.6"
spec:
  crd:
    spec:
      names:
        kind: NHIWatchNoAutomountToken
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package nhiwatch.noautomounttoken
        violation[{"msg": msg}] {
          input.review.kind.kind == "ServiceAccount"
          input.review.object.automountServiceAccountToken == true
          msg := sprintf("ServiceAccount %s/%s has automountServiceAccountToken=true (CIS 5.1.6)", [input.review.object.metadata.namespace, input.review.object.metadata.name])
        }
        violation[{"msg": msg}] {
          input.review.kind.kind == "Pod"
          input.review.object.spec.automountServiceAccountToken == true
          msg := sprintf("Pod %s/%s has automountServiceAccountToken=true (CIS 5.1.6)", [input.review.object.metadata.namespace, input.review.object.metadata.name])
        }
`,
	}
}
