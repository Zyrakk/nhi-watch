package policy

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestGenerateGatekeeperTemplates_Count(t *testing.T) {
	templates, err := GenerateGatekeeperTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if len(templates) != 5 {
		t.Errorf("expected 5 templates, got %d", len(templates))
	}
}

func TestGenerateGatekeeperTemplates_ValidYAML(t *testing.T) {
	templates, err := GenerateGatekeeperTemplates()
	if err != nil {
		t.Fatal(err)
	}
	for _, tmpl := range templates {
		var parsed map[string]interface{}
		if err := yaml.Unmarshal([]byte(tmpl.YAML), &parsed); err != nil {
			t.Errorf("invalid YAML in %s: %v", tmpl.RuleID, err)
		}
		kind, _ := parsed["kind"].(string)
		if kind != "ConstraintTemplate" {
			t.Errorf("%s: expected kind ConstraintTemplate, got %s", tmpl.RuleID, kind)
		}
	}
}

func TestGenerateGatekeeperTemplates_HasAnnotations(t *testing.T) {
	templates, _ := GenerateGatekeeperTemplates()
	for _, tmpl := range templates {
		if !strings.Contains(tmpl.YAML, "nhi-watch.io/rule-id") {
			t.Errorf("%s: missing rule-id annotation", tmpl.RuleID)
		}
		if !strings.Contains(tmpl.YAML, "nhi-watch.io/cis-control") {
			t.Errorf("%s: missing cis-control annotation", tmpl.RuleID)
		}
	}
}

func TestGenerateGatekeeperTemplates_HasRego(t *testing.T) {
	templates, _ := GenerateGatekeeperTemplates()
	for _, tmpl := range templates {
		if !strings.Contains(tmpl.YAML, "violation[") {
			t.Errorf("%s: missing Rego violation rule", tmpl.RuleID)
		}
		if !strings.Contains(tmpl.YAML, "package nhiwatch") {
			t.Errorf("%s: missing Rego package declaration", tmpl.RuleID)
		}
	}
}

func TestGenerateGatekeeperTemplates_RuleIDs(t *testing.T) {
	templates, _ := GenerateGatekeeperTemplates()
	expected := map[string]bool{
		"CLUSTER_ADMIN_BINDING":      false,
		"WILDCARD_PERMISSIONS":       false,
		"DEFAULT_SA_HAS_BINDINGS":    false,
		"SECRET_ACCESS_CLUSTER_WIDE": false,
		"AUTOMOUNT_TOKEN_ENABLED":    false,
	}
	for _, tmpl := range templates {
		if _, ok := expected[tmpl.RuleID]; ok {
			expected[tmpl.RuleID] = true
		}
	}
	for id, found := range expected {
		if !found {
			t.Errorf("missing template for rule %s", id)
		}
	}
}

func TestGenerateGatekeeperTemplates_CISControls(t *testing.T) {
	templates, _ := GenerateGatekeeperTemplates()
	for _, tmpl := range templates {
		if tmpl.CISControl == "" {
			t.Errorf("%s: missing CIS control", tmpl.RuleID)
		}
	}
}

func TestGenerateGatekeeperTemplates_ClusterAdminContent(t *testing.T) {
	templates, _ := GenerateGatekeeperTemplates()
	for _, tmpl := range templates {
		if tmpl.RuleID == "CLUSTER_ADMIN_BINDING" {
			if !strings.Contains(tmpl.YAML, "cluster-admin") {
				t.Error("cluster-admin template should reference cluster-admin")
			}
			if !strings.Contains(tmpl.YAML, "ClusterRoleBinding") {
				t.Error("should check ClusterRoleBinding")
			}
		}
	}
}
