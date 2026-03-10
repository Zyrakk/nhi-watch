package reporter

import (
	"encoding/json"
	"fmt"

	"github.com/Zyrakk/nhi-watch/internal/scoring"
)

// SARIFReporter renders a SARIF v2.1.0 report for GitHub Security tab.
type SARIFReporter struct{}

// SARIF schema types per https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

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
	Name           string         `json:"name"`
	Version        string         `json:"version"`
	InformationURI string         `json:"informationUri"`
	Rules          []sarifRuleDef `json:"rules"`
}

type sarifRuleDef struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations,omitempty"`
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
	Kind               string `json:"kind"`
}

func (r *SARIFReporter) Render(report *AuditReport) ([]byte, error) {
	// Collect unique rule definitions from results.
	ruleIndex := map[string]int{}
	var ruleDefs []sarifRuleDef

	for _, sr := range report.Results {
		for _, rr := range sr.Results {
			if _, seen := ruleIndex[rr.RuleID]; seen {
				continue
			}
			ruleIndex[rr.RuleID] = len(ruleDefs)
			rd := sarifRuleDef{
				ID:               rr.RuleID,
				Name:             rr.RuleID,
				ShortDescription: sarifMessage{Text: rr.Description},
			}
			if len(rr.CISControls) > 0 {
				tags := make([]string, 0, len(rr.CISControls))
				for _, c := range rr.CISControls {
					tags = append(tags, "CIS-"+c)
				}
				rd.Properties = sarifRuleProperties{Tags: tags}
			}
			ruleDefs = append(ruleDefs, rd)
		}
	}

	// Build SARIF results — one per NHI finding (grouped rules).
	var results []sarifResult
	for _, sr := range report.Results {
		if len(sr.Results) == 0 {
			continue
		}
		// Use the highest-scoring matched rule as the primary rule ID.
		primaryRule := sr.Results[0]
		for _, rr := range sr.Results {
			if rr.Score > primaryRule.Score {
				primaryRule = rr
			}
		}

		msg := fmt.Sprintf("[%d] %s %q in namespace %q",
			sr.FinalScore, sr.Type, sr.Name, sr.Namespace)
		if sr.Recommendation != "" {
			msg += ". " + sr.Recommendation
		}

		results = append(results, sarifResult{
			RuleID:  primaryRule.RuleID,
			Level:   severityToSARIFLevel(sr.FinalSeverity),
			Message: sarifMessage{Text: msg},
			Locations: []sarifLocation{{
				LogicalLocations: []sarifLogicalLocation{{
					Name:               sr.Name,
					FullyQualifiedName: sr.Namespace + "/" + sr.Name,
					Kind:               "resource",
				}},
			}},
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "nhi-watch",
					Version:        "1.0.0",
					InformationURI: "https://github.com/Zyrakk/nhi-watch",
					Rules:          ruleDefs,
				},
			},
			Results: results,
		}},
	}

	return json.MarshalIndent(log, "", "  ")
}

func severityToSARIFLevel(sev scoring.Severity) string {
	switch sev {
	case scoring.SeverityCritical, scoring.SeverityHigh:
		return "error"
	case scoring.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
