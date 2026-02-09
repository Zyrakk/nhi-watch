package scoring

import (
	"sort"

	"github.com/Zyrakk/nhi-watch/internal/discovery"
)

// Rule defines a single scoring rule that can be evaluated against an NHI.
type Rule struct {
	// ID is a unique identifier (e.g. "CLUSTER_ADMIN_BINDING").
	ID string

	// Description is a human-readable explanation of what the rule detects.
	Description string

	// Severity is the risk level when this rule matches.
	Severity Severity

	// Score is the numeric risk contribution (0-100).
	Score int

	// AppliesTo lists the NHI types this rule should be evaluated against.
	// An empty slice means the rule applies to all types.
	AppliesTo []discovery.NHIType

	// Evaluate checks whether the rule matches a given NHI.
	// Returns (true, detail) if the rule matches, where detail provides
	// context-specific information about the match.
	Evaluate func(nhi *discovery.NonHumanIdentity) (matched bool, detail string)
}

// RuleResult records a single rule match against an NHI.
type RuleResult struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Score       int      `json:"score"`
	Detail      string   `json:"detail"`
}

// ScoringResult holds the complete scoring for a single NHI.
type ScoringResult struct {
	NHIID          string       `json:"nhi_id"`
	Name           string       `json:"name"`
	Namespace      string       `json:"namespace"`
	Type           string       `json:"type"`
	FinalScore     int          `json:"final_score"`
	FinalSeverity  Severity     `json:"final_severity"`
	Results        []RuleResult `json:"results"`
	Recommendation string       `json:"recommendation"`
}

// Engine runs scoring rules against NHIs.
type Engine struct {
	rules []Rule
}

// NewEngine creates a scoring engine with the given rules.
func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

// Score evaluates all applicable rules against a single NHI and returns
// the scoring result. The final score is the maximum of all matching rules.
func (e *Engine) Score(nhi *discovery.NonHumanIdentity) ScoringResult {
	result := ScoringResult{
		NHIID:     nhi.ID,
		Name:      nhi.Name,
		Namespace: nhi.Namespace,
		Type:      string(nhi.Type),
		Results:   make([]RuleResult, 0),
	}

	for _, rule := range e.rules {
		if !ruleApplies(rule, nhi.Type) {
			continue
		}

		matched, detail := rule.Evaluate(nhi)
		if !matched {
			continue
		}

		rr := RuleResult{
			RuleID:      rule.ID,
			Description: rule.Description,
			Severity:    rule.Severity,
			Score:       rule.Score,
			Detail:      detail,
		}
		result.Results = append(result.Results, rr)

		if rule.Score > result.FinalScore {
			result.FinalScore = rule.Score
			result.FinalSeverity = rule.Severity
		}
	}

	// NHIs with no matching rules get INFO severity.
	if len(result.Results) == 0 {
		result.FinalSeverity = SeverityInfo
	}

	result.Recommendation = GenerateRecommendation(result.Results)

	return result
}

// ScoreAll evaluates all NHIs and returns results sorted by score descending.
func (e *Engine) ScoreAll(nhis []discovery.NonHumanIdentity) []ScoringResult {
	results := make([]ScoringResult, 0, len(nhis))
	for i := range nhis {
		results = append(results, e.Score(&nhis[i]))
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].FinalScore != results[j].FinalScore {
			return results[i].FinalScore > results[j].FinalScore
		}
		if results[i].Namespace != results[j].Namespace {
			return results[i].Namespace < results[j].Namespace
		}
		return results[i].Name < results[j].Name
	})

	return results
}

// FilterBySeverity returns only results meeting the minimum severity threshold.
func FilterBySeverity(results []ScoringResult, minSeverity Severity) []ScoringResult {
	filtered := make([]ScoringResult, 0)
	for _, r := range results {
		if SeverityMeetsThreshold(r.FinalSeverity, minSeverity) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// FilterByType returns only results matching the given NHI type string.
func FilterByType(results []ScoringResult, nhiType string) []ScoringResult {
	filtered := make([]ScoringResult, 0)
	for _, r := range results {
		if r.Type == nhiType {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// CountBySeverity returns a map of severity → count.
func CountBySeverity(results []ScoringResult) map[Severity]int {
	counts := make(map[Severity]int)
	for _, r := range results {
		counts[r.FinalSeverity]++
	}
	return counts
}

// CountByTypeAndSeverity returns counts grouped by NHI type and severity.
func CountByTypeAndSeverity(results []ScoringResult) map[string]map[Severity]int {
	counts := make(map[string]map[Severity]int)
	for _, r := range results {
		if counts[r.Type] == nil {
			counts[r.Type] = make(map[Severity]int)
		}
		counts[r.Type][r.FinalSeverity]++
	}
	return counts
}

// ruleApplies checks if a rule applies to the given NHI type.
func ruleApplies(rule Rule, nhiType discovery.NHIType) bool {
	if len(rule.AppliesTo) == 0 {
		return true // empty = applies to all
	}
	for _, t := range rule.AppliesTo {
		if t == nhiType {
			return true
		}
	}
	return false
}
