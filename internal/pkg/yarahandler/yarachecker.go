package yarahandler

import (
	"fmt"
	"strings"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
)

// HandleRule - accepts a rule and evaluates the desired condition
func HandleRule(r model.Rule) model.RuleResult {
	fmt.Println("[INFO] Yara handling rule: ", r)

	ruleName := r.Name
	matchType := r.MatchType
	matchValue := r.MatchValue
	ruleType := r.Type
	invert := r.Invert

	var evidenceInstances []model.Evidence

	fmt.Println("Rule Name", ruleName, "")

	if strings.ToLower(ruleType) == "rule" {

		for _, val := range matchValue {
			fmt.Println("Match value:", val)

			if strings.ToLower(matchType) == "regex" {
				// ToDo: Regex match..

			}
		}

	}

	var ruleResult model.RuleResult
	ruleResult.Evidence = evidenceInstances

	ruleResult.Match = true

	if len(evidenceInstances) > 0 {
		if invert {
			ruleResult.Match = false
		} else {
			ruleResult.Match = true
		}

	} else {
		if invert {
			ruleResult.Match = true
		} else {
			ruleResult.Match = false
		}
	}

	return ruleResult
}
