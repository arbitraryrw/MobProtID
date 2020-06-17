package yarahandler

import (
	"fmt"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
)

// HandleRule - accepts a rule and evaluates the desired condition
func HandleRule(r model.Rule) model.RuleResult {
	fmt.Println("[INFO] Yara handling rule: ", r)

	// POC code written a while ago for yara usage in go
	// yarahandler.Main()

	var evidenceInstances []model.Evidence

	var ruleResult model.RuleResult
	ruleResult.Evidence = evidenceInstances

	ruleResult.Match = true

	return ruleResult
}
