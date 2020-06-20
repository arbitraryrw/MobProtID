package yarahandler

import (
	"fmt"
	"strings"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

// HandleRule - accepts a rule and evaluates the desired condition
func HandleRule(r model.Rule) model.RuleResult {
	fmt.Println("[INFO] Yara handling rule: ", r)

	ruleName := r.Name
	matchType := r.MatchType
	matchValue := r.MatchValue
	// ruleType := r.Type
	invert := r.Invert

	var evidenceInstances []model.Evidence

	fmt.Println("Rule Name", ruleName, "")

	for _, val := range matchValue {
		fmt.Println("Match value:", val)

		for file, yaraRuleFile := range yaraAnalysisBundle {

			fmt.Println("File", file)

			for yaraFile, yaraMatches := range yaraRuleFile {
				fmt.Println("\tyara rule file", yaraFile, yaraMatches)

				for _, yMatch := range yaraMatches {

					if strings.ToLower(matchType) == "regex" {

						for _, m := range utils.RegexMatch(yMatch["rule"], val.(string)) {
							fmt.Println("[DEBUG] Regex rule name match ->", m)

							evidence := createEvidenceStruct(file, yMatch["name"], yMatch["offset"], ruleName)

							if (model.Evidence{}) != evidence {
								evidenceInstances = append(evidenceInstances, evidence)
							}
						}

					}

					// ToDo: Exact matches
				}
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

func createEvidenceStruct(file string, name string, offset string, ruleName string) model.Evidence {
	var evidence model.Evidence

	evidence.File = file
	evidence.Name = name
	evidence.Offset = offset
	evidence.RuleName = ruleName

	return evidence
}
