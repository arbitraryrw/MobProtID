package r2handler

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

var detectionAnalResults map[string]bool

// HandleRule - accepts a rule and evaluates the desired condition
func HandleRule(r model.Rule) model.RuleResult {
	fmt.Println("[INFO] Handling rule: ", r)

	ruleName := r.Name
	matchType := r.MatchType
	matchValue := r.MatchValue
	ruleType := r.Type
	invert := r.Invert

	fmt.Println("[INFO] RuleType: ", ruleType)
	fmt.Println("[INFO] Matching against: ", matchType)

	var evidenceInstances []model.Evidence

	for _, val := range matchValue {

		if strings.ToLower(ruleType) == "strings" {

			for k, v := range allStringsInBinary {
				// fmt.Println("[INFO] File ->", k)

				for _, s := range v {
					evidence := evalMatch(k, r, val.(string), s)
					evidenceInstances = append(evidenceInstances, evidence...)
				}
			}

		} else if strings.ToLower(ruleType) == "symbols" {

			for file, v := range allSymbolsInBinary {

				for _, s := range v {
					evidence := evalMatch(file, r, val.(string), s)
					evidenceInstances = append(evidenceInstances, evidence...)
				}
			}

		} else if strings.ToLower(ruleType) == "syscalls" {

			for file, syscallBundle := range allSyscall {

				for _, syscall := range syscallBundle {
					evidence := evalMatch(file, r, val.(string), syscall)
					evidenceInstances = append(evidenceInstances, evidence...)
				}
			}

		} else if strings.Contains(strings.ToLower(ruleType), "compilerflag") {

			var dataTarget string

			if strings.ToLower(ruleType[:3]) == "pic" {
				dataTarget = "pic"
			} else if strings.ToLower(ruleType[:6]) == "canary" {
				dataTarget = "canary"
			} else if strings.ToLower(ruleType[:8]) == "stripped" {
				dataTarget = "stripped"
			} else if strings.ToLower(ruleType[:8]) == "compiler" {
				dataTarget = "compiler"
			} else {
				panic(fmt.Sprintf(
					"[ERROR] Unknown rule type %q in %q",
					ruleType,
					ruleName))
			}

			for file, v := range allbinaryInfo {

				// fmt.Println("[INFO] Binary Info -->", file, allbinaryInfo)

				fileEnding := filepath.Ext(filepath.Base(file))

				if fileEnding == ".so" || fileEnding == ".dylib" ||
					fileEnding == ".ipa" || fileEnding == ".dex" {

					if canary, ok := v[dataTarget]; ok {

						evidence := evalMatch(file, r, val.(string), canary)
						evidenceInstances = append(evidenceInstances, evidence...)

					}

				}
			}

		} else if strings.ToLower(ruleType) == "classobjects" {
			for file, bundle := range allBinClassMethFields {

				for _, b := range bundle {

					if classes, ok := b["class"]; ok {
						for _, c := range classes {
							evidence := evalMatch(file, r, val.(string), c)
							evidenceInstances = append(evidenceInstances, evidence...)
						}
					} else {
						panic(fmt.Sprintf("[ERROR] No class object found in %q", b))
					}

				}
			}
		} else if strings.ToLower(ruleType) == "methodobjects" {
			for file, bundle := range allBinClassMethFields {

				for _, b := range bundle {

					if methods, ok := b["methods"]; ok {
						for _, m := range methods {
							evidence := evalMatch(file, r, val.(string), m)
							evidenceInstances = append(evidenceInstances, evidence...)
						}
					}
				}
			}
		} else if strings.ToLower(ruleType) == "fieldobjects" {
			for file, bundle := range allBinClassMethFields {
				fmt.Println("[INFO] Searching file", file)

				for _, b := range bundle {

					if fields, ok := b["fields"]; ok {
						for _, f := range fields {
							evidence := evalMatch(file, r, val.(string), f)
							evidenceInstances = append(evidenceInstances, evidence...)
						}
					}

				}
			}
		} else if strings.ToLower(ruleType) == "functions" {
			// fmt.Println("[DEBUG] Functions rule!")

			for file, functionsBundle := range allBinFunctions {
				for _, fb := range functionsBundle {

					evidence := evalMatch(file, r, val.(string), fb)
					evidenceInstances = append(evidenceInstances, evidence...)
				}
			}

		} else {
			panic(fmt.Sprintf("[ERROR] Unknown rule type %q in %q", r.Type, r.Name))
		}

	}

	var ruleResult model.RuleResult
	ruleResult.Evidence = evidenceInstances

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

func evalMatch(file string, r model.Rule, matchValue string, data map[string]string) []model.Evidence {

	ruleName := r.Name
	matchType := r.MatchType

	var evidenceInstances []model.Evidence

	if strings.ToLower(matchType) == "regex" {

		for _, m := range utils.RegexMatch(data["name"], matchValue) {
			evidence := createEvidenceStruct(file, m, data["offset"], ruleName)

			if (model.Evidence{}) != evidence {
				evidenceInstances = append(evidenceInstances, evidence)
			}
		}

	} else if strings.ToLower(matchType) == "exact" {

		for _, m := range utils.ExactMatch(data["name"], matchValue) {
			evidence := createEvidenceStruct(file, m, data["offset"], ruleName)

			if (model.Evidence{}) != evidence {
				evidenceInstances = append(evidenceInstances, evidence)
			}
		}

	} else {
		panic(
			fmt.Sprintf(
				"[ERROR] r2handler does not support matchType of %q in rule %q",
				r.MatchType,
				r.Name))
	}

	return evidenceInstances
}
