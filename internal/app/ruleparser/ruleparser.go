package ruleparser

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
	"github.com/arbitraryrw/MobProtID/internal/pkg/r2handler"
	"github.com/arbitraryrw/MobProtID/internal/pkg/yarahandler"
)

func ParseRuleFile(ruleFiles []string) map[string][]model.RuleResult {

	ruleFilesResults := make(map[string][]model.RuleResult, 0)

	for _, file := range ruleFiles {
		fmt.Println("[INFO] Analysing rule file:", file)

		jsonFile, err := os.Open(file)

		if err != nil {
			fmt.Println(err)
		}

		// defer the closing of our jsonFile so that we can parse it later on
		defer jsonFile.Close()

		byteValue, _ := ioutil.ReadAll(jsonFile)

		var result map[string]interface{}

		json.Unmarshal([]byte(byteValue), &result)

		baseRuleFileName := filepath.Base(file)

		if res, ok := result["rules"].([]interface{}); ok {
			ruleFilesResults[baseRuleFileName] = parseUnstructuredRuleJSON(res)
		} else {
			panic(fmt.Sprintf(
				"Unable to parse rule file %s, no \"rules\" attribute found.",
				file))
		}
	}

	return ruleFilesResults
}

func parseUnstructuredRuleJSON(haystack []interface{}) []model.RuleResult {

	var allRuleResults []model.RuleResult

	for _, value := range haystack {

		if v, ok := value.(map[string]interface{}); ok {
			fmt.Println("[INFO] Original Rule", v)

			var rName string
			var rID string
			var desc string

			if ruleName, ok := v["ruleName"].(string); ok {
				rName = ruleName
			}

			if ruleID, ok := v["ruleId"].(string); ok {
				rID = ruleID
			}

			if description, ok := v["description"].(string); ok {
				desc = description
			}

			fmt.Println("[RULE START] Starting to analyse:", rName, rID, desc)

			ruleResult := parseJSONRule(v, rName)

			fmt.Println("[RULE END]", rName, ruleResult)

			ruleResult.RuleName = rName
			ruleResult.RuleID = rID
			ruleResult.Description = desc

			allRuleResults = append(allRuleResults, ruleResult)
		}
	}

	return allRuleResults
}

func parseJSONRule(jsonRule map[string]interface{}, ruleName string) model.RuleResult {
	fmt.Println("\n[jsonrule]", jsonRule)

	if condition, ok := jsonRule["condition"]; ok {

		condition = strings.ToUpper(condition.(string))
		var subResults []model.RuleResult

		for key, val := range jsonRule {
			if strings.Contains(key, "part_") {

				res := parseJSONRule(val.(map[string]interface{}), key)
				subResults = append(subResults, res)

				fmt.Println("-------- RULE", key, "EVALUATED:", res)
			}
		}

		fmt.Println("************* BOOL ARRAY RESULTS:", subResults)

		var res model.RuleResult

		if condition == "OR" {
			for _, b := range subResults {
				if b.Match {
					res.Match = true
					res.Evidence = append(res.Evidence, b.Evidence...)
				}
			}

			if res.Match {
				return res
			}

			return model.RuleResult{}

		} else if condition == "AND" {
			for _, b := range subResults {
				if !b.Match {
					return model.RuleResult{}
				}
				res.Evidence = append(res.Evidence, b.Evidence...)
			}

			res.Match = true
			return res
		}

	} else {
		var rule model.Rule

		rule.Name = ruleName

		if val, ok := jsonRule["type"]; ok {
			if val, ok := val.(string); ok {
				rule.Type = val
			}
		} else {
			err := fmt.Sprintf("Could not parse rule, missing type in %q", jsonRule)
			panic(err)
		}

		if val, ok := jsonRule["handler"]; ok {
			if val, ok := val.(string); ok {
				rule.Handler = val
			}
		} else {
			err := fmt.Sprintf("Could not parse rule, missing handler in %q", jsonRule)
			panic(err)
		}

		if val, ok := jsonRule["matchType"]; ok {
			if val, ok := val.(string); ok {
				rule.MatchType = val
			}
		} else {
			err := fmt.Sprintf("Could not parse rule, missing matchType in %q", jsonRule)
			panic(err)
		}

		if val, ok := jsonRule["invert"]; ok {
			if val, ok := val.(bool); ok {
				rule.Invert = val
			}
		} else {
			// Default to false as this is optional
			rule.Invert = false
		}

		if val, ok := jsonRule["matchValue"]; ok {
			if val, ok := val.([]interface{}); ok {
				rule.MatchValue = val
			}
		} else {
			err := fmt.Sprintf("Could not parse rule, missing MatchValue in %q", jsonRule)
			panic(err)
		}

		// Evaluate the parsed rule
		res := evalRule(rule)
		// fmt.Println("[DEBUG] Evidence from rule", res)
		return res
	}

	// Redundant return but the compiler insists
	return model.RuleResult{}
}

func evalRule(r model.Rule) model.RuleResult {
	fmt.Println("[INFO] Evaluating rule:", r)

	var ruleResult model.RuleResult

	if r.Handler == "yara" {

		return yarahandler.HandleRule(r)

	} else if r.Handler == "radare2" {

		return r2handler.HandleRule(r)

	} else if r.Handler == "dummyTestHandlerPass" {

		var evidence []model.Evidence

		ruleResult.Match = true

		var e model.Evidence

		e.Name = "dummyMatch"
		e.Offset = "0x00000001"
		e.RuleName = r.Name
		e.File = "/usr/local/MobProtID"

		evidence = append(evidence, e)

		ruleResult.Evidence = evidence

		return ruleResult
	} else if r.Handler == "dummyTestHandlerFail" {
		var evidence []model.Evidence

		ruleResult.Match = false
		ruleResult.Evidence = evidence

		return ruleResult
	} else {
		panic(fmt.Sprintf(
			"[ERROR] Unknown rule handler %q in rule: %+v.",
			r.Handler,
			r))
	}

}
