package ruleparser

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
	"github.com/arbitraryrw/MobProtID/internal/pkg/r2handler"
	"github.com/arbitraryrw/MobProtID/internal/pkg/yarahandler"
)

func ParseRuleFile(ruleFiles []string) {

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

		if res, ok := result["rules"].([]interface{}); ok {
			parseUnstructuredRuleJSON(res)
		}

	}

}

func parseUnstructuredRuleJSON(haystack []interface{}) {

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
			fmt.Println("[RULE END]", rName, parseJSONRule(v))
		}
	}

}

func parseJSONRule(jsonRule map[string]interface{}) bool {
	fmt.Println("\n[jsonrule]", jsonRule)

	if condition, ok := jsonRule["condition"]; ok {

		condition = strings.ToUpper(condition.(string))
		var subResults []bool

		for key, val := range jsonRule {
			if strings.Contains(key, "part_") {

				res := parseJSONRule(val.(map[string]interface{}))
				subResults = append(subResults, res)

				fmt.Println("-------- RULE", key, "EVALUATED:", res)
			}
		}

		fmt.Println("************* BOOL ARRAY RESULTS:", subResults)

		if condition == "OR" {
			for _, b := range subResults {
				if b {
					return true
				}
			}
			return false

		} else if condition == "AND" {

			for _, b := range subResults {
				if !b {
					return false
				}
			}
			return true
		}

	} else {
		var rule model.Rule

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
		boolRes, _ := evalRule(rule)
		return boolRes
	}

	// Redundant return but the compiler insists
	return false
}

func evalRule(r model.Rule) (bool, []model.Evidence) {
	fmt.Println("[INFO] Evaluating rule:", r)

	var evidence []model.Evidence

	if r.Handler == "yara" {

		return yarahandler.HandleRule(r), evidence

	} else if r.Handler == "radare2" {

		b, e := r2handler.HandleRule(r)
		fmt.Println("Evidence from rule", e)
		return b, e

	} else if r.Handler == "dummyTestHandlerPass" {
		return true, evidence
	}

	return false, evidence
}
