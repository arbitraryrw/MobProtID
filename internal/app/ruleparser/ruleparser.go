package ruleparser

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

func ParseRuleFile() {
	fmt.Println("Parsing rule file..")

	var ruleFiles []string
	ruleDir := path.Join(utils.GetProjectRootDir(), "rules/")

	err := filepath.Walk(ruleDir, func(path string, info os.FileInfo, err error) error {

		if strings.Contains(filepath.Base(path), "android_rules.json") {
			ruleFiles = append(ruleFiles, path)
		}

		return nil
	})

	if err != nil {
		panic(err)
	}

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
			parseUnstructuredJSON(res)
		}

	}

}

func parseUnstructuredJSON(haystack []interface{}) {

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

				fmt.Println("-------- RULE EVALUATED:", res)
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
		var rule Rule

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

		if val, ok := jsonRule["signature"]; ok {
			if val, ok := val.([]interface{}); ok {
				rule.Signature = val
			}
		} else {
			err := fmt.Sprintf("Could not parse rule, missing signature in %q", jsonRule)
			panic(err)
		}
		// Evaluate the parsed rule
		return evalRule(rule)
	}

	// Redundant return but the compiler insists
	return false
}

func evalRule(r Rule) bool {
	fmt.Println("[INFO] Evaluating rule:", r)

	// ToDo: Tie individual handler parsers into this logic
	if r.Handler == "yara" {
		return true
	}

	return false
}

type Rule struct {
	Type      string
	Handler   string
	Signature []interface{}
}
