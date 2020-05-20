package ruleparser

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
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

	for k, value := range haystack {
		fmt.Println("CANARY -- ", k, reflect.TypeOf(value))
		fmt.Println("CANARY -- ", k, value)

		if v, ok := value.([]interface{}); ok {
			fmt.Println("\t", v)
			// getObjectFromJSON(needle, v)
		}

		if v, ok := value.(map[string]interface{}); ok {
			fmt.Println("[INFO] Original Rule", v)

			for key, value := range v {
				if strings.Contains(key, "part_") {
					fmt.Println("[DEBUG] Rule -> ", key, reflect.TypeOf(value))

					if rule, ok := value.(map[string]interface{}); ok {
						parseJSONRule(rule)
					}
				}
			}
		}

	}

}

func parseJSONRule(jsonRule map[string]interface{}) {
	fmt.Println("\t", jsonRule)

	var rule Rule

	if val, ok := jsonRule["condition"]; ok {
		fmt.Println("We have a condition sub rule!", val)
		fmt.Println("We have a condition sub rule!", reflect.TypeOf(jsonRule["sub_3_part_1"]))
		fmt.Println("We have a condition sub rule!", jsonRule)

		for key, val := range jsonRule {
			if strings.Contains(key, "part_") {

				parseJSONRule(val.(map[string]interface{}))
			}
		}

		return
	}

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

	fmt.Println("[RULE DEBUG]", rule)
}

type Rule struct {
	Type      string
	Handler   string
	Signature []interface{}
}
