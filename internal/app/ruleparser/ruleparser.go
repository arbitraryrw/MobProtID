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
			getObjectFromJSON("signature", res)
		}

	}

}

func getObjectFromJSON(needle string, haystack []interface{}) {

	for k, value := range haystack {
		fmt.Println("CANARY -- ", k, reflect.TypeOf(value))
		fmt.Println("CANARY -- ", k, value)

		if v, ok := value.([]interface{}); ok {
			fmt.Println("\t", v)
			// getObjectFromJSON(needle, v)
		}

		if v, ok := value.(map[string]interface{}); ok {

			for key, value := range v {
				fmt.Println("[DEBUG] Rule -> ", key, value)

				parseJSONRule(v)
			}
		}

	}

}

func parseJSONRule(jsonRule map[string]interface{}) {
	// fmt.Println("Parsing rule:", jsonRule)
}
