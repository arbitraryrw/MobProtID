package ruleparser

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

func ParseRuleFile() {
	fmt.Println("Parsing rule file..")

	jsonFile, err := os.Open("/home/nikola/projects/MobProtID/rules/test.json")

	if err != nil {
		fmt.Println(err)
	}

	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var result map[string]interface{}
	json.Unmarshal([]byte(byteValue), &result)

	fmt.Println(result["users"])
}
