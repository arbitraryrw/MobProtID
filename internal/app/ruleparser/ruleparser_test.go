package ruleparser

import (
	"fmt"
	"reflect"
	"strings"

	"testing"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

func TestParseRuleFile(t *testing.T) {
	t.Log("[DEBUG] Running..")

	var file = "advanced_test_rules.json"
	var got = false
	var expect = true

	rules := utils.GetRuleFiles(file)
	rulesResults := ParseRuleFile(rules)

	parsedRuleFileName := reflect.ValueOf(rulesResults).MapKeys()

	if len(parsedRuleFileName) > 0 {
		for _, key := range parsedRuleFileName {
			if strings.Compare(key.String(), file) == 0 {
				got = true
			}
		}
	} else {
		t.Errorf("TestParseRuleFile() = no items in rule response")
	}

	if got != expect {
		fmt.Println("Failed comparison!")
		t.Errorf("TestParseRuleFile() = %t; want %t", got, expect)
	}
}

func TestEvalRulePositive(t *testing.T) {
	var expect = true
	var r model.Rule

	var sigs []interface{}
	sigs = append(sigs, "test1", "test2", "test3")

	r.Handler = "dummyTestHandlerPass"
	r.MatchType = "test"
	r.MatchValue = sigs
	r.Type = "test"

	var got = evalRule(r)

	if got.Match != expect {
		fmt.Println("Failed comparison!")
		t.Errorf("evalRule() = %t; want %t", got.Match, expect)
	}
}

func TestEvalRuleNegative(t *testing.T) {
	var expect = false
	var r model.Rule

	var sigs []interface{}
	sigs = append(sigs, "test1", "test2", "test3")

	r.Handler = "dummyTestHandlerFail"
	r.MatchType = "test"
	r.MatchValue = sigs
	r.Type = "test"

	var got = evalRule(r)

	if got.Match != expect {
		fmt.Println("Failed comparison!")
		t.Errorf("evalRule() = %t; want %t", got.Match, expect)
	}
}
