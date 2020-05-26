package ruleparser

import (
	"fmt"

	"testing"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

func TestParseRuleFile(t *testing.T) {
	t.Log("[DEBUG] Running..")

	var expect = false
	var got = false

	// rules := utils.GetRuleFiles("simple_test_rules.json")
	rules := utils.GetRuleFiles("advanced_test_rules.json")

	ParseRuleFile(rules)

	if got != expect {
		fmt.Println("Failed comparison!")
		t.Errorf("evalRule() = %t; want %t", got, expect)
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

	var got, _ = evalRule(r)

	if got != expect {
		fmt.Println("Failed comparison!")
		t.Errorf("evalRule() = %t; want %t", got, expect)
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

	var got, _ = evalRule(r)

	if got != expect {
		fmt.Println("Failed comparison!")
		t.Errorf("evalRule() = %t; want %t", got, expect)
	}
}
