package ruleparser

import (
	"fmt"

	"testing"

	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

func TestParseRuleFile(t *testing.T) {
	t.Log("ayyy")

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

func TestEvalRule(t *testing.T) {
	var expect = false
	var r Rule

	var sigs []interface{}
	sigs = append(sigs, "test1", "test2", "test3")

	r.Handler = "test"
	r.MatchType = "test"
	r.MatchValue = sigs
	r.Type = "test"

	var got = evalRule(r)

	if got != expect {
		fmt.Println("Failed comparison!")
		t.Errorf("evalRule() = %t; want %t", got, expect)
	}
}
