package ruleparser

import (
	"fmt"

	"testing"

	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

func TestEvalRule(t *testing.T) {

	var expect = false
	var r Rule

	// rules := utils.GetRuleFiles("simple_test_rules.json")
	rules := utils.GetRuleFiles("advanced_test_rules.json")

	t.Log("[TESTEVALRULE]", rules)
	ParseRuleFile(rules)

	var sigs []interface{}
	sigs = append(sigs, "test1", "test2", "test3")

	r.Handler = "test"
	r.MatchType = "test"
	r.MatchValue = sigs
	r.Type = "test"

	var got = evalRule(r)

	t.Log("\n\n_____________ RES :", got)

	if got != expect {
		fmt.Println("Failed comparison!")
		t.Errorf("evalRule() = %t; want %t", got, expect)
	}
}
