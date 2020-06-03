package ruleparser

import (
	"fmt"
	"reflect"
	"strings"

	"testing"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

func TestParseRuleFilePositive(t *testing.T) {
	t.Log("[DEBUG] Running..")

	var file = "advanced_test_rules_positive.json"

	rules := utils.GetRuleFiles(file)
	ruleFileResults := ParseRuleFile(rules)

	for _, ruleResults := range ruleFileResults {

		for _, resultBundle := range ruleResults {

			if resultBundle.RuleID != "001" {
				continue
			}

			expectDesc := "Check single OR condition"
			if resultBundle.Description != expectDesc {
				t.Errorf("TestParseRuleFile() = rule description missmatch: got %q; want %q",
					resultBundle.Description,
					expectDesc)
			}

			expectRuleID := "001"
			if resultBundle.RuleID != expectRuleID {
				t.Errorf("TestParseRuleFile() = rule ID missmatch: got %q; want %q",
					resultBundle.RuleID,
					expectRuleID)
			}

			expectRuleName := "Complex nested rule"
			if resultBundle.RuleName != expectRuleName {
				t.Errorf("TestParseRuleFile() = rule Name missmatch: got %q; want %q",
					resultBundle.RuleName,
					expectRuleName)
			}

			expectMatch := true
			if expectMatch != resultBundle.Match {
				t.Errorf("TestParseRuleFile() = rule Match missmatch: got %t; want %t",
					resultBundle.Match,
					expectMatch)
			}

			expectEvidenceLen := 5

			if len(resultBundle.Evidence) != 5 {
				t.Errorf("TestParseRuleFile() = rule Evidence 0 missmatch: got %q ; want %q",
					len(resultBundle.Evidence),
					expectEvidenceLen)
			}

			part1 := false
			sub2part1 := false
			sub2part2 := false
			subsub3part2 := false
			sub3part2 := false

			// Itterate over each piece of evidence
			for _, e := range resultBundle.Evidence {
				if e.RuleName == "part_1" {
					part1 = true
				} else if e.RuleName == "sub_2_part_1" {
					sub2part1 = true
				} else if e.RuleName == "sub_2_part_2" {
					sub2part2 = true
				} else if e.RuleName == "sub_sub_3_part_2" {
					subsub3part2 = true
				} else if e.RuleName == "sub_3_part_2" {
					sub3part2 = true
				}

			}

			if !part1 {
				t.Errorf("TestParseRuleFile() = rule Evidence missmatch: got %q ; missing %q",
					resultBundle.Evidence,
					"part_1")
			}

			if !sub2part1 {
				t.Errorf("TestParseRuleFile() = rule Evidence missmatch: got %q ; missing %q",
					resultBundle.Evidence,
					"sub_2_part_1")
			}
			if !sub2part2 {
				t.Errorf("TestParseRuleFile() = rule Evidence missmatch: got %q ; missing %q",
					resultBundle.Evidence,
					"sub_2_part_2")
			}
			if !subsub3part2 {
				t.Errorf("TestParseRuleFile() = rule Evidence missmatch: got %q ; missing %q",
					resultBundle.Evidence,
					"sub_sub_3_part_2")
			}
			if !sub3part2 {
				t.Errorf("TestParseRuleFile() = rule Evidence missmatch: got %q ; missing %q",
					resultBundle.Evidence,
					"sub_3_part_2")
			}

		}
	}

}

func TestParseRuleFileNegative(t *testing.T) {
	t.Log("[DEBUG] Running..")

	var file = "advanced_test_rules_negative.json"

	rules := utils.GetRuleFiles(file)
	ruleFileResults := ParseRuleFile(rules)

	for _, ruleResults := range ruleFileResults {

		for _, resultBundle := range ruleResults {

			if resultBundle.RuleID != "001" {
				continue
			}

			expectDesc := "Check single OR condition"
			if resultBundle.Description != expectDesc {
				t.Errorf("TestParseRuleFile() = rule description missmatch: got %q; want %q",
					resultBundle.Description,
					expectDesc)
			}

			expectRuleID := "001"
			if resultBundle.RuleID != expectRuleID {
				t.Errorf("TestParseRuleFile() = rule ID missmatch: got %q; want %q",
					resultBundle.RuleID,
					expectRuleID)
			}

			expectRuleName := "Complex nested rule"
			if resultBundle.RuleName != expectRuleName {
				t.Errorf("TestParseRuleFile() = rule Name missmatch: got %q; want %q",
					resultBundle.RuleName,
					expectRuleName)
			}

			expectMatch := false
			if expectMatch != resultBundle.Match {
				t.Errorf("TestParseRuleFile() = rule Match missmatch: got %t; want %t",
					resultBundle.Match,
					expectMatch)
			}

			expectEvidenceLen := 0
			if len(resultBundle.Evidence) != 0 {
				t.Errorf("TestParseRuleFile() = rule Evidence 0 missmatch: got %q ; want %q",
					len(resultBundle.Evidence),
					expectEvidenceLen)
			}

		}
	}

}

func TestParseRuleFileStructure(t *testing.T) {
	t.Log("[DEBUG] Running..")

	var file = "advanced_test_rules_positive.json"
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
