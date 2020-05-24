package ruleparser

import (
	"fmt"

	"testing"
)

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
