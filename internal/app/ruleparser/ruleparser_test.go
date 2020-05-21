package ruleparser

import (
	"fmt"

	"testing"
)

func TestEvalRule(t *testing.T) {

	var expect = "test"
	var got = "test"

	if expect == "dummy val" {
		fmt.Println("Failed comparison!")
		t.Errorf("Description() = %q; want %q", got, expect)
	}
}
