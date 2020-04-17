package r2handler

import (
	"fmt"
	"strings"
	"testing"
)

// ToDo: Unit test wrapper code around r2 when it starts being developed

//Description Dummy function to check scope
func TestUgetStringEntireBinary(t *testing.T) {

	r2s := openR2Pipe("../../../test/sample_binary")

	var expect = "It's MobProtID here!"
	got := getStringEntireBinary(r2s)

	var result = false

	for _, val := range got {
		if strings.Compare(expect, val) == 0 {
			t.Log(val)
			result = true
		}
	}

	t.Log(result)

	if strings.Compare("a", "a") != 0 {
		fmt.Println("Failed comparison!")
		t.Errorf("Description() = %q; want %q", got, expect)
	}
}
