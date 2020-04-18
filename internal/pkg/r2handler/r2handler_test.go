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
			// Successfully found the string in the slice
			result = true
		}
	}

	if result == false {
		fmt.Println("Failed comparison!")
		t.Errorf("getStringEntireBinary() = could not find %q in sample_binary r2 reponse", expect)
	}
}
