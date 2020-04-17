package r2handler

import (
	"fmt"
	"strings"
	"testing"
)

// ToDo: Unit test wrapper code around r2 when it starts being developed

//Description Dummy function to check scope
func TestUgetStringEntireBinary(t *testing.T) {

	var expect = "utils coming in!"
	got := "aa"

	if strings.Compare("a", "a") != 0 {
		fmt.Println("Failed comparison!")
		t.Errorf("Description() = %q; want %q", got, expect)
	}
}
