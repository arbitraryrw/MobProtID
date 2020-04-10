package utils

import (
	"strings"

	"fmt"

	"testing"
)

//Description Dummy function to check scope
func TestDescription(t *testing.T) {

	var expect = "utils coming in!"
	got := Description()

	if strings.Compare(got, expect) != 0 {
		fmt.Println("Failed comparison!")
		t.Errorf("Description() = %q; want %q", got, expect)
	}
}
