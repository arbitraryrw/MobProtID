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

func TestIsCommandAvailable(t *testing.T) {
	if IsCommandAvailable("ls") == false {
		t.Error("ls command does not exist! This should exists!")
	}
	if IsCommandAvailable("ls123456789") == true {
		t.Error("ls111 command should not exist!")
	}
}
