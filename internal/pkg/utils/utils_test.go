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

func TestRegexMatchPositive(t *testing.T) {
	haystack := "Something"
	needle := "(?i)(^some.*$)"

	got := false
	expect := true

	res := RegexMatch(haystack, needle)

	if len(res) > 0 {
		got = true
	}

	if got != expect {
		t.Errorf(
			"Regexmatch() could not find needle %q; in haystack %q",
			needle,
			haystack)
	}
}

func TestRegexMatchNegative(t *testing.T) {
	haystack := "Something"
	needle := "(^some.*$)"

	got := false
	expect := false

	res := RegexMatch(haystack, needle)

	if len(res) > 0 {
		got = true
	}

	if got != expect {
		t.Errorf(
			"Regexmatch() found need %q; in haystack %q when it should not be present.",
			needle,
			haystack)
	}
}
