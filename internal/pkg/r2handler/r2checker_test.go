package r2handler

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
)

func init() {}

func TestHandleRule(t *testing.T) {

	sampleBinaryRelPath := "../../../test/sample_binary"
	sampleBinAbsPath, err := filepath.Abs(sampleBinaryRelPath)

	if err != nil {
		panic(err)
	}

	parsedBinaryFilePaths := make([]string, 0)
	parsedBinaryFilePaths = append(parsedBinaryFilePaths, sampleBinAbsPath)

	var wg sync.WaitGroup

	wg.Add(1)
	go PrepareAnal(parsedBinaryFilePaths, &wg)
	wg.Wait()

	// Test Positive Rule
	var r model.Rule
	var sigs []interface{}

	sigs = append(sigs, "(?i)(.*mobprotid.*)")

	r.Handler = "radare2"
	r.MatchType = "regex"
	r.MatchValue = sigs
	r.Type = "strings"
	r.Name = "part_1"
	r.Invert = false

	result := HandleRule(r)

	if result.Match != true {
		t.Errorf(
			"HandleRule = yara result mismatch, expected %t, got %t",
			true,
			result.Match)
	}

	if len(result.Evidence) != 1 {
		t.Errorf(
			"HandleRule = yara rule result evidence missmatch"+
				", expected %q match, got: %q match",
			1,
			len(result.Evidence))
	}

	for _, e := range result.Evidence {
		if e.File != sampleBinAbsPath {
			t.Errorf(
				"HandleRule = yara rule result evidence file missmatch"+
					", expected %q, got: %q",
				sampleBinAbsPath,
				e.File)
		}

		if e.RuleName != r.Name {
			t.Errorf(
				"HandleRule = yara rule result evidence rule name missmatch"+
					", expected %q, got: %q",
				r.Name,
				e.RuleName)
		}
		if e.Name != "It's MobProtID here!" {
			t.Errorf(
				"HandleRule = yara rule result evidence name missmatch"+
					", expected %q, got: %q",
				"It's MobProtID here!",
				e.Name)
		}
		if e.Offset != "1918" {
			t.Errorf(
				"HandleRule = yara rule result evidence offset"+
					"missmatch, expected %q, got: %q",
				"1918",
				e.Offset)
		}

	}
}
