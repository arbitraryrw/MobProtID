package yarahandler

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func init() {}

func TestPrepareAnal(t *testing.T) {

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

	for file, yaraBundle := range yaraAnalysisBundle {

		if file != sampleBinAbsPath {
			t.Errorf(
				"PrepareAnal = yara analysis bundle malformed, expected %q got %q",
				sampleBinAbsPath,
				file)
		}

		for rule, matches := range yaraBundle {

			if !strings.Contains(rule, ".yara") {
				t.Errorf(
					"PrepareAnal = yara analysis bundle malformed, expected %q got %q in name",
					rule,
					".yara")
			}

			for _, m := range matches {

				if _, ok := m["name"]; !ok {
					t.Errorf(
						"PrepareAnal = yara analysis bundle malformed, missing %q attribute in %q",
						"name",
						m)
				}

				if _, ok := m["offset"]; !ok {
					t.Errorf(
						"PrepareAnal = yara analysis bundle malformed, missing %q attribute in %q",
						"offset",
						m)
				}

				if _, ok := m["rule"]; !ok {
					t.Errorf(
						"PrepareAnal = yara analysis bundle malformed, missing %q attribute in %q",
						"rule",
						m)
				}

				if m["name"] != "It's MobProtID here!" {
					t.Errorf(
						"PrepareAnal = yara analysis bundle malformed, expected %q, got %q",
						"It's MobProtID here!",
						m["name"])
				}

				if m["offset"] != "1918" {
					t.Errorf(
						"PrepareAnal = yara analysis bundle malformed, expected %q, got %q",
						"1918",
						m["offset"])
				}

				if m["rule"] != "first_example" {
					t.Errorf(
						"PrepareAnal = yara analysis bundle malformed, expected %q, got %q",
						"first_example",
						m["rule"])
				}

			}
		}

	}

}
