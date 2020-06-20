package yarahandler

import (
	"strings"
	"sync"
	"testing"
)

func init() {}

func TestPrepareAnal(t *testing.T) {

	analFile := "/bin/ls"

	parsedBinaryFilePaths := make([]string, 0)
	parsedBinaryFilePaths = append(parsedBinaryFilePaths, analFile)

	var wg sync.WaitGroup

	wg.Add(1)
	go PrepareAnal(parsedBinaryFilePaths, &wg)
	wg.Wait()

	for file, yaraBundle := range yaraAnalysisBundle {

		if file != analFile {
			t.Errorf(
				"PrepareAnal = yara analysis bundle malformed, expected %q got %q",
				analFile,
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

			}
		}

	}

}
