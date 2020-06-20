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

		for rule := range yaraBundle {

			if !strings.Contains(rule, ".yara") {
				t.Errorf(
					"PrepareAnal = yara analysis bundle malformed, expected %q got %q in name",
					rule,
					".yara")
			}

		}

	}

}
