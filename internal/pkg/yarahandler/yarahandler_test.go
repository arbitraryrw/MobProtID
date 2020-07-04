package yarahandler

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

func init() {}

func TestPrepareAnal(t *testing.T) {

	sampleBinaryRelPath := "../../../test/sample_binary.so"
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

			if !strings.Contains(rule, "simpleYaraRule.yara") {
				continue
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

				if m["rule"] != "yaraCheckerBasic" {
					t.Errorf(
						"PrepareAnal = yara analysis bundle malformed, expected %q, got %q",
						"yaraCheckerBasic",
						m["rule"])
				}

			}
		}

	}

}

func TestUrunYaraRule(t *testing.T) {

	sampleBinaryRelPath := "../../../test/sample_binary.so"
	sampleBinAbsPath, err := filepath.Abs(sampleBinaryRelPath)

	if err != nil {
		panic(err)
	}

	parsedBinaryFilePaths := make([]string, 0)
	parsedBinaryFilePaths = append(parsedBinaryFilePaths, sampleBinAbsPath)

	yaraRuleFilePath := utils.GetRuleFiles("example.yara")

	for _, bp := range parsedBinaryFilePaths {

		res := runYaraRule(bp, yaraRuleFilePath[0])

		if len(res) != 1 {
			t.Errorf(
				"runYaraRule() = yara response error, expected 1 match, got %q: %q",
				len(res),
				res)
		}

		if _, ok := res[0]["name"]; !ok {
			t.Errorf(
				"PrepareAnal = yara analysis bundle malformed, missing %q attribute in %q",
				"name",
				res[0])
		}

		if _, ok := res[0]["offset"]; !ok {
			t.Errorf(
				"PrepareAnal = yara analysis bundle malformed, missing %q attribute in %q",
				"offset",
				res[0])
		}

		if _, ok := res[0]["rule"]; !ok {
			t.Errorf(
				"PrepareAnal = yara analysis bundle malformed, missing %q attribute in %q",
				"rule",
				res[0])
		}

		if res[0]["name"] != "It's MobProtID here!" {
			t.Errorf(
				"PrepareAnal = yara analysis bundle malformed, expected %q, got %q",
				"It's MobProtID here!",
				res[0]["name"])
		}

		if res[0]["offset"] != "1918" {
			t.Errorf(
				"PrepareAnal = yara analysis bundle malformed, expected %q, got %q",
				"1918",
				res[0]["offset"])
		}

		if res[0]["rule"] != "first_example" {
			t.Errorf(
				"PrepareAnal = yara analysis bundle malformed, expected %q, got %q",
				"first_example",
				res[0]["rule"])
		}

	}

}
