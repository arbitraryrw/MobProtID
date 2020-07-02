package r2handler

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
)

var testBinPath string

func init() {
	sampleBinaryRelPath := "../../../test/sample_binary"
	sampleBinAbsPath, err := filepath.Abs(sampleBinaryRelPath)

	if err != nil {
		panic(
			fmt.Sprintf(
				"[ERROR] r2checker unit test setup failed: %q",
				"err"))
	}

	testBinPath = sampleBinAbsPath

	parsedBinaryFilePaths := make([]string, 0)
	parsedBinaryFilePaths = append(parsedBinaryFilePaths, sampleBinAbsPath)

	var wg sync.WaitGroup

	wg.Add(1)
	go PrepareAnal(parsedBinaryFilePaths, &wg)
	wg.Wait()
}

func TestHandleRuleSymbols(t *testing.T) {
	// Test Positive Rule
	var r model.Rule
	var sigs []interface{}

	sigs = append(sigs, "(?i)(^_init$)")

	r.Handler = "radare2"
	r.MatchType = "regex"
	r.MatchValue = sigs
	r.Type = "symbols"
	r.Name = "part_1"
	r.Invert = false

	result := HandleRule(r)

	if result.Match != true {
		t.Errorf(
			"HandleRule = radare2 symbol rule result mismatch,"+
				"expected %t, got %t",
			true,
			result.Match)
	}

	if len(result.Evidence) != 1 {
		t.Errorf(
			"HandleRule = radare2 symbol rule result evidence"+
				"mismatch, expected %q, got %q",
			1,
			len(result.Evidence))

		return
	}

	if result.Evidence[0].File != testBinPath {
		t.Errorf(
			"HandleRule = radare2 symbol rule result path mismatch,"+
				"expected %q, got %q",
			testBinPath,
			result.Evidence[0].File)
	}

	if result.Evidence[0].RuleName != r.Name {
		t.Errorf(
			"HandleRule = radare2 symbol rule result rule mismatch,"+
				"expected %q, got %q",
			r.Name,
			result.Evidence[0].RuleName)
	}
	if result.Evidence[0].Name != "_init" {
		t.Errorf(
			"HandleRule = radare2 symbol rule result name mismatch,"+
				"expected %q, got %q",
			"_init",
			result.Evidence[0].Name)
	}
	if result.Evidence[0].Offset != "1344" {
		t.Errorf(
			"HandleRule = radare2 symbol rule result offset mismatch,"+
				"expected %q, got %q",
			"1344",
			result.Evidence[0].Offset)
	}

}

func TestHandleRuleStrings(t *testing.T) {
	// ToDo: test for:
	// 2. syscalls
	// 3. compilerflag
	// 4. classobjects
	// 5. methodobjects
	// 6. fieldobjects

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
			"HandleRule = radare2 result mismatch, expected %t, got %t",
			true,
			result.Match)
	}

	if len(result.Evidence) != 1 {
		t.Errorf(
			"HandleRule = radare2 rule result evidence missmatch"+
				", expected %q match, got: %q match",
			1,
			len(result.Evidence))
	}

	for _, e := range result.Evidence {
		if e.File != testBinPath {
			t.Errorf(
				"HandleRule = radare2 rule result evidence file missmatch"+
					", expected %q, got: %q",
				testBinPath,
				e.File)
		}

		if e.RuleName != r.Name {
			t.Errorf(
				"HandleRule = radare2 rule result evidence rule name missmatch"+
					", expected %q, got: %q",
				r.Name,
				e.RuleName)
		}
		if e.Name != "It's MobProtID here!" {
			t.Errorf(
				"HandleRule = radare2 rule result evidence name missmatch"+
					", expected %q, got: %q",
				"It's MobProtID here!",
				e.Name)
		}
		if e.Offset != "1918" {
			t.Errorf(
				"HandleRule = radare2 rule result evidence offset"+
					"missmatch, expected %q, got: %q",
				"1918",
				e.Offset)
		}

		r.Invert = true
		result = HandleRule(r)

		if result.Match != false {
			t.Errorf(
				"HandleRule = radare2 result mismatch, expected"+
					" inverted result of %t, got %t",
				false,
				result.Match)
		}

		r.Invert = false

		var negativeSigs []interface{}
		negativeSigs = append(negativeSigs, "(?i)(.*thisShouldNotMatchAtAll.*)")
		r.MatchValue = negativeSigs

		negativeResults := HandleRule(r)

		if negativeResults.Match != false {
			t.Errorf(
				"HandleRule = radare2 result mismatch, expected %t, got %t",
				true,
				result.Match)
		}

	}
}

func TestUcreateEvidenceStruct(t *testing.T) {
	expectPath := "test/file/path"
	expectName := "stringNameMatch"
	expectOffset := "0xffff"
	expectRuleName := "part_1"

	evidence := createEvidenceStruct(
		expectPath,
		expectName,
		expectOffset,
		expectRuleName)

	if (model.Evidence{}) == evidence {
		t.Errorf(
			"createEvidenceStruct = radare2 evidence struct empty, got: %q",
			evidence)
	}

	if evidence.File != expectPath {
		t.Errorf(
			"createEvidenceStruct = radare2 evidence file mismatch, expected %q, got %q",
			expectPath,
			evidence.File)
	}

	if evidence.Name != expectName {
		t.Errorf(
			"createEvidenceStruct = radare2 evidence name mismatch, expected %q, got %q",
			expectName,
			evidence.Name)
	}

	if evidence.Offset != expectOffset {
		t.Errorf(
			"createEvidenceStruct = radare2 evidence offset mismatch, expected %q, got %q",
			expectOffset,
			evidence.Offset)
	}

	if evidence.RuleName != expectRuleName {
		t.Errorf(
			"createEvidenceStruct = radare2 evidence rule name mismatch, expected %q, got %q",
			expectRuleName,
			evidence.RuleName)
	}
}

func TestUevalMatchRegex(t *testing.T) {
	var r model.Rule
	var sigs []interface{}

	sigs = append(sigs, "(?i)(.*secretvalue.*)")

	r.Handler = "radare2"
	r.MatchType = "regex"
	r.MatchValue = sigs
	r.Type = "strings"
	r.Name = "part_1"
	r.Invert = false

	expectFilePath := "test/file/path"
	expectName := "superSecretValueTest"
	expectOffset := "0x1337"

	testMatchData := make(map[string]string, 0)
	testMatchData["name"] = expectName
	testMatchData["offset"] = expectOffset

	res := evalMatch(expectFilePath, r, r.MatchValue[0].(string), testMatchData)

	if len(res) != 1 {
		t.Errorf(
			"evalMatch = radare2 rule result evidence missmatch"+
				", expected %q match, got: %q match",
			1,
			len(res))

		// Don't run the deeper tests as there is nothing to test
		return
	}

	if res[0].File != expectFilePath {
		t.Errorf(
			"evalMatch = radare2 evidence file mismatch, expected %q, got %q",
			expectFilePath,
			res[0].File)
	}

	if res[0].Name != expectName {
		t.Errorf(
			"evalMatch = radare2 evidence name mismatch, expected %q, got %q",
			expectName,
			res[0].Name)
	}

	if res[0].Offset != expectOffset {
		t.Errorf(
			"evalMatch = radare2 evidence offset mismatch, expected %q, got %q",
			expectOffset,
			res[0].Offset)
	}

	if res[0].RuleName != r.Name {
		t.Errorf(
			"evalMatch = radare2 evidence rule name mismatch, expected %q, got %q",
			r.Name,
			res[0].RuleName)
	}

	negativeMatchRegex := "(?i)(.*thisShouldNotmatch.*)"
	negativeRes := evalMatch(
		expectFilePath,
		r,
		negativeMatchRegex,
		testMatchData)

	if len(negativeRes) != 0 {
		t.Errorf(
			"evalMatch = radare2 rule result evidence missmatch"+
				", expected %q match, got: %q match",
			1,
			len(res))
	}
}

func TestUevalMatchExact(t *testing.T) {
	var r model.Rule
	var sigs []interface{}

	sigs = append(sigs, "Secret")

	r.Handler = "radare2"
	r.MatchType = "exact"
	r.MatchValue = sigs
	r.Type = "strings"
	r.Name = "part_1"
	r.Invert = false

	expectFilePath := "test/file/path"
	expectName := "superSecretValueTest"
	expectOffset := "0x1337"

	testMatchData := make(map[string]string, 0)
	testMatchData["name"] = expectName
	testMatchData["offset"] = expectOffset

	res := evalMatch(expectFilePath, r, r.MatchValue[0].(string), testMatchData)

	if len(res) != 1 {
		t.Errorf(
			"evalMatch = radare2 rule result evidence missmatch"+
				", expected %q match, got: %q match",
			1,
			len(res))

		// Don't run the deeper tests as there is nothing to test
		return
	}

	if res[0].File != expectFilePath {
		t.Errorf(
			"evalMatch = radare2 evidence file mismatch, expected %q, got %q",
			expectFilePath,
			res[0].File)
	}

	if res[0].Name != expectName {
		t.Errorf(
			"evalMatch = radare2 evidence name mismatch, expected %q, got %q",
			expectName,
			res[0].Name)
	}

	if res[0].Offset != expectOffset {
		t.Errorf(
			"evalMatch = radare2 evidence offset mismatch, expected %q, got %q",
			expectOffset,
			res[0].Offset)
	}

	if res[0].RuleName != r.Name {
		t.Errorf(
			"evalMatch = radare2 evidence rule name mismatch, expected %q, got %q",
			r.Name,
			res[0].RuleName)
	}

	negativeMatchRegex := "sEcReT"
	negativeRes := evalMatch(
		expectFilePath,
		r,
		negativeMatchRegex,
		testMatchData)

	if len(negativeRes) != 0 {
		t.Errorf(
			"evalMatch = radare2 rule result evidence missmatch"+
				", expected %q match, got: %q match",
			1,
			len(res))
	}
}
