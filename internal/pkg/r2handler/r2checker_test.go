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
	sampleBinaryRelPath := "../../../test/sample_binary.so"
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

func TestHandleRuleStrings(t *testing.T) {
	// ToDo: test for:
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

	validateRuleResult(r,
		"It's MobProtID here!",
		"1918",
		t)
}

func TestHandleRuleSymbols(t *testing.T) {
	var r model.Rule
	var sigs []interface{}

	sigs = append(sigs, "(?i)(^_init$)")

	r.Handler = "radare2"
	r.MatchType = "regex"
	r.MatchValue = sigs
	r.Type = "symbols"
	r.Name = "part_1"
	r.Invert = false

	validateRuleResult(r,
		"_init",
		"1344",
		t)
}

func TestHandleRuleFunctions(t *testing.T) {
	var r model.Rule
	var sigs []interface{}

	sigs = append(sigs, "(?i)(^entry.init0$)")

	r.Handler = "radare2"
	r.MatchType = "regex"
	r.MatchValue = sigs
	r.Type = "functions"
	r.Name = "part_1"
	r.Invert = false

	validateRuleResult(r,
		"entry.init0",
		"1696",
		t)
}

func TestHandleRuleSysCalls(t *testing.T) {
	var r model.Rule
	var sigs []interface{}

	sigs = append(sigs, "(?i)(.*)")

	r.Handler = "radare2"
	r.MatchType = "regex"
	r.MatchValue = sigs
	r.Type = "sysCalls"
	r.Name = "part_1"
	r.Invert = false

	result := HandleRule(r)

	fmt.Println(result)
}

func TestHandleRulePicCompilerFlags(t *testing.T) {
	var r model.Rule
	var sigs []interface{}

	sigs = append(sigs, "(?i)(^true$)")

	r.Handler = "radare2"
	r.MatchType = "regex"
	r.MatchValue = sigs
	r.Type = "picCompilerFlag"
	r.Name = "part_1"
	r.Invert = false

	validateRuleResult(r,
		"true",
		"0x0",
		t)
}

func TestHandleRuleCanaryCompilerFlags(t *testing.T) {
	var r model.Rule
	var sigs []interface{}

	sigs = append(sigs, "(?i)(^false$)")

	r.Handler = "radare2"
	r.MatchType = "regex"
	r.MatchValue = sigs
	r.Type = "canaryCompilerFlag"
	r.Name = "part_1"
	r.Invert = false

	validateRuleResult(r,
		"false",
		"0x0",
		t)
}

func TestHandleRuleStrippedCompilerFlags(t *testing.T) {
	var r model.Rule
	var sigs []interface{}

	sigs = append(sigs, "(?i)(^false$)")

	r.Handler = "radare2"
	r.MatchType = "regex"
	r.MatchValue = sigs
	r.Type = "strippedCompilerFlag"
	r.Name = "part_1"
	r.Invert = false

	validateRuleResult(r,
		"false",
		"0x0",
		t)
}

func validateRuleResult(
	rule model.Rule,
	expectMatchName string,
	expectMatchOffset string,
	t *testing.T) {

	result := HandleRule(rule)

	if result.Match != true {
		t.Errorf(
			"HandleRule = radare2 rule match result mismatch,"+
				"expected %t, got %t",
			true,
			result.Match)
	}

	if len(result.Evidence) != 1 {
		t.Errorf(
			"HandleRule = radare2 rule result evidence"+
				"mismatch, expected %q match, got %q",
			1,
			len(result.Evidence))

		return
	}

	if result.Evidence[0].File != testBinPath {
		t.Errorf(
			"HandleRule = radare2 rule result path mismatch,"+
				"expected %q, got %q",
			testBinPath,
			result.Evidence[0].File)
	}

	if result.Evidence[0].RuleName != rule.Name {
		t.Errorf(
			"HandleRule = radare2 rule result mismatch,"+
				"expected %q, got %q",
			rule.Name,
			result.Evidence[0].RuleName)
	}
	if result.Evidence[0].Name != expectMatchName {
		t.Errorf(
			"HandleRule = radare2 rule result name mismatch,"+
				"expected %q, got %q",
			expectMatchName,
			result.Evidence[0].Name)
	}
	if result.Evidence[0].Offset != expectMatchOffset {
		t.Errorf(
			"HandleRule = radare2 rule result offset mismatch,"+
				"expected %q, got %q",
			expectMatchOffset,
			result.Evidence[0].Offset)
	}

	rule.Invert = true
	result = HandleRule(rule)

	if result.Match != false {
		t.Errorf(
			"HandleRule = radare2 result mismatch, expected"+
				" inverted result of %t, got %t",
			false,
			result.Match)
	}

	rule.Invert = false

	var negativeSigs []interface{}
	negativeSigs = append(negativeSigs, "(?i)(^thisShouldNotMatchAtAll$)")
	rule.MatchValue = negativeSigs

	negativeResults := HandleRule(rule)

	if negativeResults.Match != false {
		t.Errorf(
			"HandleRule = radare2 result mismatch, expected %t, got %t",
			true,
			result.Match)
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
