package yarahandler

import (
	"testing"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
)

func init() {}

func TestHandleRule(t *testing.T) {

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
			"createEvidenceStruct = yara evidence struct empty, got: %q",
			evidence)
	}

	if evidence.File != expectPath {
		t.Errorf(
			"createEvidenceStruct = yara evidence file mismatch, expected %q, got %q",
			expectPath,
			evidence.File)
	}

	if evidence.Name != expectName {
		t.Errorf(
			"createEvidenceStruct = yara evidence name mismatch, expected %q, got %q",
			expectName,
			evidence.Name)
	}

	if evidence.Offset != expectOffset {
		t.Errorf(
			"createEvidenceStruct = yara evidence offset mismatch, expected %q, got %q",
			expectOffset,
			evidence.Offset)
	}

	if evidence.RuleName != expectRuleName {
		t.Errorf(
			"createEvidenceStruct = yara evidence rule name mismatch, expected %q, got %q",
			expectRuleName,
			evidence.RuleName)
	}
}
