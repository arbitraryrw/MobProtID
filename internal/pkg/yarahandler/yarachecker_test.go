package yarahandler

import (
	"testing"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
)

func init() {}

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
}
