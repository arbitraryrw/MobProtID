package r2handler

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

func init() {

	abs, err := filepath.Abs("../../../test/dummy_app_MobProtID.apk")
	if err != nil {
		panic("Unable to generate path to test file.")
	}

	utils.CreateAnalysisDir(abs)
	utils.PrepBinaryForAnal(abs)
}

func TestUgetStringEntireBinary(t *testing.T) {

	r2s := openR2Pipe("../../../test/sample_binary.so")

	var expectString = "It's MobProtID here!"
	var expectOffset = "1918"
	got := getStringEntireBinary(r2s)

	var result = false

	for _, val := range got {
		if strings.Compare(expectString, val["name"]) == 0 &&
			val["offset"] == expectOffset {
			result = true
		}
	}

	if result == false {
		fmt.Println("Failed comparison!")
		t.Errorf("getStringEntireBinary() = could not find %q at offset %q in sample_binary r2 reponse", expectString, expectOffset)
	}
}

func TestUgetSysCalls(t *testing.T) {

	var result = false

	r2s := openR2Pipe("/bin/bash")
	expectSyscallName := "read"
	got := getSysCalls(r2s)

	if len(got) > 0 {
		for _, v := range got {
			if v["name"] == expectSyscallName &&
				strings.Contains(v["offset"], "0x") {
				result = true
				break
			}
		}
	}

	if result == false {
		fmt.Println("Failed comparison!")
		t.Errorf("getSysCalls = could not find %q with valid offset in /bin/bash r2 reponse",
			expectSyscallName)
	}
}

func TestUgetFunctions(t *testing.T) {

	result := false

	testFile := []string{"classes2.dex"}
	matchedFiles := utils.FindFilesInDir(testFile, utils.UnzippedAnalBinPath)

	if len(matchedFiles) < 0 {
		t.Errorf("Unable to find test file %q in analysis directory %q", testFile[0], utils.UnzippedAnalBinPath)
	}

	r2s := openR2Pipe(matchedFiles[0])

	expect := "method.public.final.Lcom_example_dummyapplication" +
		"_SensitiveLogic.Lcom_example_dummyapplication_SensitiveLogic" +
		".method.rootDetection__Z"

	got := getFunctions(r2s)

	for _, f := range got {
		if _, ok := f["name"]; !ok {
			t.Error("getFunctions() = map missing name attribute.")
		}

		if _, ok := f["offset"]; !ok {
			t.Error("getFunctions() = map missing name attribute.")
		}

		if f["name"] == expect && f["offset"] == "79828" {
			result = true
		}

	}

	if result == false {
		t.Errorf("getFunctions() = could not find %q in %q r2 reponse",
			expect,
			matchedFiles[0])
	}
}

func TestUgetFunctionsAndClasses(t *testing.T) {

	classResult := false
	methodResult := false
	fieldResult := false

	testFile := []string{"classes2.dex"}
	matchedFiles := utils.FindFilesInDir(testFile, utils.UnzippedAnalBinPath)

	if len(matchedFiles) < 0 {
		t.Errorf(
			"Unable to find test file %q in analysis directory %q",
			testFile[0],
			utils.UnzippedAnalBinPath)
	}

	r2s := openR2Pipe(matchedFiles[0])

	expectClassName := "com/example/dummyapplication/SensitiveLogic"
	expectClassOffset := "63404"

	expectMethodName := "rootDetection"
	expectMethodOffset := "79828"

	expectFieldName := "SensitiveLogic.ifield_c:Landroid/content/Context"
	expectFieldOffset := "54820"

	got := getClassMethFields(r2s)

	for _, bundle := range got {

		if classBundle, ok := bundle["class"]; ok {
			for _, c := range classBundle {
				if strings.Contains(c["name"], expectClassName) &&
					c["offset"] == expectClassOffset {
					classResult = true
				}
			}
		}

		if methodBundle, ok := bundle["methods"]; ok {
			for _, m := range methodBundle {
				if strings.Contains(m["name"], expectMethodName) &&
					m["offset"] == expectMethodOffset {
					methodResult = true
				}
			}
		}

		if fieldBundle, ok := bundle["fields"]; ok {
			for _, f := range fieldBundle {
				if strings.Contains(f["name"], expectFieldName) &&
					f["offset"] == expectFieldOffset {
					fieldResult = true
				}
			}
		}

	}

	if classResult == false {
		t.Errorf(
			"getFunctionsAndClasses() = could not find class %q at offset %q in %q r2 reponse",
			expectClassName,
			expectClassOffset,
			matchedFiles[0])
	}

	if methodResult == false {
		t.Errorf(
			"getFunctionsAndClasses() = could not find method %q at offset %q in %q r2 reponse",
			expectMethodName,
			expectMethodOffset,
			matchedFiles[0])
	}

	if fieldResult == false {
		t.Errorf(
			"getFunctionsAndClasses() = could not find field %q at offset %q in %q r2 reponse",
			expectFieldName,
			expectFieldOffset,
			matchedFiles[0])
	}
}
