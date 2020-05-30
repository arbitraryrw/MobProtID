package engine

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/arbitraryrw/MobProtID/internal/app/ruleparser"
	"github.com/arbitraryrw/MobProtID/internal/pkg/r2handler"
	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

//Description Dummy function to check scope
func Description() string {
	return "Engine coming in!"
}

// Start initialises the core analysis orchestration logic
func Start(bp string) {
	fmt.Println("[INFO] Engine Starting..")
	fmt.Println("[INFO] Analysis artifacts stored: ", utils.AnalysisDir)

	var rules []string
	analFileBaseName := filepath.Base(bp)
	platform := "unknown"
	filesOfInterest := []string{}

	if analFileBaseName[len(analFileBaseName)-4:] == ".apk" {
		platform = "android"
		filesOfInterest = append(filesOfInterest, ".so", "2.dex")
		rules = utils.GetRuleFiles("android_rules.json")

	} else if analFileBaseName[len(analFileBaseName)-4:] == ".ipa" {
		platform = "ios"
		filesOfInterest = append(filesOfInterest, ".dylib")
		rules = utils.GetRuleFiles("ios_rules.json")
	}

	if platform == "unknown" {
		panic("Engine unable to recognise file ending, must be either ipa / apk.")
	}

	fmt.Println("RULE FILES ->", rules)
	ruleResults := ruleparser.ParseRuleFile(rules)
	fmt.Println("[INFO] All Rule Files Results", ruleResults)

	return

	utils.CreateAnalysisDir(bp)
	utils.PrepBinaryForAnal(bp)

	fmt.Println("[INFO] R2 Running...")

	parsedBinaryFilePaths := make([]string, 0)

	// parsedBinaryFilePaths = append(parsedBinaryFilePaths, bp, "/bin/bash")

	matchedFiles := utils.FindFilesInDir(filesOfInterest, utils.UnzippedAnalBinPath)
	parsedBinaryFilePaths = append(parsedBinaryFilePaths, matchedFiles...)

	fmt.Println(parsedBinaryFilePaths)

	if platform == "android" {
		manifestProps := utils.GetDroidManifest(utils.AnalysisBinPath)
		fmt.Println(manifestProps)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go r2handler.PrepareAnal(parsedBinaryFilePaths, &wg)

	// fmt.Println("[INFO] Yara Running...")
	// yarahandler.Main()

	wg.Wait()

	results := r2handler.Anal()

	fmt.Println("[INFO] Static analysis results:", results)

	// r := []string{"ruleOne", "ruletwo", "rulethree", "rulefour", "rulefive"}
	// nextRule := ruleSequence(r...)
	// fmt.Println(nextRule())

	// fmt.Println("Engine Finished")
}

func ruleSequence(rules ...string) func() string {
	i := 0

	return func() string {
		if i < len(rules) {
			ret := rules[i]
			i++
			return ret
		} else {
			return ""
		}
	}

}
