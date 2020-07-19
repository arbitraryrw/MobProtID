package engine

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/arbitraryrw/MobProtID/internal/app/ruleparser"
	"github.com/arbitraryrw/MobProtID/internal/pkg/r2handler"
	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
	"github.com/arbitraryrw/MobProtID/internal/pkg/yarahandler"
)

//Description Dummy function to check scope
func Description() string {
	return "Engine coming in!"
}

// Start initialises the core analysis orchestration logic
func Start(bp string, testRuleSet bool) {
	fmt.Println("[INFO] Engine Starting..")
	fmt.Println("[INFO] Analysis artifacts stored: ", utils.AnalysisDir)

	var rules []string
	analFileBaseName := filepath.Base(bp)
	platform := "unknown"
	filesOfInterest := []string{}

	if analFileBaseName[len(analFileBaseName)-4:] == ".apk" {
		platform = "android"
		filesOfInterest = append(filesOfInterest, ".so", "2.dex")

		if testRuleSet {
			rules = utils.GetRuleFiles("test_android_rules.json")
		} else {
			rules = utils.GetRuleFiles("prod_android_rules.json")
		}

	} else if analFileBaseName[len(analFileBaseName)-4:] == ".ipa" {
		platform = "ios"
		filesOfInterest = append(filesOfInterest, ".dylib")

		if testRuleSet {
			rules = utils.GetRuleFiles("test_ios_rules.json")
		} else {
			rules = utils.GetRuleFiles("prod_ios_rules.json")
		}
	}

	if platform == "unknown" {
		panic("Engine unable to recognise file ending, must be either ipa / apk.")
	}

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

	wg.Add(1)
	go yarahandler.PrepareAnal(parsedBinaryFilePaths, &wg)
	wg.Wait()

	fmt.Println("RULE FILES ->", rules)
	ruleResults := ruleparser.ParseRuleFile(rules)

	for k, v := range ruleResults {
		fmt.Println("[INFO] Results for rule file", k)
		for _, rr := range v {
			fmt.Println("\t", rr.RuleID, rr.RuleName, rr.Match)
			fmt.Println("\t\t", len(rr.Evidence), "Evidence entries:")

			for _, e := range rr.Evidence {
				fmt.Println("\t\t", e)
			}
		}
	}

	utils.CreateTempFile("phaseOne.json")

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
