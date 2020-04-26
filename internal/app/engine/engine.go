package engine

import (
	"fmt"
	"sync"

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

	utils.CreateAnalysisDir(bp)
	utils.PrepBinaryForAnal(bp)

	fmt.Println("[INFO] R2 Running...")

	parsedBinaryFilePaths := make([]string, 0)

	// parsedBinaryFilePaths = append(parsedBinaryFilePaths, bp, "/bin/bash")

	filesOfInterest := []string{".so", ".dex"}
	matchedFiles := utils.FindFilesInDir(filesOfInterest, utils.UnzippedAnalBinPath)
	parsedBinaryFilePaths = append(parsedBinaryFilePaths, matchedFiles...)

	fmt.Println(parsedBinaryFilePaths)

	manifestProps := utils.GetDroidManifest(utils.AnalysisBinPath)
	fmt.Println(manifestProps)

	var wg sync.WaitGroup

	wg.Add(1)
	go r2handler.PrepareAnal(parsedBinaryFilePaths, &wg)

	// fmt.Println("[INFO] Yara Running...")
	// yarahandler.Main()

	wg.Wait()

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
