package yarahandler

import (
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/hillu/go-yara"

	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

var yaraAnalysisBundle map[string]map[string][]map[string]string

func init() {
	yaraAnalysisBundle = make(map[string]map[string][]map[string]string, 0)
}

// PrepareAnal - gathers all the relevant data required for analysis
func PrepareAnal(binaryPaths []string, wg *sync.WaitGroup) {
	defer wg.Done()

	fmt.Println("*** Yara handler pre-analysis starting ***")

	yaraRuleResults := make(map[string][]map[string]string, 0)

	yaraRuleFilePaths := utils.GetRuleFiles(".yara")

	for index, path := range binaryPaths {
		fmt.Println("\tanalysing file ->", index, path)

		for _, yaraRulePath := range yaraRuleFilePaths {
			fmt.Println("\t\t-> Yara file:", yaraRulePath)

			yaraRuleMatches := make(chan []map[string]string)

			go func(p string, rp string) {
				yaraRuleMatches <- runYaraRule(p, rp)
			}(path, yaraRulePath)

			yaraRuleResults[yaraRulePath] = <-yaraRuleMatches
			close(yaraRuleMatches)
		}

		yaraAnalysisBundle[path] = yaraRuleResults
	}

	fmt.Println("*** Yara handler pre-analysis complete ***")
}

func runYaraRule(binaryPath string, rulePath string) []map[string]string {

	fmt.Println("[INFO] Running yara rule", rulePath, "on", binaryPath)

	c, err := yara.NewCompiler()
	if err != nil {
		panic(err)
	}

	f, err := os.Open(rulePath)
	if err != nil {
		panic(err)
	}

	err = c.AddFile(f, "mobprotid")
	f.Close()

	if err != nil {
		panic(err)
	}

	r, err := c.GetRules()
	if err != nil {
		panic(err)
	}

	yaraMatches, err := r.ScanFile(binaryPath, 0, 0)
	if err != nil {
		panic(err)
	}

	return parseYaraMatches(yaraMatches)
}

func parseYaraMatches(yaraMatchRuleObject []yara.MatchRule) []map[string]string {

	parentMatches := make([]map[string]string, 0)

	for _, yaraMatch := range yaraMatchRuleObject {

		// log.Printf("-[%s] %s", yaraMatch.Namespace, yaraMatch.Rule)
		// log.Printf("\t\ttags: %s", yaraMatch.Tags)

		// if _, ok := yaraMatch.Meta["author"]; ok {
		// 	log.Printf("\t\tauthor: %s", yaraMatch.Meta["author"])
		// }
		// if _, ok := yaraMatch.Meta["description"]; ok {
		// 	log.Printf("\t\tdescription: %s", yaraMatch.Meta["description"])
		// }

		for _, m := range yaraMatch.Strings {

			childMatch := make(map[string]string, 0)

			// log.Printf("\t\t\tRule part name: %q", m.Name)

			childMatch["name"] = string(m.Data[:])
			childMatch["offset"] = strconv.FormatUint(m.Offset, 10)
			childMatch["rule"] = yaraMatch.Rule

			parentMatches = append(parentMatches, childMatch)
		}
	}

	return parentMatches
}
