package yarahandler

import (
	"fmt"
	"log"
	"os"
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

	for index, path := range binaryPaths {
		fmt.Println("\tanalysing file ->", index, path)

		yaraRuleFilePaths := utils.GetRuleFiles(".yara")

		for _, yaraRulePath := range yaraRuleFilePaths {
			fmt.Println("\t\t-> Yara file:", yaraRulePath)

			yaraRuleMatches := make(chan []map[string]string)

			go func(p string, rp string) {
				yaraRuleMatches <- testYara(p, rp)
			}(path, yaraRulePath)

			yaraRuleResults[yaraRulePath] = <-yaraRuleMatches
			close(yaraRuleMatches)
		}

		yaraAnalysisBundle[path] = yaraRuleResults
	}

	fmt.Println("*** Yara handler pre-analysis complete ***")
}

func testYara(binaryPath string, rulePath string) []map[string]string {

	fmt.Println("------------------------:", binaryPath, rulePath)
	tParent := make([]map[string]string, 0)
	tChild := make(map[string]string, 0)

	tChild["name"] = "test name"
	tChild["offset"] = "0xffff"

	tParent = append(tParent, tChild)

	return tParent
}

func runYaraRule(ruleFileName string) {

	rules := utils.GetRuleFiles(ruleFileName)

	for _, rulePath := range rules {

		fmt.Println("[INFO] Running yara rule", rulePath)

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

		m, err := r.ScanFile("/bin/ls", 0, 0)
		printMatches(m, err)

	}

	for file, yaraRuleFile := range yaraAnalysisBundle {

		fmt.Println("File", file)

		for yaraFile, yaraMatches := range yaraRuleFile {
			fmt.Println("\tyara rule file", yaraFile, yaraMatches)
		}
	}
}

func printMatches(m []yara.MatchRule, err error) {
	if err == nil {
		if len(m) > 0 {
			for _, match := range m {
				log.Printf("-[%s] %s", match.Namespace, match.Rule)

				if _, ok := match.Meta["author"]; ok {
					log.Printf("\t\tauthor: %s", match.Meta["author"])
				}
				if _, ok := match.Meta["description"]; ok {
					log.Printf("\t\tdescription: %s", match.Meta["description"])
				}

				log.Printf("\t\ttags: %s", match.Tags)
				log.Println("\t\tMatches:")

				for _, m := range match.Strings {
					log.Printf("\t\t\tRule Name: %q", m.Name)
					log.Printf("\t\t\tBinary Offset: %d", m.Offset)
					log.Printf("\t\t\tString Match: %q", m.Data)
					log.Printf("---")
				}
			}
		} else {
			log.Print("no matches.")
		}
	} else {
		log.Printf("error: %s.", err)
	}
}
