package yarahandler

import (
	"log"
	"os"
	"path"

	"github.com/hillu/go-yara"

	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

func Main() {

	rulePath := path.Join(utils.GetProjectRootDir(), "rules/example.yara")

	c, err := yara.NewCompiler()
	if err != nil {
		panic(err)
	}

	f, err := os.Open(rulePath)
	if err != nil {
		panic(err)
	}

	err = c.AddFile(f, "poc-tests")
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
				}
			}
		} else {
			log.Print("no matches.")
		}
	} else {
		log.Printf("error: %s.", err)
	}
}
