package engine

import (
	"fmt"

	"github.com/arbitraryrw/MobProtID/internal/pkg/yarahandler"
)

//Description Dummy function to check scope
func Description() string {
	return "Engine coming in!"
}

// Start initialises the core analysis orchestration logic
func Start() {
	fmt.Println("[INFO] Engine Starting..")

	fmt.Println("[INFO] R2 Running...")
	r2handler.PrepareAnal()

	fmt.Println("[INFO] Yara Running...")
	yarahandler.Main()

	r := []string{"ruleOne", "ruletwo", "rulethree", "rulefour", "rulefive"}
	nextRule := ruleSequence(r...)
	fmt.Println(nextRule())
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
