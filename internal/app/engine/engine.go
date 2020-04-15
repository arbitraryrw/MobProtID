package engine

import (
	"fmt"
	"sync"

	"github.com/arbitraryrw/MobProtID/internal/pkg/r2handler"
)

//Description Dummy function to check scope
func Description() string {
	return "Engine coming in!"
}

// Start initialises the core analysis orchestration logic
func Start(bp string) {
	fmt.Println("[INFO] Engine Starting..")

	fmt.Println("[INFO] R2 Running...")

	var wg sync.WaitGroup

	wg.Add(1)
	go r2handler.PrepareAnal(bp, &wg)

	// fmt.Println("[INFO] Yara Running...")
	// yarahandler.Main()

	wg.Wait()

	// r := []string{"ruleOne", "ruletwo", "rulethree", "rulefour", "rulefive"}
	// nextRule := ruleSequence(r...)
	// fmt.Println(nextRule())

	fmt.Println("Engine Finished")
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
