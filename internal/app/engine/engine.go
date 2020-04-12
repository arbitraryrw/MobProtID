package engine

import (
	"fmt"

	"github.com/arbitraryrw/MobProtID/internal/pkg/r2handler"
	"github.com/arbitraryrw/MobProtID/internal/pkg/yarahandler"
)

//Description Dummy function to check scope
func Description() string {
	return "Engine coming in!"
}

func Start() {
	fmt.Println("[INFO] Engine Starting..")

	fmt.Println("[INFO] R2 Running...")
	r2handler.Testr2()

	fmt.Println("[INFO] Yara Running...")
	yarahandler.Main()
}
