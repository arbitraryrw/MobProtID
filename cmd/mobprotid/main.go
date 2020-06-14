package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/arbitraryrw/MobProtID/internal/app/engine"
)

func init() {
	fmt.Println("*** MobProtID Starting ***")
}

func main() {
	targetPtr := flag.String("target",
		"",
		"The target artifact to analyse")

	testFlagPtr := flag.Bool(
		"test",
		false,
		"Use the test ruleset instead of the stable ruleset")

	flag.Parse()

	if *targetPtr != "" {
		fmt.Println("target:", *targetPtr)

		var targetPath string

		if string(*targetPtr)[:1] == "~" {

			usr, _ := user.Current()
			homeDir := usr.HomeDir

			targetPath = filepath.Join(homeDir, string(*targetPtr)[1:])

		} else {
			targetPath, _ = filepath.Abs(*targetPtr)
		}

		if _, err := os.Stat(targetPath); err == nil {

			engine.Start(targetPath, *testFlagPtr)

		} else {
			fmt.Println(targetPath, "File does not exist")
		}

	} else {
		fmt.Println("No target provided, please enter a valid path")
	}
}
