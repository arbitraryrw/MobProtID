package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/arbitraryrw/MobProtID/internal/app/engine"
	"github.com/arbitraryrw/MobProtID/internal/app/ruleparser"
)

func init() {
	fmt.Println("*** MobProtID Starting ***")
}

func main() {
	wordPtr := flag.String("target", "", "The target artifact to analyse")
	flag.Parse()

	if *wordPtr != "" {
		fmt.Println("target:", *wordPtr)

		var targetPath string

		if string(*wordPtr)[:1] == "~" {

			usr, _ := user.Current()
			homeDir := usr.HomeDir

			targetPath = filepath.Join(homeDir, string(*wordPtr)[1:])

		} else {
			targetPath, _ = filepath.Abs(*wordPtr)
		}

		if _, err := os.Stat(targetPath); err == nil {

			ruleparser.ParseRuleFile()

			return
			engine.Start(targetPath)

		} else {
			fmt.Println(targetPath, "File does not exist")
		}

	} else {
		fmt.Println("No target provided, please enter a valid path")
	}
}
