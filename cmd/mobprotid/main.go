package main

import (
	"flag"
	"fmt"

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

		ruleparser.ParseRuleFile()
		engine.Start()
	} else {
		fmt.Println("No target provided, please enter a valid path")
	}
}
