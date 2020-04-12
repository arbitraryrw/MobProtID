package main

import (
	"fmt"

	"github.com/arbitraryrw/MobProtID/internal/app/engine"

	"github.com/arbitraryrw/MobProtID/internal/app/ruleparser"
)

func main() {
	fmt.Println("*** MobProtID Starting ***")

	ruleparser.ParseRuleFile()
	engine.Start()
}
