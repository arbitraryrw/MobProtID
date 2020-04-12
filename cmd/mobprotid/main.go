package main

import (
	"fmt"

	"github.com/arbitraryrw/MobProtID/internal/app/engine"

	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"

	"github.com/arbitraryrw/MobProtID/internal/app/ruleparser"
)

func main() {
	fmt.Println("MobProtID Starting..")
	fmt.Println(engine.Description())
	fmt.Println(utils.Description())

	ruleparser.ParseRuleFile()

	engine.Testr2()
}
