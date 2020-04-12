package main

import (
	"fmt"

	"github.com/arbitraryrw/MobProtID/internal/app/engine"

	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"

	"github.com/arbitraryrw/MobProtID/internal/app/ruleparser"

	"github.com/arbitraryrw/MobProtID/internal/pkg/r2handler"

	"github.com/arbitraryrw/MobProtID/internal/pkg/yarahandler"
)

func main() {
	fmt.Println("MobProtID Starting..")
	fmt.Println(engine.Description())
	fmt.Println(utils.Description())

	ruleparser.ParseRuleFile()

	r2handler.Testr2()
	yarahandler.Main()
}
