package main

import (
	"fmt"

	"github.com/arbitraryrw/MobProtID/internal/app/engine"

	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

func main() {
	fmt.Println("MobProtID Starting..")
	fmt.Println(engine.Description())
	fmt.Println(utils.Description())
}
