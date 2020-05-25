package yarahandler

import (
	"fmt"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
)

func HandleRule(r model.Rule) bool {
	fmt.Println("[INFO] Yara handling rule: ", r)

	return true
}
