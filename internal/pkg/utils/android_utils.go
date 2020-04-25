package utils

import (
	"fmt"
	"os/exec"
)

func GetDroidManifest() string {
	//aapt dump xmltree ../dummy_app_MobProtID.apk AndroidManifest.xml

	app := "aapt"

	// Arguments for AAPT
	arg0 := "dump"
	arg1 := "xmltree"
	arg2 := AnalysisBinPath
	arg3 := "AndroidManifest.xml"

	cmd := exec.Command(app, arg0, arg1, arg2, arg3)
	stdout, err := cmd.Output()

	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println(string(stdout))

	return "Getting android manifest details.."
}
