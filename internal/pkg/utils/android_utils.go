package utils

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

func GetDroidManifest() string {
	//aapt dump xmltree ../dummy_app_MobProtID.apk AndroidManifest.xml

	app := "aapt"

	if ok := IsCommandAvailable(app); ok {

		// Arguments for AAPT
		arg0 := "dump"
		arg1 := "xmltree"
		arg2 := AnalysisBinPath
		arg3 := "AndroidManifest.xml"

		cmd := exec.Command(app, arg0, arg1, arg2, arg3)
		stdout, err := cmd.Output()

		if err != nil {
			panic(err.Error())
		}

		var rawCommandOutput string = string(stdout)

		scanner := bufio.NewScanner(strings.NewReader(rawCommandOutput))

		for scanner.Scan() {
			fmt.Println(scanner.Text()[3:])

			if strings.Contains(scanner.Text()[3:], "android") {
				fmt.Println("yep!")
			}
			break
		}

		return "Getting android manifest details.."

	} else {
		panic("Unable to find aapt installed, make sure android-sdk is installed.")
	}

}
