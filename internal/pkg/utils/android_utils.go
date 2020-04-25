package utils

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

// GetDroidManifest parses the target binaries AndroidManifest.xml file
func GetDroidManifest() map[string]string {
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

		var parsedOutput map[string]string = make(map[string]string, 0)

		scanner := bufio.NewScanner(strings.NewReader(rawCommandOutput))

		//A: android:debuggable(0x0101000f)=(type 0x12)0xffffffff (means debuggable is true)
		//A: android:debuggable(0x0101000f)=(type 0x12)0x0 (means debuggable is false)
		for scanner.Scan() {

			// fmt.Println(scanner.Text()[len(scanner.Text())-10:])
			ct := scanner.Text()[3:]

			if strings.Contains(ct, "android:debuggable") {
				fmt.Println("Found debuggable!")
				fmt.Println()

				if len(ct) > 10 && ct[len(ct)-10:] == "0xffffffff" {
					fmt.Println("It's defo allowed..")
				} else {

				}

			} else if strings.Contains(ct, "android:allowBackup") {
				fmt.Println("Found allowbackup!")
				fmt.Println(ct)

			} else if strings.Contains(ct, "android:targetSdkVersion") {
				fmt.Println("Found targetSdkVersion!")
				fmt.Println(ct)

			} else if strings.Contains(ct, "android:minSdkVersion") {
				fmt.Println("Found minSdkVersion!")
				fmt.Println(ct)

			} else if strings.Contains(ct, "package=\"") {
				s := strings.Split(ct, "\"")

				if len(s) > 1 {
					parsedOutput["pName"] = s[1]
				}
			}

		}

		return parsedOutput

	} else {
		panic("Unable to find aapt installed, make sure android-sdk is installed.")
	}

}
