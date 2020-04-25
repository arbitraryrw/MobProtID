package utils

import (
	"bufio"
	"encoding/hex"
	"os/exec"
	"strconv"
	"strings"
)

// GetDroidManifest parses the target binaries AndroidManifest.xml file
func GetDroidManifest(abs string) map[string]string {
	//aapt dump xmltree ../dummy_app_MobProtID.apk AndroidManifest.xml

	app := "aapt"

	if ok := IsCommandAvailable(app); ok {

		// Arguments for AAPT
		arg0 := "dump"
		arg1 := "xmltree"
		arg2 := abs
		arg3 := "AndroidManifest.xml"

		cmd := exec.Command(app, arg0, arg1, arg2, arg3)
		stdout, err := cmd.Output()

		if err != nil {
			panic(err.Error())
		}

		var rawCommandOutput string = string(stdout)

		var parsedOutput map[string]string = make(map[string]string, 0)

		scanner := bufio.NewScanner(strings.NewReader(rawCommandOutput))

		for scanner.Scan() {

			ct := scanner.Text()[3:]

			if strings.Contains(ct, "android:debuggable") {

				//A: android:debuggable(0x0101000f)=(type 0x12)0xffffffff (means debuggable is true)
				//A: android:debuggable(0x0101000f)=(type 0x12)0x0 (means debuggable is false)
				if len(ct) > 10 && ct[len(ct)-10:] == "0xffffffff" {
					parsedOutput["debuggable"] = "true"
				} else {
					parsedOutput["debuggable"] = "false"
				}

			} else if strings.Contains(ct, "android:allowBackup") {

				if len(ct) > 10 && ct[len(ct)-10:] == "0xffffffff" {
					parsedOutput["allowBackup"] = "true"
				} else {
					parsedOutput["allowBackup"] = "false"
				}

			} else if strings.Contains(ct, "android:targetSdkVersion") {

				if len(ct) > 4 {

					tvHex := strings.Split(ct[len(ct)-4:], "0x")

					bs, err := hex.DecodeString(tvHex[1])
					if err != nil {
						panic(err)
					}

					if len(bs) > 0 {
						parsedOutput["targetSdkVersion"] = strconv.Itoa(int(bs[0]))
					}

				}

			} else if strings.Contains(ct, "android:minSdkVersion") {

				if len(ct) > 4 {

					mvHex := strings.Split(ct[len(ct)-4:], "0x")

					bs, err := hex.DecodeString(mvHex[1])
					if err != nil {
						panic(err)
					}

					if len(bs) > 0 {
						parsedOutput["minSdkVersion"] = strconv.Itoa(int(bs[0]))
					}

				}

			} else if strings.Contains(ct, "package=\"") {
				s := strings.Split(ct, "\"")

				if len(s) > 1 {
					parsedOutput["package"] = s[1]
				}
			}

		}

		return parsedOutput

	} else {
		panic("Unable to find aapt installed, make sure android-sdk is installed.")
	}

}
