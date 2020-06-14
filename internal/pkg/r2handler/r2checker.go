package r2handler

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/arbitraryrw/MobProtID/internal/pkg/model"
	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"
)

var detectionAnalResults map[string]bool

func HandleRule(r model.Rule) model.RuleResult {
	fmt.Println("[INFO] Handling rule: ", r)

	ruleName := r.Name
	matchType := r.MatchType
	matchValue := r.MatchValue
	ruleType := r.Type
	invert := r.Invert

	fmt.Println("[INFO] RuleType: ", ruleType)
	fmt.Println("[INFO] Matching against: ", matchType)

	var evidenceInstances []model.Evidence

	for _, val := range matchValue {

		if strings.ToLower(ruleType) == "strings" {

			fmt.Println("[INFO] Searching binary strings..")
			for k, v := range allStringsInBinary {
				// fmt.Println("[INFO] File ->", k)

				for _, s := range v {
					if strings.ToLower(matchType) == "regex" {

						for _, m := range utils.RegexMatch(s["name"], val.(string)) {
							evidence := createEvidenceStruct(k, m, s["offset"], ruleName)

							if (model.Evidence{}) != evidence {
								evidenceInstances = append(evidenceInstances, evidence)
							}
						}

					} else if strings.ToLower(matchType) == "exact" {

						for _, m := range utils.ExactMatch(s["name"], val.(string)) {
							evidence := createEvidenceStruct(k, m, s["offset"], ruleName)

							if (model.Evidence{}) != evidence {
								evidenceInstances = append(evidenceInstances, evidence)
							}
						}

					}
				}
			}

		} else if strings.ToLower(ruleType) == "symbols" {

			fmt.Println("[INFO] Searching binary symbols..")
			for file, v := range allSymbolsInBinary {
				// fmt.Println("[INFO] Symbol File ->", k)

				for _, s := range v {
					evidence := evalMatch(file, r, val.(string), s)
					evidenceInstances = append(evidenceInstances, evidence...)
				}
			}

		} else if strings.ToLower(ruleType) == "syscalls" {

			for file, syscallBundle := range allSyscall {

				for _, syscall := range syscallBundle {
					evidence := evalMatch(file, r, val.(string), syscall)
					evidenceInstances = append(evidenceInstances, evidence...)
				}
			}

		} else if strings.Contains(strings.ToLower(ruleType), "compilerflag") {

			var dataTarget string

			if strings.ToLower(ruleType[:3]) == "pic" {
				dataTarget = "pic"
			} else if strings.ToLower(ruleType[:6]) == "canary" {
				dataTarget = "canary"
			} else if strings.ToLower(ruleType[:8]) == "stripped" {
				dataTarget = "stripped"
			} else if strings.ToLower(ruleType[:8]) == "compiler" {
				dataTarget = "compiler"
			} else {
				panic(fmt.Sprintf(
					"[ERROR] Unknown rule type %q in %q",
					ruleType,
					ruleName))
			}

			for file, v := range allbinaryInfo {

				// fmt.Println("[INFO] Binary Info -->", file, allbinaryInfo)

				if len(file) < 4 {
					continue
				}

				fileEnding := filepath.Base(file)[len(filepath.Base(file))-4:]

				if fileEnding == ".so" || fileEnding == ".dylib" ||
					fileEnding == ".ipa" || fileEnding == ".dex" {

					if canary, ok := v[dataTarget]; ok {

						evidence := evalMatch(file, r, val.(string), canary)
						evidenceInstances = append(evidenceInstances, evidence...)

					}

				}
			}

		} else if strings.ToLower(ruleType) == "classobjects" {
			for file, bundle := range allBinClassAndFunc {

				for _, b := range bundle {

					if classes, ok := b["class"]; ok {
						for _, c := range classes {
							evidence := evalMatch(file, r, val.(string), c)
							evidenceInstances = append(evidenceInstances, evidence...)
						}
					} else {
						panic(fmt.Sprintf("[ERROR] No class object found in %q", b))
					}

				}
			}
		} else if strings.ToLower(ruleType) == "methodobjects" {
			for file, bundle := range allBinClassAndFunc {

				for _, b := range bundle {

					if methods, ok := b["methods"]; ok {
						for _, m := range methods {
							evidence := evalMatch(file, r, val.(string), m)
							evidenceInstances = append(evidenceInstances, evidence...)
						}
					}
				}
			}
		} else if strings.ToLower(ruleType) == "fieldobjects" {
			for file, bundle := range allBinClassAndFunc {
				fmt.Println("[INFO] Searching file", file)

				for _, b := range bundle {

					if fields, ok := b["fields"]; ok {
						for _, f := range fields {
							evidence := evalMatch(file, r, val.(string), f)
							evidenceInstances = append(evidenceInstances, evidence...)
						}
					}

				}
			}
		} else {
			panic(fmt.Sprintf("[ERROR] Unknown rule type %q in %q", r.Type, r.Name))
		}

	}

	var ruleResult model.RuleResult
	ruleResult.Evidence = evidenceInstances

	if len(evidenceInstances) > 0 {
		if invert {
			ruleResult.Match = false
		} else {
			ruleResult.Match = true
		}

	} else {
		if invert {
			ruleResult.Match = true
		} else {
			ruleResult.Match = false
		}
	}

	return ruleResult
}

func createEvidenceStruct(file string, name string, offset string, ruleName string) model.Evidence {
	var evidence model.Evidence

	evidence.File = file
	evidence.Name = name
	evidence.Offset = offset
	evidence.RuleName = ruleName

	return evidence
}

func evalMatch(file string, r model.Rule, matchValue string, data map[string]string) []model.Evidence {

	ruleName := r.Name
	matchType := r.MatchType

	var evidenceInstances []model.Evidence

	if strings.ToLower(matchType) == "regex" {

		for _, m := range utils.RegexMatch(data["name"], matchValue) {
			evidence := createEvidenceStruct(file, m, data["offset"], ruleName)

			if (model.Evidence{}) != evidence {
				evidenceInstances = append(evidenceInstances, evidence)
			}
		}

	} else if strings.ToLower(matchType) == "exact" {

		for _, m := range utils.ExactMatch(data["name"], matchValue) {
			evidence := createEvidenceStruct(file, m, data["offset"], ruleName)

			if (model.Evidence{}) != evidence {
				evidenceInstances = append(evidenceInstances, evidence)
			}
		}

	} else {
		panic(
			fmt.Sprintf(
				"[ERROR] r2handler does not support matchType of %q in rule %q",
				r.MatchType,
				r.Name))
	}

	return evidenceInstances
}

//Anal - analyses the information gathered by r2
func Anal() map[string]bool {
	detectionAnalResults = make(map[string]bool, 0)

	detectionAnalResults["jbOrRootDetection"] = false
	detectionAnalResults["emulatorDetection"] = false
	detectionAnalResults["debugDetection"] = false
	detectionAnalResults["dniDetection"] = false

	fmt.Println("Performing Analysis")

	fmt.Println("Analysing", len(allStringsInBinary), "strings")
	fmt.Println("Analysing", len(allSymbolsInBinary), "symbols")
	fmt.Println("Analysing", len(allSyscall), "syscalls")
	fmt.Println("Analysing", len(allBinClassAndFunc), "binClassAndFunc")

	// ** Disabled as allBinClassAndFunc handles this functionality for now
	// Search through functions for matches to detectionStrings
	// fmt.Println("[INFO] Searching binary functions..")
	// for _, f := range allBinFuncs {
	// 	for _, bf := range f {
	// 		if val, ok := bf["name"]; ok {
	// 			CheckAllSigs(val)
	// 		}
	// 	}
	// }

	//ToDO: Analysis logic here
	// faccesstat, open, stat64

	return detectionAnalResults
}

func checkForJBOrRoot(s string) bool {

	var rootDetectSigs = []string{
		"BusinessLogic",
		"rootdetect",
		"rooted",
		"supersecret",
		"/sbin/su",
		"/system/bin/su",
		"/system/bin/failsafe/su",
		"/system/xbin/su",
		"/system/xbin/busybox",
		"/system/sd/xbin/su",
		"/data/local/su",
		"/data/local/xbin/su",
		"/data/local/bin/su",
		"/system/app/Superuser.apk",
		"/system/etc/init.d/99SuperSUDaemon",
		"/dev/com.koushikdutta.superuser.daemon/",
		"/system/xbin/daemonsu",
	}

	var jbDetectSigs = []string{
		"/Applications/Cydia.app",
		"/Applications/FakeCarrier.app",
		"/Applications/Icy.app",
		"/Applications/IntelliScreen.app",
		"/Applications/MxTube.app",
		"/Applications/RockApp.app",
		"/Applications/SBSettings.app",
		"/Applications/WinterBoard.app",
		"/Applications/blackra1n.app",
		"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
		"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
		"/bin/bash",
		"/bin/sh",
		"/etc/apt",
		"/etc/ssh/sshd_config",
		"/private/var/lib/apt",
		"/private/var/lib/cydia",
		"/private/var/mobile/Library/SBSettings/Themes",
		"/private/var/stash",
		"/private/var/tmp/cydia.log",
		"/usr/bin/sshd",
		"/usr/libexec/sftp-server",
		"/usr/libexec/ssh-keysign",
		"/usr/sbin/sshd",
		"/var/cache/apt",
		"/var/lib/apt",
		"/var/lib/cydia",
		"/usr/bin/cycript",
		"/usr/local/bin/cycript",
		"/usr/lib/libcycript.dylib",
	}

	for _, ds := range rootDetectSigs {
		if strings.Contains(strings.ToLower(s), ds) {
			fmt.Println("[FINDING] Root Detection - We have a match!", ds, "was in", s)

			return true
		}
	}

	for _, ds := range jbDetectSigs {
		if strings.Contains(strings.ToLower(s), ds) {
			fmt.Println("[FINDING] Jailbreak Detection - We have a match!", ds, "was in", s)

			return true
		}
	}

	return false
}

func checkForEmulator(s string) bool {
	var emulatorSigs = []string{
		"emulator",
	}

	for _, ds := range emulatorSigs {
		if strings.Contains(strings.ToLower(s), ds) {
			fmt.Println("[FINDING] Emulator Detection - We have a match!", ds, "was in", s)

			return true
		}
	}

	return false
}

func checkForDebugger(s string) bool {

	var debuggerSigs = []string{
		"isDebuggerConnected",
	}

	for _, ds := range debuggerSigs {
		if strings.Contains(strings.ToLower(s), ds) {
			fmt.Println("[FINDING] Debugger Instrumentation Detection - We have a match!", ds, "was in", s)

			return true
		}
	}
	return false
}

func checkForDni(s string) bool {

	var dynamicInstSigs = []string{
		"XposedBridge.jar",
		"/system/framework/XposedBridge.jar",
		"substrate",
		"frida-agent",
		"frida-gadget",
		"/usr/sbin/frida-server",
		"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
		"/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
		"/Library/MobileSubstrate/MobileSubstrate.dylib",
	}

	for _, ds := range dynamicInstSigs {
		if strings.Contains(strings.ToLower(s), ds) {
			fmt.Println("[FINDING] Dynamic Instrumentation Detection - We have a match!", ds, "was in", s)

			return true
		}
	}

	return false
}

func CheckAllSigs(val string) {
	if !detectionAnalResults["jbOrRootDetection"] {
		if checkForJBOrRoot(val) {
			detectionAnalResults["jbOrRootDetection"] = true
		}
	}

	if !detectionAnalResults["emulatorDetection"] {
		if checkForEmulator(val) {
			detectionAnalResults["emulatorDetection"] = true
		}
	}

	if !detectionAnalResults["debugDetection"] {
		if checkForDebugger(val) {
			detectionAnalResults["debugDetection"] = true
		}
	}

	if !detectionAnalResults["dniDetection"] {
		if checkForDni(val) {
			detectionAnalResults["dniDetection"] = true
		}
	}
}
