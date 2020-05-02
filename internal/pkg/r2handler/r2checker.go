package r2handler

import (
	"fmt"
	"strings"
)

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

var emulatorSigs = []string{
	"emulator",
}

var debuggerSigs = []string{
	"isDebuggerConnected",
}
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

//Anal - analyses the information gathered by r2
func Anal() {
	fmt.Println("Performing Analysis")

	fmt.Println("Analysing", len(allStringsInBinary), "strings")
	fmt.Println("Analysing", len(allSymbolsInBinary), "symbols")
	fmt.Println("Analysing", len(allSyscall), "syscalls")
	fmt.Println("Analysing", len(allBinFuncs), "binFuncs")

	// Search through functions for matches to detectionStrings
	fmt.Println("[INFO] Searching binary functions..")
	for _, f := range allBinFuncs {
		for _, bf := range f {
			if val, ok := bf["name"]; ok {

				checkAgainstSigs(val)

				// Function name
				// fmt.Println("[DEBUG]", val)
			}
		}
	}

	// Search through strings in binary for detectionStrings
	fmt.Println("[INFO] Searching binary strings..")
	for k, v := range allStringsInBinary {
		fmt.Println("[INFO] File ->", k)

		for _, s := range v {

			checkAgainstSigs(s)

		}
	}

	fmt.Println("[INFO] Searching binary symbols..")
	for k, v := range allSymbolsInBinary {
		fmt.Println("[INFO] File ->", k)
		for _, s := range v {
			checkAgainstSigs(s)
		}
	}

	// allSymbolsInBinary map[string][]string
	// allbinaryInfo map[string]map[string]string
	// allSyscall map[string]map[string]string

	//ToDO: Analysis logic here
	// faccesstat, open, stat64
}

func checkAgainstSigs(s string) {
	for _, ds := range rootDetectSigs {
		if strings.Contains(strings.ToLower(s), ds) {
			fmt.Println("[INFO] Root Detection - We have a match!", ds, "was in", s)
		}
	}

	for _, ds := range jbDetectSigs {
		if strings.Contains(strings.ToLower(s), ds) {
			fmt.Println("[INFO] Jailbreak Detection - We have a match!", ds, "was in", s)
		}
	}
	for _, ds := range emulatorSigs {
		if strings.Contains(strings.ToLower(s), ds) {
			fmt.Println("[INFO] Emulator Detection - We have a match!", ds, "was in", s)
		}
	}
	for _, ds := range debuggerSigs {
		if strings.Contains(strings.ToLower(s), ds) {
			fmt.Println("[INFO] Debugger Instrumentation Detection - We have a match!", ds, "was in", s)
		}
	}

	for _, ds := range dynamicInstSigs {
		if strings.Contains(strings.ToLower(s), ds) {
			fmt.Println("[INFO] Dynamic Instrumentation Detection - We have a match!", ds, "was in", s)
		}
	}
}
