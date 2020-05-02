package r2handler

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"

	"github.com/radare/r2pipe-go"
)

var allStringsInBinary map[string][]string
var allSymbolsInBinary map[string][]string
var allbinaryInfo map[string]map[string]string
var allSyscall map[string]map[string]string
var allBinFuncs map[string][]map[string]string

func init() {
	allStringsInBinary = make(map[string][]string, 0)
	allSymbolsInBinary = make(map[string][]string, 0)
	allSyscall = make(map[string]map[string]string, 0)
	allbinaryInfo = make(map[string]map[string]string, 0)
	allBinFuncs = make(map[string][]map[string]string, 0)
}

// PrepareAnal - gathers all the relevant data required for analysis
func PrepareAnal(binaryPath []string, wg *sync.WaitGroup) {

	defer wg.Done()
	fmt.Println("*** R2 handler Starting ***")

	for index, path := range binaryPath {
		fmt.Println(index, path)

		strings := make(chan []string)
		binaryInfo := make(chan map[string]string)
		symbols := make(chan []string)
		syscalls := make(chan map[string]string)
		binFuncs := make(chan []map[string]string)

		// fmt.Println(index, path)

		go func(p string) {
			r2Session := openR2Pipe(path)
			binaryInfo <- getBinaryInfo(r2Session)
			r2Session.Close()
		}(path)

		go func(p string) {
			r2Session := openR2Pipe(path)
			strings <- getStringEntireBinary(r2Session)
			r2Session.Close()
		}(path)

		go func(p string) {
			r2Session := openR2Pipe(path)
			symbols <- getSymbols(r2Session)
			r2Session.Close()
		}(path)

		go func(p string) {
			r2sessionMap := openR2Pipe(path)
			syscalls <- getSysCalls(r2sessionMap)
			r2sessionMap.Close()
		}(path)

		go func(p string) {
			r2Session := openR2Pipe(path)
			binFuncs <- getFunctions(r2Session)
			r2Session.Close()
		}(path)

		allStringsInBinary[path] = <-strings
		allSymbolsInBinary[path] = <-symbols
		allSyscall[path] = <-syscalls
		allbinaryInfo[path] = <-binaryInfo
		allBinFuncs[path] = <-binFuncs

		close(strings)
		close(symbols)
		close(syscalls)
		close(binaryInfo)
		close(binFuncs)
	}

	// writeString("Letsa go!")

	return
}

func openR2Pipe(path string) r2pipe.Pipe {

	// fmt.Println("Opening", path)
	// r2p, err := r2pipe.NewPipe("malloc://256")
	r2p, err := r2pipe.NewPipe(path)

	if err != nil {
		panic(err)
	}

	return *r2p
}

func writeString(s string, r2session r2pipe.Pipe) {

	_, err := r2session.Cmd("w " + s)
	if err != nil {
		panic(err)
	}
	buf, err := r2session.Cmd("ps")
	if err != nil {
		panic(err)
	}
	fmt.Println(buf)
}

func getStringEntireBinary(r2session r2pipe.Pipe) []string {

	var buf interface{}

	err := utils.Retry(5, 2*time.Second, func() (err error) {
		buf, err = r2session.Cmdj("izzj")
		return
	})

	// Example return of izzj
	//map[length:8 ordinal:86 paddr:6549 section:.shstrtab size:9 string:.comment type:ascii vaddr:245]
	// buf, err := r2session.Cmdj("izzj")

	if err != nil {
		panic(err)
	}

	stringsInBinary := make([]string, 0)

	// Assert buf as map[string]interface{} and then parse if true
	if buf, ok := buf.([]interface{}); ok {

		for _, stringBundle := range buf {

			if sb, ok := stringBundle.(map[string]interface{}); ok {

				// r2 4.0.0 the "string" key values are b64 encoded
				// sDec, _ := base64.StdEncoding.DecodeString(sb["string"].(string))
				// stringsInBinary = append(stringsInBinary, string(sDec))

				if s, ok := sb["string"]; ok {
					stringsInBinary = append(stringsInBinary, s.(string))
				}

			} else {
				panic("Unexpected reponse from R2 while getting all strings in binary!")
			}
		}
	} else {
		fmt.Println("[INFO] Found no strings in binary")
	}

	return stringsInBinary
}

func getBinaryInfo(r2session r2pipe.Pipe) map[string]string {

	var buf interface{}

	err := utils.Retry(5, 2*time.Second, func() (err error) {
		buf, err = r2session.Cmdj("iIj")
		return
	})

	// buf, err := r2session.Cmdj("iIj")
	if err != nil {
		panic(err)
	}

	binaryInfo := make(map[string]string)

	if bi, ok := buf.(map[string]interface{}); ok {
		// fmt.Println("R2 returned ->", bi)

		if val, ok := bi["compiler"].(string); ok {
			binaryInfo["compiler"] = val
		}

		if val, ok := bi["canary"].(bool); ok {
			binaryInfo["canary"] = strconv.FormatBool(val)
		}

		if val, ok := bi["pic"].(bool); ok {
			binaryInfo["pic"] = strconv.FormatBool(val)
		}

		if val, ok := bi["stripped"].(bool); ok {
			binaryInfo["stripped"] = strconv.FormatBool(val)
		}

	} else {
		fmt.Println("[ERROR] Response from R2:", buf)
		fmt.Println("[ERROR] Response type from R2:", reflect.TypeOf(buf))
		panic("Unexpected reponse from R2 while getting binary info")
	}

	return binaryInfo
}

func getSymbols(r2session r2pipe.Pipe) []string {

	var buf interface{}

	err := utils.Retry(5, 2*time.Second, func() (err error) {
		// Example data from r2:
		// map[bind:GLOBAL flagname:sym.main is_imported:false name:main
		//ordinal:61 paddr:1706 realname:main size:56 type:FUNC vaddr:1706]
		buf, err = r2session.Cmdj("isj")
		return
	})

	if err != nil {
		panic(err)
	}

	symbolsInBinary := make([]string, 0)

	if buf, ok := buf.([]interface{}); ok {
		for _, symMap := range buf {

			// fmt.Println(symMap)

			if sym, ok := symMap.(map[string]interface{}); ok {

				if symType, ok := sym["type"].(string); ok {

					// Can be of type SECT / FILE / FUNC / OBJ / NOTYPE
					if symType == "FUNC" {
						symbolsInBinary = append(symbolsInBinary, sym["realname"].(string))
					}
				}
			}
		}
	}

	return symbolsInBinary
}

func getSysCalls(r2session r2pipe.Pipe) map[string]string {

	var buf string

	err := utils.Retry(5, 2*time.Second, func() (err error) {
		// Annoyingly you can't seem to chain as and /j to get json output
		// having to parse the r2 string response
		buf, err = r2session.Cmd("/as")
		return
	})

	if err != nil {
		panic(err)
	}

	syscalls := make(map[string]string, 0)

	if len(buf) > 0 {

		for _, val := range strings.Split(buf, "\n") {
			splitVal := strings.Fields(val)
			syscalls[splitVal[0]] = splitVal[1]
		}

	}

	return syscalls
}

func getStringsDataSections(r2session r2pipe.Pipe) {
	_, err := r2session.Cmdj("izj")
	if err != nil {
		panic(err)
	}
}

func getExports(r2session r2pipe.Pipe) {

}

func getFunctions(r2session r2pipe.Pipe) []map[string]string {

	// Instruct r2 to analyse the binary
	r2session.Cmd("aaa")

	buf, err := r2session.Cmdj("aflj")

	if err != nil {
		panic(err)
	}

	functionsInBinary := make([]map[string]string, 0)

	if buf, ok := buf.([]interface{}); ok {
		for _, funcBundle := range buf {

			funBundle := make(map[string]string)

			if fun, ok := funcBundle.(map[string]interface{}); ok {

				// fmt.Println("[DEBUG] r2 func object ->", fun)

				/*
					R2 sample response:
					map[bits:32 bpvars:[] callrefs:[map[addr:399668 at:543028 type:CALL]] cc:1 codexrefs:[map[addr:543248 at:543028 type:CALL]]
					cost:0 datarefs:[] dataxrefs:[] difftype:new ebbs:1 edges:0 indegree:1 is-pure:true maxbound:543036 minbound:543028
					name:method.constructor.Landroid_support_v4_os_ResultReceiver_1.Landroid_support_v4_os_ResultReceiver_1.method._init___V
					nargs:0 nbbs:1 nlocals:0 noreturn:false offset:543028 outdegree:1 realsz:8 regvars:[]
					signature:method.constructor.Landroid_support_v4_os_ResultReceiver_1.Landroid_support_v4_os_ResultReceiver_1.method._init___V ();
					size:8 spvars:[] stackframe:0 type:fcn]
				*/

				if funName, ok := fun["name"].(string); ok {
					funBundle["name"] = funName
				}

				if funOffset, ok := fun["offset"]; ok {
					funBundle["offset"] = fmt.Sprintf("%g", funOffset)
				}

				if funType, ok := fun["type"].(string); ok {
					funBundle["type"] = funType
				}
			}

			// Append the individual function to the parent array
			functionsInBinary = append(functionsInBinary, funBundle)

		}
	}

	return functionsInBinary
}

// Seems to overlap alot with getFunctions() investigate if this has value
func getFunctionsAndClasses(r2session r2pipe.Pipe) []map[string]string {

	fAndCInBinary := make([]map[string]string, 0)

	buf, err := r2session.Cmdj("icj")

	if err != nil {
		panic(err)
	}

	fmt.Println(buf)

	return fAndCInBinary
}
