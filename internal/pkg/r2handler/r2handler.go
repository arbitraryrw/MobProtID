package r2handler

import (
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"

	"github.com/radare/r2pipe-go"
)

var r2sessionMap map[string]r2pipe.Pipe

func init() {}

// PrepareAnal - gathers all the relevant data required for analysis
func PrepareAnal(binaryPath []string, wg *sync.WaitGroup) {

	defer wg.Done()
	fmt.Println("*** R2 handler Starting ***")

	allStrings := make(chan []string)
	binaryInfo := make(chan map[string]string)
	symbols := make(chan []string)
	syscalls := make(chan []string)

	for index, path := range binaryPath {
		fmt.Println(index, path)

		go func(p string) {
			r2Session := openR2Pipe(path)
			binaryInfo <- getBinaryInfo(r2Session)
			r2Session.Close()
		}(path)

		go func(p string) {
			r2Session := openR2Pipe(path)
			allStrings <- getStringEntireBinary(r2Session)
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
	}

	// writeString("Letsa go!")

	fmt.Println("Lets see if r2 has returned the goods:", <-binaryInfo)
	fmt.Println("Found", len(<-allStrings), "strings in binary")
	fmt.Println("Found", <-symbols, "symbols in binary")
	fmt.Println("Found", len(<-syscalls), "syscalls in binary")

	anal()
}

func anal() {
	fmt.Println("Performing Analysis")

	//ToDO: Analysis logic here
	// faccesstat, open, stat64
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

func getSysCalls(r2session r2pipe.Pipe) []string {

	var buf interface{}

	err := utils.Retry(5, 2*time.Second, func() (err error) {
		// Example data from r2:
		// map[bind:GLOBAL flagname:sym.main is_imported:false name:main
		//ordinal:61 paddr:1706 realname:main size:56 type:FUNC vaddr:1706]
		buf, err = r2session.Cmdj("asj")
		return
	})

	fmt.Println(buf, err)

	syscalls := make([]string, 0)

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
