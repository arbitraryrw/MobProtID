package r2handler

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"sync"

	"github.com/radare/r2pipe-go"
)

var r2session r2pipe.Pipe

func init() {}

// PrepareAnal - gathers all the relevant data required for analysis
func PrepareAnal(binaryPath string, wg *sync.WaitGroup) {

	defer wg.Done()
	fmt.Println("*** R2 handler Starting ***")

	r2session = openR2Pipe(binaryPath)

	// writeString("Letsa go!")

	allStrings := make(chan []string)

	go func() { allStrings <- getStringEntireBinary() }()

	binaryInfo := getBinaryInfo()
	fmt.Println("Lets see if r2 has returned the goods:", binaryInfo)

	fmt.Println("Found", len(<-allStrings), "strings in binary")

	anal()
}

func anal() {
	fmt.Println("Performing Analaysis")

	//ToDO: Analysis logic here
	// faccesstat, open, stat64

	defer r2session.Close()
}

func openR2Pipe(path string) r2pipe.Pipe {

	fmt.Println("Opening", path)
	// r2p, err := r2pipe.NewPipe("malloc://256")
	r2p, err := r2pipe.NewPipe(path)

	if err != nil {
		panic(err)
	}

	return *r2p
}

func writeString(s string) {

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

func getStringEntireBinary() []string {
	buf, err := r2session.Cmdj("izzj")
	if err != nil {
		panic(err)
	}

	stringsInBinary := make([]string, 0)

	// Assert buf as map[string]interface{} and then parse if true
	if buf, ok := buf.([]interface{}); ok {

		for _, stringBundle := range buf {

			sb, ok := stringBundle.(map[string]interface{})

			if ok {

				sDec, _ := base64.StdEncoding.DecodeString(sb["string"].(string))

				stringsInBinary = append(stringsInBinary, string(sDec))

				// fmt.Println("Length", sb["length"])
				// fmt.Println("Ordinal", sb["ordinal"])
				// fmt.Println("Paddr", sb["paddr"])
				// fmt.Println("Section", sb["section"])
				// fmt.Println("Size", sb["size"])
				// fmt.Println("Type", sb["type"])
				// fmt.Println("Decoded string", string(sDec))
				// fmt.Println()

			} else {
				panic("Unexpected string bundle from r2, unable to assert!")
			}
		}
	} else {
		panic("Unable to parse R2 strings returned")
	}

	return stringsInBinary
}

func getBinaryInfo() map[string]string {
	buf, err := r2session.Cmdj("iIj")
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
		panic("Unexpected reponse from R2 while getting binary info")
	}

	return binaryInfo

}

func getStringsDataSections() {
	_, err := r2session.Cmdj("izj")
	if err != nil {
		panic(err)
	}
}

func getExports(r2session r2pipe.Pipe) {

}

func getSymbols(r2session r2pipe.Pipe) {

}
