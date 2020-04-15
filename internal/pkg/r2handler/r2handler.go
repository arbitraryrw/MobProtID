package r2handler

import (
	"encoding/base64"
	"fmt"

	"github.com/radare/r2pipe-go"
)

var r2session r2pipe.Pipe

func init() {}

// PrepareAnal -
func PrepareAnal(binaryPath string) {

	fmt.Println("*** R2 handler Starting ***")

	r2session = openR2Pipe(binaryPath)

	anal()
}

func anal() {
	fmt.Println("Performing Analaysis")

	// writeString("Letsa go!")
	allStrings := getStringEntireBinary()
	fmt.Println("Found", len(allStrings), "strings in binary")

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
