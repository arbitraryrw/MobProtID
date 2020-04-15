package r2handler

import (
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
	getStringEntireBinary()

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

func getStringEntireBinary() {
	buf, err := r2session.Cmdj("izzj")
	if err != nil {
		panic(err)
	}

	fmt.Println(buf)

	if buf, ok := buf.(map[string]interface{}); ok {
		fmt.Println(buf)
	}
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
