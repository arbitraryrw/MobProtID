package r2handler

import (
	"fmt"

	"github.com/radare/r2pipe-go"
)

var r2session r2pipe.Pipe

func init() {
	fmt.Println("*** R2 handler Starting ***")

	r2p, err := r2pipe.NewPipe("malloc://256")
	if err != nil {
		panic(err)
	}
	defer r2p.Close()

	_, err = r2p.Cmd("w Hey There Boss")
	if err != nil {
		panic(err)
	}
	buf, err := r2p.Cmd("ps")
	if err != nil {
		panic(err)
	}
	fmt.Println(buf)
}

func getStrings(r2session r2pipe.Pipe) {

}
