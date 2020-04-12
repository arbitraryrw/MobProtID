package r2handler

import (
	"fmt"

	"github.com/radare/r2pipe-go"
)

func Testr2() {
	r2p, err := r2pipe.NewPipe("malloc://256")
	if err != nil {
		panic(err)
	}
	defer r2p.Close()

	_, err = r2p.Cmd("w Hello World")
	if err != nil {
		panic(err)
	}
	buf, err := r2p.Cmd("ps")
	if err != nil {
		panic(err)
	}
	fmt.Println(buf)
}
