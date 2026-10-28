package main

import (
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
)

// Load prog.o, print the program id, then run the program once a second on
// packets of 64, 80, 96 and 112 bytes in turn, for a minute.
func main() {
	spec, err := ebpf.LoadCollectionSpec(os.Args[1])
	if err != nil {
		panic(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}
	defer coll.Close()
	info, _ := coll.Programs["entry"].Info()
	id, _ := info.ID()
	fmt.Println(id)
	for i := range 60 {
		n := 64 + 16*(i%4)
		ret, err := coll.Programs["entry"].Run(&ebpf.RunOptions{Data: make([]byte, n), Repeat: 1})
		fmt.Fprintf(os.Stderr, "run len=%d action=%d err=%v\n", n, ret, err)
		time.Sleep(time.Second)
	}
}
