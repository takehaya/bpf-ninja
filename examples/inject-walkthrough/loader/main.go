package main

import (
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// Load prog.o, print the program id, then run the program once a second on
// packets of 64, 80, 96 and 112 bytes in turn, for a minute.
// With a second argument, wait for that file before starting the workload.
func main() {
	spec, err := ebpf.LoadCollectionSpec(os.Args[1])
	if err != nil {
		panic(err)
	}
	// A zero-sized BTF key lets queue maps keep their declared value type.
	// Without it the loader retries map creation without BTF, and injected
	// hooks can only describe the value as opaque bytes.
	spec.Maps["recent"].Key = &btf.Struct{Name: "empty_key"}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}
	defer coll.Close()
	info, _ := coll.Programs["entry"].Info()
	id, _ := info.ID()
	fmt.Println(id)
	// Optional gate used by observers so the initial Bloom misses are observable.
	if len(os.Args) > 2 {
		for {
			if _, err := os.Stat(os.Args[2]); err == nil {
				break
			} else if !os.IsNotExist(err) {
				panic(err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	for i := range 60 {
		n := 64 + 16*(i%4)
		ret, err := coll.Programs["entry"].Run(&ebpf.RunOptions{Data: make([]byte, n), Repeat: 1})
		fmt.Fprintf(os.Stderr, "run len=%d action=%d err=%v\n", n, ret, err)
		time.Sleep(time.Second)
	}
}
