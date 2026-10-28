// observer attaches to the push, pop and peek hooks of the program whose id
// is os.Args[2] and prints each call: the op, the site, the value and the
// helper's result and flags.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func main() {
	id, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}
	target, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
	if err != nil {
		panic(err)
	}
	spec, err := ebpf.LoadCollectionSpec(os.Args[1])
	if err != nil {
		panic(err)
	}
	for _, p := range spec.Programs {
		p.AttachTarget = target
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}
	defer coll.Close()
	for _, name := range []string{"on_push", "on_pop", "on_peek"} {
		l, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs[name]})
		if err != nil {
			panic(err)
		}
		defer func() { _ = l.Close() }()
	}
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		panic(err)
	}
	for {
		rec, err := rd.Read()
		if err != nil {
			panic(err)
		}
		b := rec.RawSample
		op := []string{"push", "pop", "peek"}[binary.LittleEndian.Uint32(b)]
		status := binary.LittleEndian.Uint64(b[16:])
		value := binary.LittleEndian.Uint64(b[8:])
		fmt.Printf("%-4s site=%d value=%d ret=%d flags=%d\n", op, binary.LittleEndian.Uint32(b[4:]),
			value, int32(status), status>>32)
	}
}
