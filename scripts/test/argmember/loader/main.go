// The fixture uses BPF_PROG_TEST_RUN only; it never attaches to an interface.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func packet(n int, port uint16) []byte {
	b := make([]byte, n)
	copy(b[:12], []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(b[12:], 0x0800)
	b[14] = 0x45
	binary.BigEndian.PutUint16(b[16:], uint16(n-14))
	b[22], b[23] = 64, 6
	copy(b[26:], []byte{10, 0, 0, 1, 10, 0, 0, 2})
	binary.BigEndian.PutUint16(b[34:], 40000)
	binary.BigEndian.PutUint16(b[36:], port)
	b[46], b[47] = 0x50, 0x02
	return b
}

func main() {
	spec, err := ebpf.LoadCollectionSpec(os.Args[1])
	if err != nil {
		panic(err)
	}
	// Queue maps have a zero-byte key. Supplying its empty BTF type keeps
	// the kernel from refusing keyless BTF and the loader retrying without
	// the declared u64 value type. The map still has no key bytes.
	if queue := spec.Maps["recent"]; queue != nil {
		queue.Key = &btf.Struct{Name: "empty_key"}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}
	defer coll.Close()
	if m := coll.Maps["policies"]; m != nil {
		for i, port := range []uint16{443, 80} {
			key, value := make([]byte, 4), make([]byte, 8)
			binary.BigEndian.PutUint16(key, port)
			binary.NativeEndian.PutUint32(value, uint32(2-i))
			binary.BigEndian.PutUint16(value[4:], port)
			if err := m.Put(key, value); err != nil {
				panic(err)
			}
		}
	}
	prog := coll.Programs["entry"]
	info, err := prog.Info()
	if err != nil {
		panic(err)
	}
	id, ok := info.ID()
	if !ok {
		panic("no program ID")
	}
	fmt.Println(id)
	for i := 0; i < 3600; i++ {
		port := []uint16{443, 80, 22}[i%3]
		n := []int{64, 80, 96}[i%3]
		if _, err := prog.Run(&ebpf.RunOptions{Data: packet(n, port)}); err != nil {
			panic(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
