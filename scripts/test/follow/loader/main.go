// The loader sends numbered packets through a program with
// BPF_PROG_TEST_RUN and replaces the program while they flow, the way a
// datapath reload does. It never attaches to an interface.
//
// usage: loader DIR GEN1.o GEN2.o TOTAL SWAP_AT
//
// It prints generation 1's program ID, waits for DIR/go, then sends packets
// 2 ms apart with the sequence number in the IPv4 ID. At packet SWAP_AT it
// starts loading generation 2 on another goroutine, while packets keep running
// on generation 1. After the load returns, it sends TOTAL packets on generation
// 2 and closes generation 1. DIR/done receives the first sequence number
// that ran on generation 2 and its program ID. The loader then keeps
// generation 2 loaded until it is killed.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func packet(seq int) []byte {
	b := make([]byte, 64)
	copy(b[:12], []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(b[12:], 0x0800)
	b[14] = 0x45
	binary.BigEndian.PutUint16(b[16:], 50)
	binary.BigEndian.PutUint16(b[18:], uint16(seq))
	b[22], b[23] = 64, 6
	copy(b[26:], []byte{10, 0, 0, 1, 10, 0, 0, 2})
	binary.BigEndian.PutUint16(b[34:], 40000)
	binary.BigEndian.PutUint16(b[36:], 443)
	b[46], b[47] = 0x50, 0x02
	return b
}

type generation struct {
	coll *ebpf.Collection
	prog *ebpf.Program
	id   ebpf.ProgramID
}

func runTraffic(total, swapAt int, startLoad func() <-chan struct{}, switchNext func(), send func(int), pause func()) (firstOnNext, sent int) {
	for sent < swapAt {
		send(sent)
		sent++
		pause()
	}
	loaded := startLoad()
	for {
		select {
		case <-loaded:
			switchNext()
			firstOnNext = sent
			goto switched
		default:
			send(sent)
			sent++
			pause()
		}
	}

switched:
	for range total - swapAt {
		send(sent)
		sent++
		pause()
	}
	return firstOnNext, sent
}

func load(object string) *generation {
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		panic(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}
	// One policy for port 443; the value is as long as this generation's
	// struct pol.
	policies := coll.Maps["policies"]
	key, value := make([]byte, 4), make([]byte, policies.ValueSize())
	binary.BigEndian.PutUint16(key, 443)
	binary.NativeEndian.PutUint32(value, 2)
	if len(value) > 4 {
		binary.BigEndian.PutUint16(value[4:], 443)
	}
	if err := policies.Put(key, value); err != nil {
		panic(err)
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
	return &generation{coll, prog, id}
}

func tracingLinks(id ebpf.ProgramID) int {
	it := new(link.Iterator)
	defer it.Close()
	n := 0
	for it.Next() {
		info, err := it.Link.Info()
		if err != nil {
			panic(err)
		}
		if tr := info.Tracing(); info.Type == link.TracingType && tr != nil && tr.TargetObjectId == uint32(id) {
			n++
		}
	}
	if err := it.Err(); err != nil {
		panic(err)
	}
	return n
}

func main() {
	dir := os.Args[1]
	total, err := strconv.Atoi(os.Args[4])
	if err != nil {
		panic(err)
	}
	swapAt, err := strconv.Atoi(os.Args[5])
	if err != nil {
		panic(err)
	}
	current := load(os.Args[2])
	fmt.Println(current.id)
	for i := 0; ; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go")); err == nil {
			break
		}
		if i > 6000 {
			panic("no go file within 60s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var next *generation
	firstOnNext, sent := runTraffic(total, swapAt, func() <-chan struct{} {
		loaded := make(chan struct{})
		go func() {
			next = load(os.Args[3])
			close(loaded)
		}()
		return loaded
	}, func() {
		current.coll.Close()
		current = next
	}, func(seq int) {
		if _, err := current.prog.Run(&ebpf.RunOptions{Data: packet(seq)}); err != nil {
			panic(err)
		}
	}, func() {
		time.Sleep(2 * time.Millisecond)
	})
	done := fmt.Sprintf("total=%d first_gen2_seq=%d id2=%d links2=%d\n", sent, firstOnNext, current.id, tracingLinks(current.id))
	if err := os.WriteFile(filepath.Join(dir, "done"), []byte(done), 0o644); err != nil {
		panic(err)
	}
	time.Sleep(time.Minute)
}
