// This loader deliberately creates a map without BTF, then loads the ELF program.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 4 {
		panic("usage: loader ELF OUTPUT_DIR untyped|typed")
	}
	spec, err := ebpf.LoadCollectionSpec(os.Args[1])
	check(err)
	out := os.Args[2]
	mSpec := spec.Maps["sessions"].Copy()
	if os.Args[3] == "untyped" {
		mSpec.Key = nil
		mSpec.Value = nil
	}
	m, err := ebpf.NewMap(mSpec)
	check(err)
	defer m.Close()
	info, err := m.Info()
	check(err)
	id, _ := info.BTFID()
	check(os.WriteFile(filepath.Join(out, "map-btf.txt"), []byte(fmt.Sprintf("BTFID=%d\n", id)), 0600))
	if os.Args[3] == "untyped" && id != 0 {
		panic("loader unexpectedly created map BTF")
	}
	check(m.Put(uint32(0), struct{ Identity, Action uint32 }{7, 2}))
	// Rewrite only the map reference; the program retains its original ELF BTF.
	check(spec.Programs["ingress"].Instructions.AssociateMap("sessions", m))
	p, err := ebpf.NewProgram(spec.Programs["ingress"])
	check(err)
	defer p.Close()
	pi, err := p.Info()
	check(err)
	pid, _ := pi.ID()
	check(os.WriteFile(filepath.Join(out, "ready"), []byte(fmt.Sprint(pid)), 0600))
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(out, "trigger")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			panic("trigger timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for i, identity := range []uint32{7, 8, 7} {
		check(m.Put(uint32(0), struct{ Identity, Action uint32 }{identity, 2}))
		packet := bytes.Repeat([]byte{byte(0xa0 + i)}, 64)
		ret, got, err := p.Test(packet)
		check(err)
		if ret != 2 || !bytes.Equal(packet, got) {
			panic("TEST_RUN changed action or packet")
		}
		check(json.NewEncoder(os.Stdout).Encode(map[string]any{"sequence": i, "identity": identity, "action": ret, "packet": packet}))
	}
	// Keep the hook alive until the observer is detached.
	for {
		if _, err := os.Stat(filepath.Join(out, "stop")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			panic("stop timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
