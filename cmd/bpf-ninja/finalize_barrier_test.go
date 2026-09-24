package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/output"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"sync"
	"testing"
	"time"
)

func TestBpfFinalizeWaitsForWriterRegistration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, fast := range []bool{false, true} {
		t.Run(fmt.Sprintf("fast=%v", fast), func(t *testing.T) {
			f := newTestFinalizer(t, 2)
			var maps []*ebpf.Map
			for range 2 {
				m, e := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 65536})
				if e != nil {
					t.Fatal(e)
				}
				defer func() { _ = m.Close() }()
				maps = append(maps, m)
			}
			send := func(shard int, tag int32) {
				p, e := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: asm.Instructions{
					asm.LoadMapPtr(asm.R1, maps[shard].FD()), asm.Mov.Imm(asm.R2, 24), asm.Mov.Imm(asm.R3, 0), asm.FnRingbufReserve.Call(), asm.JEq.Imm(asm.R0, 0, "exit"),
					asm.Mov.Imm(asm.R2, 0), asm.StoreMem(asm.R0, 0, asm.R2, asm.DWord), asm.StoreMem(asm.R0, 8, asm.R2, asm.DWord), asm.StoreMem(asm.R0, 16, asm.R2, asm.DWord), asm.StoreImm(asm.R0, 14, 4, asm.Half), asm.StoreImm(asm.R0, 16, int64(tag), asm.Word),
					asm.Mov.Reg(asm.R1, asm.R0), asm.Mov.Imm(asm.R2, 0), asm.FnRingbufSubmit.Call(), asm.Mov.Imm(asm.R0, 2).WithSymbol("exit"), asm.Return(),
				}})
				if e != nil {
					t.Fatal(e)
				}
				defer func() { _ = p.Close() }()
				if _, e = p.Run(&ebpf.RunOptions{Data: make([]byte, 64)}); e != nil {
					t.Fatal(e)
				}
			}
			arrived, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			sink := func(i int, pkts []capture.Packet) error {
				once.Do(func() { close(arrived); <-release }) // before any writer is registered
				for _, pkt := range pkts {
					if f.stateFor(pkt.Tag).finalized.Load() {
						return fmt.Errorf("pre-barrier record dropped")
					}
					w, e := output.NewWriter(output.TagShardPath(f.basePath, i, pkt.Tag), output.Config{})
					if e != nil {
						return e
					}
					f.register(pkt.Tag, i, w)
					if e = w.WriteBatch([]capture.Packet{pkt}); e != nil {
						f.fail(pkt.Tag, e)
						return e
					}
				}
				return nil
			}
			var stop func()
			var barrier func() func() (bool, error)
			var err error
			if fast {
				r, e := capture.NewFastShardedReader(maps)
				if e != nil {
					t.Fatal(e)
				}
				stop, err = r.RunShardsFast(sink)
				barrier = r.Barrier
			} else {
				r, e := capture.NewShardedReader(maps)
				if e != nil {
					t.Fatal(e)
				}
				stop, err = r.RunShards(sink)
				barrier = r.Barrier
			}
			if err != nil {
				t.Fatal(err)
			}
			send(0, 3)
			select {
			case <-arrived:
			case <-time.After(3 * time.Second):
				t.Fatal("sink did not start")
			}
			send(0, 7)
			send(1, 7)
			f.stateFor(7)
			f.begin = func(uint32) (func() (bool, error), error) { return barrier(), nil }
			for range 100 {
				if done := f.step(nil); len(done) != 0 {
					t.Fatal("ack before writer registration")
				}
			}
			close(release)
			deadline := time.Now().Add(3 * time.Second)
			for !f.isMerged(7) {
				for _, tag := range f.step(nil) {
					if e := f.finalize(tag); e != nil {
						t.Fatal(e)
					}
				}
				if time.Now().After(deadline) {
					t.Fatal("barrier did not finish")
				}
				time.Sleep(time.Millisecond)
			}
			stop()
			if n, e := countPcapPackets(output.TagMergedPath(f.basePath, 7)); e != nil || n != 2 {
				t.Fatalf("merged n=%d err=%v", n, e)
			}
			if e := f.closeAll(); e != nil {
				t.Fatal(e)
			}
		})
	}
}
