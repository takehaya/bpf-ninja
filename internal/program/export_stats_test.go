package program

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
	"golang.org/x/sys/unix"
	"runtime"
	"testing"
)

func TestBpfExportOutcomeAccounting(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	var mask unix.CPUSet
	if err := unix.SchedGetaffinity(0, &mask); err != nil {
		t.Fatal(err)
	}
	cpu := 0
	for !mask.IsSet(cpu) {
		cpu++
	}
	for _, kind := range []string{"normal", "full", "lookup", "copy"} {
		t.Run(kind, func(t *testing.T) {
			runtime.LockOSThread()
			var one unix.CPUSet
			one.Set(cpu)
			if err := unix.SchedSetaffinity(0, &one); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.SchedSetaffinity(0, &mask); runtime.UnlockOSThread() }()
			ringSpec := &ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 4096}
			ring, err := ebpf.NewMap(ringSpec)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ring.Close() }()
			outer, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: uint32(cpu + 1), InnerMap: ringSpec})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = outer.Close() }()
			if kind != "lookup" {
				if err := outer.Update(uint32(cpu), ring, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			probe := &Probe{}
			if err := probe.initExportStats(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = probe.Close() }()
			var out codegen.Output
			out.Capture.MaxCapLen = 64
			insns := buildXDPNativeInsns(out, outer.FD(), nil, 0, probe.StatsMap.FD())
			if kind == "copy" {
				for i, ins := range insns {
					if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnXdpLoadBytes) {
						// Force the copy helper to fail after reserve, exercising discard+count.
						insns = append(insns[:i], append(asm.Instructions{asm.Mov.Imm(asm.R2, 1<<20)}, insns[i:]...)...)
						break
					}
				}
			}
			p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: insns})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = p.Close() }()
			n := 17
			if kind == "full" {
				n = 100
			}
			for range n {
				if _, err := p.Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
					t.Fatal(err)
				}
			}
			k, err := probe.ExportStats()
			if err != nil {
				t.Fatal(err)
			}
			if k.Submitted+k.ReserveFail+k.LookupMiss+k.CopyFail != uint64(n) {
				t.Fatalf("unbalanced outcomes %+v want %d", k, n)
			}
			switch kind {
			case "normal":
				if k.Submitted != 17 {
					t.Fatal(k)
				}
			case "full":
				if k.Submitted == 0 || k.ReserveFail == 0 {
					t.Fatal(k)
				}
			case "lookup":
				if k.LookupMiss != 17 {
					t.Fatal(k)
				}
			case "copy":
				if k.CopyFail != 17 {
					t.Fatal(k)
				}
			}
			r, err := fastrb.New(ring.FD(), 4096)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			got := r.ReadBatch(func([]byte) {})
			if uint64(got) != k.Submitted {
				t.Fatalf("ring contains %d, submitted %d", got, k.Submitted)
			}
		})
	}
}
