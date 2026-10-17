package program

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
	"github.com/takehaya/bpf-ninja/pkg/kunai/dsltest"
	"testing"
	"time"
)

func TestBpfGatedEntryCopyFailure(t *testing.T) {
	for _, tc := range []struct {
		name              string
		emit              Emit
		reject            bool
		submitted, failed uint64
	}{
		{"both", EmitBoth, false, 0, 1}, {"entry", EmitEntry, false, 0, 1}, {"exit-no-entry-copy", EmitExit, false, 1, 0}, {"exit-filter-miss", EmitBoth, true, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := loadDummyXDP(t)
			outer, inners, err := createShardedRingbuf("copytest")
			if err != nil {
				t.Fatal(err)
			}
			p := &Probe{EventsMap: outer, InnerMaps: inners, maps: append([]*ebpf.Map{outer}, inners...)}
			defer func() { _ = p.Close() }()
			if err := p.initExportStats(); err != nil {
				t.Fatal(err)
			}
			hold, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: holdHdr + 64, MaxEntries: uint32(holdSlots)})
			if err != nil {
				t.Fatal(err)
			}
			p.maps = append(p.maps, hold)
			h, _ := hook.ByProgramType(ebpf.XDP)
			var out codegen.Output
			out.Capture.MaxCapLen = 64
			entry, err := buildGatedEntryInsns(h, out, filter.TargetFilters{}, hold.FD(), 0, p.StatsMap.FD(), 0, nil, nil, tc.emit, 64, 0)
			if err != nil {
				t.Fatal(err)
			}
			injected := false
			for i, ins := range entry {
				if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnProbeReadKernel) {
					entry = append(entry[:i], append(asm.Instructions{asm.Mov.Imm(asm.R3, 0)}, entry[i:]...)...)
					injected = true
					break
				}
			}
			if injected != (tc.emit != EmitExit) {
				t.Fatalf("copy injection=%v emit=%v", injected, tc.emit)
			}
			if tc.reject {
				out, err = compileFilterWithSlots("eth where action == XDP_DROP", true, true, ebpf.XDP, nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			scratch, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: scratchBufSize, MaxEntries: 1})
			if err != nil {
				t.Fatal(err)
			}
			p.maps = append(p.maps, scratch)
			exit, err := buildGatedExitInsns(h, out, filter.TargetFilters{}, outer.FD(), hold.FD(), p.StatsMap.FD(), scratch.FD(), nil, nil, tc.emit, 64, 8, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := attachTracingProbe(p, target, "copy_exit", xdpFuncName, ebpf.AttachTraceFExit, exit); err != nil {
				t.Fatal(err)
			}
			if err := attachTracingProbe(p, target, "copy_entry", xdpFuncName, ebpf.AttachTraceFEntry, entry); err != nil {
				t.Fatal(err)
			}
			if _, err := target.Run(&ebpf.RunOptions{Data: dsltest.BuildEthIPv4UDP(t, 1234, 6081, []byte{1, 2, 3, 4})}); err != nil {
				t.Fatal(err)
			}
			if err := p.Quiesce(); err != nil {
				t.Fatal(err)
			}
			stats, err := p.ExportStats()
			if err != nil {
				t.Fatal(err)
			}
			records := uint64(0)
			for _, m := range inners {
				r, err := fastrb.New(m.FD(), int(m.MaxEntries()))
				if err != nil {
					t.Fatal(err)
				}
				r.ReadBatch(func([]byte) { records++ })
				_ = r.Close()
			}
			if stats.Submitted != tc.submitted || stats.CopyFail != tc.failed || stats.LookupMiss+stats.ReserveFail != 0 || records != tc.submitted {
				t.Fatalf("records=%d stats=%+v want submitted=%d copy_fail=%d", records, stats, tc.submitted, tc.failed)
			}
		})
	}
}

// TestBpfGatedResidualHold covers a hold whose fexit never ran: after
// Quiesce, ExportStats counts it as unpaired. Only the entry half is
// attached, the way an invocation whose exit a trampoline rewrite
// skipped leaves its slot.
func TestBpfGatedResidualHold(t *testing.T) {
	target := loadDummyXDP(t)
	p := &Probe{}
	defer func() { _ = p.Close() }()
	if err := p.initExportStats(); err != nil {
		t.Fatal(err)
	}
	hold, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: holdHdr + 64, MaxEntries: uint32(holdSlots)})
	if err != nil {
		t.Fatal(err)
	}
	p.maps = append(p.maps, hold)
	p.holdMap = hold
	h, _ := hook.ByProgramType(ebpf.XDP)
	var out codegen.Output
	out.Capture.MaxCapLen = 64
	entry, err := buildGatedEntryInsns(h, out, filter.TargetFilters{}, hold.FD(), 0, p.StatsMap.FD(), 0, nil, nil, EmitBoth, 64, 0)
	if err != nil {
		t.Fatal(err)
	}
	entry = constantJiffies(t, entry) // a jiffy tick between the runs must not resync
	if err := attachTracingProbe(p, target, "residual_entry", xdpFuncName, ebpf.AttachTraceFEntry, entry); err != nil {
		t.Fatal(err)
	}
	frame := dsltest.BuildEthIPv4UDP(t, 1234, 6081, []byte{1, 2, 3, 4})
	runPinned(t, affinityCPUs(t)[0], func() { // both runs must share one CPU's hold
		for range 2 {
			if _, err := target.Run(&ebpf.RunOptions{Data: frame}); err != nil {
				t.Fatal(err)
			}
		}
	})
	if err := p.Quiesce(); err != nil {
		t.Fatal(err)
	}
	stats, err := p.ExportStats()
	if err != nil {
		t.Fatal(err)
	}
	// With no exit to give the depth back, the second run held at depth 1;
	// both holds are left behind.
	if stats.HoldOverwrite != 0 || stats.HoldUnpaired != 2 {
		t.Fatalf("stats %+v, want hold_overwrite=0 hold_unpaired=2", stats)
	}
}

// constantJiffies replaces the gated entry's bpf_jiffies64 call with 0,
// so a test's consecutive runs never look a jiffy apart.
func constantJiffies(t *testing.T, insns asm.Instructions) asm.Instructions {
	t.Helper()
	for i, ins := range insns {
		if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnJiffies64) {
			insns[i] = asm.Mov.Imm(asm.R0, 0).WithMetadata(ins.Metadata)
			return insns
		}
	}
	t.Fatal("no bpf_jiffies64 call in the gated entry")
	return nil
}

// TestBpfGatedStaleHoldNeverPairs leaves a valid hold behind (only the
// entry half attached, as when a trampoline rewrite skips the fexit),
// waits for the depth to go stale, then runs an invocation whose entry
// filter misses at that same depth. Its fexit must drop the stale hold
// even when the frame identity matches (here the identity check is
// removed, standing in for a recycled frame address).
func TestBpfGatedStaleHoldNeverPairs(t *testing.T) {
	target := loadDummyXDP(t)
	outer, inners, err := createShardedRingbuf("staletest")
	if err != nil {
		t.Fatal(err)
	}
	p := &Probe{EventsMap: outer, InnerMaps: inners, maps: append([]*ebpf.Map{outer}, inners...)}
	defer func() { _ = p.Close() }()
	if err := p.initExportStats(); err != nil {
		t.Fatal(err)
	}
	hold, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: holdHdr + 64, MaxEntries: uint32(holdSlots)})
	if err != nil {
		t.Fatal(err)
	}
	scratch, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: scratchBufSize, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	p.maps = append(p.maps, hold, scratch)
	p.holdMap = hold
	h, _ := hook.ByProgramType(ebpf.XDP)
	entryOut, err := compileFilterWithSlots("eth/ipv4/udp[dport==6081]", true, false, ebpf.XDP, nil)
	if err != nil {
		t.Fatal(err)
	}
	entryOut.Capture.MaxCapLen = 64
	entry, err := buildGatedEntryInsns(h, entryOut, filter.TargetFilters{}, hold.FD(), 0, p.StatsMap.FD(), scratch.FD(), nil, nil, EmitBoth, 64, 0)
	if err != nil {
		t.Fatal(err)
	}
	var exitOut codegen.Output
	exitOut.Capture.MaxCapLen = 64
	exit, err := buildGatedExitInsns(h, exitOut, filter.TargetFilters{}, outer.FD(), hold.FD(), p.StatsMap.FD(), scratch.FD(), nil, nil, EmitBoth, 64, 8, 0)
	if err != nil {
		t.Fatal(err)
	}
	removed := 0
	for i, ins := range exit {
		if ins.OpCode.JumpOp() == asm.JNE && ins.Dst == asm.R1 && ins.Src == asm.R2 && ins.Reference() == "hold_unpaired" {
			exit[i] = asm.Mov.Reg(asm.R1, asm.R1).WithMetadata(ins.Metadata) // identity check off
			removed++
		}
	}
	if removed != 1 {
		t.Fatalf("removed %d identity checks, want 1", removed)
	}
	if err := attachTracingProbe(p, target, "stale_entry", xdpFuncName, ebpf.AttachTraceFEntry, entry); err != nil {
		t.Fatal(err)
	}
	match := dsltest.BuildEthIPv4UDP(t, 1234, 6081, []byte{1, 2, 3, 4})
	miss := dsltest.BuildEthIPv4UDP(t, 1234, 9999, []byte{1, 2, 3, 4})
	runPinned(t, affinityCPUs(t)[0], func() {
		if _, err := target.Run(&ebpf.RunOptions{Data: match}); err != nil { // holds at depth 0, never consumed
			t.Fatal(err)
		}
		if err := attachTracingProbe(p, target, "stale_exit", xdpFuncName, ebpf.AttachTraceFExit, exit); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)                                   // the open depth goes stale
		if _, err := target.Run(&ebpf.RunOptions{Data: miss}); err != nil { // resyncs to depth 0, misses the filter
			t.Fatal(err)
		}
	})
	// Read before Quiesce, so the count is the fexit's, not the scan of
	// holds left valid at the end.
	stats, err := p.ExportStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Submitted != 0 || stats.HoldUnpaired != 1 || stats.HoldResync != 1 || stats.HoldOverwrite != 0 {
		t.Fatalf("stats %+v, want no export, hold_unpaired=1, hold_depth_resync=1", stats)
	}
	if err := p.Quiesce(); err != nil {
		t.Fatal(err)
	}
	if after, err := p.ExportStats(); err != nil || after.HoldUnpaired != 1 {
		t.Fatalf("after Quiesce: stats %+v (%v), want the stale hold consumed (hold_unpaired=1)", after, err)
	}
}
