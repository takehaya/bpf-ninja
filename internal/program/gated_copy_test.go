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
			hold, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: holdHdr + 64, MaxEntries: 1})
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
// skipped leaves the slot.
func TestBpfGatedResidualHold(t *testing.T) {
	target := loadDummyXDP(t)
	p := &Probe{}
	defer func() { _ = p.Close() }()
	if err := p.initExportStats(); err != nil {
		t.Fatal(err)
	}
	hold, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: holdHdr + 64, MaxEntries: 1})
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
	if err := attachTracingProbe(p, target, "residual_entry", xdpFuncName, ebpf.AttachTraceFEntry, entry); err != nil {
		t.Fatal(err)
	}
	frame := dsltest.BuildEthIPv4UDP(t, 1234, 6081, []byte{1, 2, 3, 4})
	runPinned(t, 0, func() { // both runs must share one CPU's hold
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
	// The second run overwrote the first hold; the second is left behind.
	if stats.HoldOverwrite != 1 || stats.HoldUnpaired != 1 {
		t.Fatalf("stats %+v, want hold_overwrite=1 hold_unpaired=1", stats)
	}
}
