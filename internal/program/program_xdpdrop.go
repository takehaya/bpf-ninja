// Package program — filter-only XDP drop bench path (B4).
//
// LoadXDPDropBench builds a minimal native XDP program for the §5.5
// datapath macrobench: copy the packet prefix into a per-CPU scratch
// window (the same window model the fentry/tc observers use in
// production), run the compiled filter on the window, bump two
// per-CPU counters (total / matched), and return XDP_DROP for every
// packet. There is no capture path, so cell-to-cell deltas isolate
// the filter cost; the floor variant skips copy + filter entirely so
// the window-copy cost itself is measurable.
//
// Why the window copy instead of running the filter directly on
// ctx->data (runFilterDirect)? kunai's dispatch idiom rebuilds the
// layer pointer and reads back into the previous header at a negative
// offset (e.g. udp.dport from gtp_start-6). On a map-value window the
// verifier proves that statically; on PTR_TO_PACKET a rebuilt pointer
// has no proven range and negative offsets are rejected, so aux-walk
// filters (F7/F9/F10 class) fail to load. Same latent limitation
// applies to LoadXDPNative (--mode xdp); see docs/ja/TODO.md.
package program

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/xdp-ninja/internal/attach"
	"github.com/takehaya/xdp-ninja/pkg/kunai/codegen"
)

const (
	dropStatTotal   uint32 = 0
	dropStatMatched uint32 = 1
)

// DropBench is a handle for an attached filter-only drop program.
type DropBench struct {
	prog  *ebpf.Program
	link  link.Link
	stats *ebpf.Map
	maps  []*ebpf.Map
}

// LoadXDPDropBench compiles filterExpr (kunai DSL when useDSL, else
// pcap-filter via cbpfc; empty expr = accept-all, which still pays
// the window copy) and attaches the drop program to state's
// interface. floor=true skips copy + filter entirely (counter + drop
// only). Caller must ensure no other XDP program is attached.
func LoadXDPDropBench(state *attach.InterfaceState, filterExpr string, useDSL, floor bool) (*DropBench, error) {
	bench, err := newXDPDropBench(filterExpr, useDSL, floor)
	if err != nil {
		return nil, err
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   bench.prog,
		Interface: state.IfIndex,
	})
	if err != nil {
		_ = bench.Close()
		return nil, fmt.Errorf("attaching XDP: %w", err)
	}
	bench.link = l
	return bench, nil
}

// newXDPDropBench builds the program + maps without attaching, so
// verifier-load tests can exercise the builder standalone.
func newXDPDropBench(filterExpr string, useDSL, floor bool) (*DropBench, error) {
	var out codegen.Output
	if !floor {
		var err error
		out, err = compileFilter(filterExpr, useDSL, false, ebpf.XDP)
		if err != nil {
			return nil, err
		}
	}

	stats, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "xdpdrop_stats",
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 2,
	})
	if err != nil {
		return nil, fmt.Errorf("creating stats map: %w", err)
	}
	bench := &DropBench{stats: stats, maps: []*ebpf.Map{stats}}

	scratchFD := -1
	if !floor {
		scratch, err := ebpf.NewMap(&ebpf.MapSpec{
			Name:    "xdpdrop_scratch",
			Type:    ebpf.PerCPUArray,
			KeySize: 4, ValueSize: scratchBufSize, MaxEntries: 1,
		})
		if err != nil {
			_ = bench.Close()
			return nil, fmt.Errorf("creating scratch map: %w", err)
		}
		bench.maps = append(bench.maps, scratch)
		scratchFD = scratch.FD()
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "xdpdrop_bench",
		Type:         ebpf.XDP,
		Instructions: buildXDPDropInsns(out, stats.FD(), scratchFD, floor),
		License:      "GPL",
	})
	if err != nil {
		_ = bench.Close()
		return nil, fmt.Errorf("loading XDP drop program: %w", err)
	}
	bench.prog = prog
	return bench, nil
}

// Counters returns the per-CPU sums of processed and matched packets.
func (d *DropBench) Counters() (total, matched uint64, err error) {
	sum := func(slot uint32) (uint64, error) {
		var vals []uint64
		if err := d.stats.Lookup(&slot, &vals); err != nil {
			return 0, fmt.Errorf("stats lookup slot %d: %w", slot, err)
		}
		var s uint64
		for _, v := range vals {
			s += v
		}
		return s, nil
	}
	if total, err = sum(dropStatTotal); err != nil {
		return 0, 0, err
	}
	if matched, err = sum(dropStatMatched); err != nil {
		return 0, 0, err
	}
	return total, matched, nil
}

// Close detaches and releases the program and maps.
func (d *DropBench) Close() error {
	var first error
	if d.link != nil {
		if err := d.link.Close(); err != nil {
			first = err
		}
	}
	if d.prog != nil {
		if err := d.prog.Close(); err != nil && first == nil {
			first = err
		}
	}
	for _, m := range d.maps {
		if err := m.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// buildXDPDropInsns assembles:
//
//	prologue → total++ → [window copy → filter] → matched++ → XDP_DROP
//
// floor=true drops the bracketed part. The filter's no-match branch
// jumps to "exit", skipping the matched counter; with an empty filter
// every copied packet falls through to matched++.
//
// Host stack slots (all shallower than codegen.KunaiStackTop = -56,
// so they cannot clash with kunai's spills):
//
//	 -4: stats slot index
//	-16: scratch map key (u32 0)
//	-24: scratch value ptr
//	-32: copy_len
func buildXDPDropInsns(filterOut codegen.Output, statsFD, scratchFD int, floor bool) asm.Instructions {
	var insns asm.Instructions
	insns = append(insns, loadXDPPacketPointers()...)
	insns = append(insns, bumpDropStat(statsFD, dropStatTotal, "xd_total_done")...)
	if !floor {
		insns = append(insns, copyWindowXDP(scratchFD)...)
		insns = append(insns, filterOut.Main...)
		if len(filterOut.Main) > 0 {
			insns = append(insns, asm.JEq.Imm(asm.R2, 0, "exit").WithSymbol("filter_result"))
		}
	}
	insns = append(insns, bumpDropStat(statsFD, dropStatMatched, "xd_match_done")...)
	insns = append(insns,
		asm.Mov.Imm(asm.R0, xdpDrop).WithSymbol("exit"),
		asm.Return(),
	)
	if len(filterOut.Callbacks) > 0 {
		insns[0] = btf.WithFuncMetadata(insns[0], codegen.MainFilterFuncBTF("xdpdrop_filter"))
		insns = append(insns, filterOut.Callbacks...)
	}
	return insns
}

// copyWindowXDP copies min(pkt_len, scratchBufSize) packet bytes into
// the per-CPU scratch window with bpf_xdp_load_bytes, then sets the
// filter ABI inputs R0 = window start, R1 = window end (R9 = pkt_len
// from the prologue survives the helper calls).
//
// XDP counterpart of runFilter (tracing), which can over-read with
// bpf_probe_read_kernel; bpf_xdp_load_bytes needs the exact length,
// so the clamp runs after the map lookup and feeds R4 without a stack
// roundtrip — a spill/fill would drop the umin=1 constraint that 6.1
// / 6.6 require for the helper's size argument (same ordering rule as
// captureXDPNative).
func copyWindowXDP(scratchFD int) asm.Instructions {
	return asm.Instructions{
		// scratch = map_lookup(&key0)
		asm.LoadMapPtr(asm.R1, scratchFD),
		asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16),
		asm.StoreImm(asm.R2, 0, 0, asm.Word),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.StoreMem(asm.R10, -24, asm.R0, asm.DWord),

		// copy_len = min(pkt_len, scratchBufSize); empty packet → exit
		asm.Mov.Reg(asm.R3, asm.R9),
		asm.JLE.Imm(asm.R3, int32(scratchBufSize), "xd_len_ok"),
		asm.Mov.Imm(asm.R3, int32(scratchBufSize)),
		asm.JLT.Imm(asm.R3, 1, "exit").WithSymbol("xd_len_ok"),
		asm.StoreMem(asm.R10, -32, asm.R3, asm.DWord),

		// bpf_xdp_load_bytes(ctx, 0, scratch, copy_len)
		asm.Mov.Reg(asm.R4, asm.R3), // len first: keeps umin=1, R3 free for dst
		asm.Mov.Reg(asm.R3, asm.R0), // dst = scratch
		asm.Mov.Reg(asm.R1, asm.R6), // ctx
		asm.Mov.Imm(asm.R2, 0),      // offset
		asm.FnXdpLoadBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, "exit"),

		// filter ABI: R0 = window start, R1 = window end
		asm.LoadMem(asm.R0, asm.R10, -24, asm.DWord),
		asm.LoadMem(asm.R1, asm.R10, -32, asm.DWord),
		asm.Add.Reg(asm.R1, asm.R0),
	}
}

// bumpDropStat increments stats[slot] for the current CPU. Helpers
// clobber only R0-R5, so R6-R9 packet state survives. The skip label
// needs a landing instruction; the trailing Mov is that pad.
func bumpDropStat(statsFD int, slot uint32, skipLabel string) asm.Instructions {
	return asm.Instructions{
		asm.StoreImm(asm.R10, -4, int64(slot), asm.Word),
		asm.LoadMapPtr(asm.R1, statsFD),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, skipLabel),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(skipLabel),
	}
}
