package program

import (
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	statReserveFail uint32 = iota
	statSubmitted
	statLookupMiss
	statCopyFail
	// statHoldOverwrite counts gated entries that found the hold slot still
	// valid: the earlier entry-matched invocation that wrote it can no longer
	// be decided at its exit (synchronous re-entry of the target).
	statHoldOverwrite
	// statHoldUnpaired counts gated exits that consumed a hold written by a
	// different invocation; that invocation's entry image is dropped.
	// ExportStats adds the holds no exit consumed by the end of the capture.
	statHoldUnpaired
	statCount
)

type ExportStats struct {
	ReserveFail, Submitted, LookupMiss, CopyFail uint64
	// HoldOverwrite and HoldUnpaired count entry-matched gated invocations
	// whose exit decision was lost; their records are neither exported nor
	// counted as selected.
	HoldOverwrite, HoldUnpaired uint64
}

func (p *Probe) ExportStats() (ExportStats, error) {
	var out ExportStats
	if p.StatsMap == nil {
		return out, fmt.Errorf("export counters unavailable")
	}
	fields := []*uint64{&out.ReserveFail, &out.Submitted, &out.LookupMiss, &out.CopyFail, &out.HoldOverwrite, &out.HoldUnpaired}
	for key, dst := range fields {
		var values []uint64
		if err := p.StatsMap.Lookup(uint32(key), &values); err != nil {
			return out, err
		}
		for _, n := range values {
			*dst += n
		}
	}
	if p.holdMap != nil && p.links == nil {
		// After Quiesce, a hold still marked valid is an invocation whose
		// fexit never ran (a trampoline rewrite by another attach made it
		// skip its exit), with no later exit on that CPU to count it.
		n, err := p.residualHolds()
		if err != nil {
			return out, err
		}
		out.HoldUnpaired += n
	}
	return out, nil
}

func (p *Probe) residualHolds() (uint64, error) {
	var values [][]byte
	if err := p.holdMap.Lookup(uint32(0), &values); err != nil {
		return 0, fmt.Errorf("reading gated holds: %w", err)
	}
	var n uint64
	for _, v := range values {
		if binary.NativeEndian.Uint16(v[holdValid:]) != 0 {
			n++
		}
	}
	return n, nil
}

func (p *Probe) initExportStats() error {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "ninja_stats", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: statCount})
	if err != nil {
		return err
	}
	p.StatsMap = m
	p.maps = append(p.maps, m)
	return nil
}
func emitExportCounter(fd int, key uint32, label string) asm.Instructions {
	if fd <= 0 {
		return asm.Instructions{asm.Ja.Label("exit").WithSymbol(label)}
	}
	return asm.Instructions{
		asm.StoreImm(asm.R10, -16, int64(key), asm.Word).WithSymbol(label),
		asm.LoadMapPtr(asm.R1, fd), asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "exit"),
		// Atomic addition also covers nested execution on one CPU.
		asm.Mov.Imm(asm.R1, 1), asm.StoreXAdd(asm.R0, asm.R1, asm.DWord), asm.Ja.Label("exit"),
	}
}

// emitCounterInc adds one to counter key and falls through to the
// instruction labelled next (also the target when the lookup misses).
// Clobbers R0-R5 and stack[-16].
func emitCounterInc(fd int, key uint32, next string) asm.Instructions {
	if fd <= 0 {
		return nil
	}
	return asm.Instructions{
		asm.StoreImm(asm.R10, -16, int64(key), asm.Word),
		asm.LoadMapPtr(asm.R1, fd), asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, next),
		asm.Mov.Imm(asm.R1, 1), asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
	}
}
func emitExportTerminals(fd int) asm.Instructions {
	var out asm.Instructions
	out = append(out, emitExportCounter(fd, statSubmitted, "rb_submitted")...)
	if fd > 0 {
		out = append(out, emitExportCounter(fd, statReserveFail, "rb_fail")...)
		out = append(out, emitExportCounter(fd, statLookupMiss, "rb_lookup_fail")...)
	}
	out = append(out, asm.LoadMem(asm.R1, asm.R10, -32, asm.DWord).WithSymbol("rb_copy_fail"), asm.Mov.Imm(asm.R2, 0), asm.FnRingbufDiscard.Call())
	out = append(out, emitExportCounter(fd, statCopyFail, "rb_copy_count")...)
	return out
}
