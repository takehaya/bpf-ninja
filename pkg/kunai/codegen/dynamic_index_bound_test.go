package codegen

import (
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
)

// TestEmitDynamicIndexReadHeaderCountAnchors pins the shape of the
// header-count bound (D-031) under every anchor emitDynamicIndexRead
// accepts. Only the slot anchor is reachable with the bundled vocabulary
// (srv6 follows the variable-length ipv6, so the where clause reads it
// through its runtime entry slot); the R4 and absolute arms are pinned
// here so a future header-counted stack at a fixed offset inherits a
// tested sequence. In every arm the count travels in R2, the index stays
// in R3, the slot value stays in R5, and the compare is `JGE R3, R2`.
func TestEmitDynamicIndexReadHeaderCountAnchors(t *testing.T) {
	ref := &ir.FieldRef{Aux: &ir.AuxRef{Stack: &ir.StackIndex{Capacity: 8}}}
	bound := indexBound{hdr: true, byteOff: 4, addend: 1}
	anchors := map[string]layerAnchor{
		"slot": slotAnchor(-240),
		"r4":   r4Anchor(),
		"abs":  absAnchor(54),
	}
	for name, anchor := range anchors {
		t.Run(name, func(t *testing.T) {
			insns := emitDynamicIndexRead(ref, anchor, 3, bound, "fail")
			// The index is read first; the count read starts right after
			// the capacity check and writes only R2 until the compare.
			capIdx := -1
			for i, ins := range insns {
				if ins.OpCode == asm.JGE.Op(asm.ImmSource) && ins.Dst == asm.R3 && ins.Constant == 8 {
					capIdx = i
				}
			}
			if capIdx < 0 {
				t.Fatalf("no capacity check:\n%v", insns)
			}
			tail := insns[capIdx+1:]
			last := tail[len(tail)-1]
			if last.OpCode != asm.JGE.Op(asm.RegSource) || last.Dst != asm.R3 || last.Src != asm.R2 || last.Reference() != "fail" {
				t.Fatalf("count compare is %v; want JGE R3, R2 -> fail", last)
			}
			var loads, addend int
			for _, ins := range tail[:len(tail)-1] {
				if ins.OpCode.Class().IsALU() || ins.OpCode.Class() == asm.LdXClass {
					if ins.Dst != asm.R2 {
						t.Errorf("count read writes %v: %v", ins.Dst, ins)
					}
				}
				if ins.OpCode.Class() == asm.LdXClass {
					loads++
					if ins.OpCode != asm.LoadMemOp(asm.Byte) || ins.Src != asm.R2 || ins.Offset != -1 {
						t.Errorf("count load %v is not the bounded byte load", ins)
					}
				}
				if ins.OpCode == asm.Add.Op(asm.ImmSource) && ins.Constant == 1 && ins.Dst == asm.R2 {
					addend++
				}
			}
			if loads != 1 || addend < 1 {
				t.Fatalf("count read: %d loads, %d addend adds:\n%v", loads, addend, tail)
			}
			// The index arrives through the anchor the caller named.
			switch {
			case anchor.UseSlot:
				if insns[0].OpCode != asm.LoadMemOp(asm.DWord) || insns[0].Dst != asm.R5 || insns[0].Offset != -240 {
					t.Errorf("slot anchor: first insn %v should load R5 from the slot", insns[0])
				}
			case anchor.UseR4:
				if insns[0].Dst != asm.R3 || insns[0].Src != offsetBase {
					t.Errorf("r4 anchor: first insn %v should derive R3 from R4", insns[0])
				}
			default:
				if insns[0].OpCode != asm.Mov.Op(asm.ImmSource) || insns[0].Constant != 54+3 {
					t.Errorf("abs anchor: first insn %v should set R3 = 57", insns[0])
				}
			}
		})
	}
}
