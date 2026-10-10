package codegen

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf/asm"
)

// TestEmitFieldLoadToWritesOnlyDst pins the register contract of
// emitFieldLoadTo under every anchor: the destination is the only
// register written (emitHeaderCount relies on it to keep R3, the index,
// and R5, the slot value, alive), every jump takes the caller's fail
// label, the write-back overlay lands in the destination too, and the R4
// arm with dst = R3 is emitBoundedLoad's sequence (the byte identity the
// bracket and where guards rely on).
func TestEmitFieldLoadToWritesOnlyDst(t *testing.T) {
	overlay := slotAnchor(-240)
	overlay.WriteBack, overlay.WriteBackOff, overlay.WriteBackSlot = true, 6, -248
	for name, anchor := range map[string]layerAnchor{"slot": slotAnchor(-240), "r4": r4Anchor(), "abs": absAnchor(54), "overlay": overlay} {
		t.Run(name, func(t *testing.T) {
			insns := emitFieldLoadTo(asm.R2, anchor, 6, asm.Byte, "fail")
			for _, ins := range insns {
				if (ins.OpCode.Class().IsALU() || ins.OpCode.Class() == asm.LdXClass) && ins.Dst != asm.R2 {
					t.Errorf("%v writes %v", ins, ins.Dst)
				}
				if ins.OpCode.Class().IsJump() && ins.Reference() != "fail" {
					t.Errorf("%v jumps to %q, want the caller's fail label", ins, ins.Reference())
				}
			}
			last := insns[len(insns)-1]
			if last.OpCode.Class() != asm.LdXClass || last.Dst != asm.R2 {
				t.Errorf("last instruction %v is not the load into R2", last)
			}
			if anchor.WriteBack && (len(insns) != 1 || last.Src != asm.R10 || last.Offset != -248) {
				t.Errorf("overlay read is %v; want one load of R10-248", insns)
			}
			if anchor.UseR4 {
				got, want := emitFieldLoadTo(asm.R3, anchor, 6, asm.Byte, "fail"), emitBoundedLoad(asm.R3, 6, asm.Byte, "fail")
				if !reflect.DeepEqual(got, want) {
					t.Errorf("R4 arm with dst = R3:\n%v\nwant emitBoundedLoad's\n%v", got, want)
				}
			}
		})
	}
}
