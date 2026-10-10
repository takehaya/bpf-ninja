package codegen

import (
	"testing"

	"github.com/cilium/ebpf/asm"
)

// TestEmitFieldLoadToWritesOnlyDst pins the register contract of
// emitFieldLoadTo under every anchor: the destination is the only
// register written (emitHeaderCount relies on it to keep R3, the index,
// and R5, the slot value, alive), and the write-back overlay lands in the
// destination too. With dst = R3 and the reject label the output is
// emitFieldLoad's.
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
			}
			last := insns[len(insns)-1]
			if last.OpCode.Class() != asm.LdXClass || last.Dst != asm.R2 {
				t.Errorf("last instruction %v is not the load into R2", last)
			}
			if anchor.WriteBack && (len(insns) != 1 || last.Src != asm.R10 || last.Offset != -248) {
				t.Errorf("overlay read is %v; want one load of R10-248", insns)
			}
			same := emitFieldLoadTo(asm.R3, anchor, 6, asm.Byte, dslReject)
			if ref := emitFieldLoad(anchor, 6, asm.Byte); len(same) != len(ref) {
				t.Errorf("dst=R3 differs from emitFieldLoad: %v vs %v", same, ref)
			}
		})
	}
}
