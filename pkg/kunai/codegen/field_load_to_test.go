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
// label, the write-back overlay lands in the destination too, no
// instruction copies a register onto itself, and the R4 arm is the
// bounded idiom the bracket and where guards rely on (emitBoundedLoad is
// its wrapper).
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
				if ins.OpCode.ALUOp() == asm.Mov && ins.OpCode.Source() == asm.RegSource && ins.Dst == ins.Src {
					t.Errorf("%v copies a register onto itself", ins)
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
				want := asm.Instructions{
					asm.Mov.Reg(asm.R3, asm.R4),
					asm.Add.Imm(asm.R3, 6),
					asm.JGT.Imm(asm.R3, int32(ScratchBufSize)-1, "fail"),
					asm.Add.Reg(asm.R3, asm.R0),
					asm.Add.Imm(asm.R3, 1),
					asm.JGT.Reg(asm.R3, asm.R1, "fail"),
					asm.LoadMem(asm.R3, asm.R3, -1, asm.Byte),
				}
				if got := emitFieldLoadTo(asm.R3, anchor, 6, asm.Byte, "fail"); !reflect.DeepEqual(got, want) {
					t.Errorf("R4 arm with dst = R3:\n%v\nwant the bounded idiom\n%v", got, want)
				}
			}
		})
	}
	// The slot arm with a zero field offset is the slot load and the
	// bounded load, nothing in between.
	if got := emitFieldLoadTo(asm.R2, slotAnchor(-240), 0, asm.Half, "fail"); got[0].Src != asm.R10 || got[1].OpCode.JumpOp() != asm.JGT {
		t.Errorf("slot arm at offset 0 = %v; want the slot load straight into the bound check", got)
	}
}

// TestEmitBoundedLoadIntoOtherRegister: the wrapper writes dst alone, so
// a caller that keeps a value in R3 (none today; emitFlagTriggers keeps
// the flag byte in R5) could rely on it.
func TestEmitBoundedLoadIntoOtherRegister(t *testing.T) {
	insns := emitBoundedLoad(asm.R5, -4, asm.Byte, "fail")
	for _, ins := range insns {
		if (ins.OpCode.Class().IsALU() || ins.OpCode.Class() == asm.LdXClass) && ins.Dst != asm.R5 {
			t.Errorf("%v writes %v", ins, ins.Dst)
		}
	}
	if first := insns[0]; first.OpCode.JumpOp() != asm.JLT || first.Dst != asm.R4 || first.Constant != 4 {
		t.Errorf("first instruction %v; want the underflow guard JLT R4, 4", first)
	}
	if last := insns[len(insns)-1]; last.OpCode.Class() != asm.LdXClass || last.Dst != asm.R5 || last.Src != asm.R5 {
		t.Errorf("last instruction %v; want the load into R5", last)
	}
}

// TestFoldOffsetIntoScalarSameRegister: folding in place never copies the
// register onto itself, and a zero offset folds to nothing; a different
// destination keeps the copy.
func TestFoldOffsetIntoScalarSameRegister(t *testing.T) {
	for _, c := range []struct {
		off  int32
		want asm.Instructions
	}{
		{-4, asm.Instructions{asm.JLT.Imm(asm.R2, 4, "fail"), asm.Sub.Imm(asm.R2, 4)}},
		{6, asm.Instructions{asm.Add.Imm(asm.R2, 6)}},
		{0, nil},
	} {
		if got := foldOffsetIntoScalar(asm.R2, asm.R2, c.off, "fail"); !reflect.DeepEqual(got, c.want) {
			t.Errorf("fold in place, off %d:\n%v\nwant\n%v", c.off, got, c.want)
		}
	}
	for _, c := range []struct {
		off  int32
		want asm.Instructions
	}{
		{-4, asm.Instructions{asm.JLT.Imm(asm.R4, 4, "fail"), asm.Mov.Reg(asm.R3, asm.R4), asm.Sub.Imm(asm.R3, 4)}},
		{6, asm.Instructions{asm.Mov.Reg(asm.R3, asm.R4), asm.Add.Imm(asm.R3, 6)}},
		{0, asm.Instructions{asm.Mov.Reg(asm.R3, asm.R4)}},
	} {
		if got := foldOffsetIntoScalar(asm.R3, asm.R4, c.off, "fail"); !reflect.DeepEqual(got, c.want) {
			t.Errorf("fold into R3 from R4, off %d:\n%v\nwant\n%v", c.off, got, c.want)
		}
	}
}
