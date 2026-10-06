package codegen

import (
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// cursorCounter proves that a byte counter decreases by exactly the cursor
// advance on every iteration. Such a counter can be represented as an immutable
// region end, avoiding two correlated mutable quantities in the verifier.
func (c *pmCtx) cursorCounter(entry *vocab.ParseState) string {
	sel := entry.Trans.Select
	if !hasCounterAndKindKeys(sel) || counterTrueTargetFor2Key(sel) != vocab.StateAccept {
		return ""
	}
	for i, st := range c.machine.States {
		if st == entry {
			if !c.spec.RegionCounterTracksBytes(i) {
				return ""
			}
			return sel.Keys[0].Counter
		}
	}
	return ""
}

// sameLengthAdvance identifies sibling aliases of the proven region advance.
func (c *pmCtx) sameLengthAdvance(idx, fallback int) bool {
	if idx < 0 {
		return false
	}
	st, def := c.machine.States[idx], c.machine.States[fallback]
	return len(st.Extracts) == 0 && len(st.Advances) == 1 && st.Advances[0].Kind == vocab.AdvanceOpLookahead && st.Advances[0].Skip != nil && *st.Advances[0].Skip == *def.Advances[0].Skip && vocab.LoopSiblingTarget(st) == vocab.LoopSiblingTarget(def)
}

// emitSharedLengthAdvance merges fixed-size validation and variable-size
// skipping after dispatch. R7 is the required length, or zero for the default.
// The immutable region proof makes the one cursor update also account for the
// counter. Sharing the load avoids duplicating bounds branches for each kind.
func (c *pmCtx) emitSharedLengthAdvance(fallback int, lengthLabel, continueLabel, rejectLabel string) asm.Instructions {
	off := c.machine.States[fallback].Advances[0].Skip.LenByteOff
	validated := lengthLabel + "_valid"
	insns := asm.Instructions{asm.Mov.Imm(asm.R7, 0), landingNoop(lengthLabel)}
	insns = append(insns, foldOffsetIntoScalar(asm.R0, asm.R3, int32(off), rejectLabel)...)
	insns = append(insns, boundedScalarLoad(asm.R1, asm.R4, asm.R0, asm.R5, asm.Byte, rejectLabel)...)
	insns = append(insns,
		asm.JEq.Imm(asm.R7, 0, validated),
		asm.JNE.Reg(asm.R1, asm.R7, rejectLabel),
		landingNoop(validated),
		asm.JLT.Imm(asm.R1, int32(off+1), rejectLabel),
		asm.Add.Reg(asm.R3, asm.R1),
		asm.JGT.Imm(asm.R3, ScratchBufSize, rejectLabel),
		asm.Mov.Reg(asm.R0, asm.R4), asm.Add.Reg(asm.R0, asm.R3),
		asm.JGT.Reg(asm.R0, asm.R5, rejectLabel),
		asm.StoreMem(asm.R2, bpfLoopCbCtxOffsetField, asm.R3, asm.DWord),
		asm.Ja.Label(continueLabel),
	)
	return insns
}
