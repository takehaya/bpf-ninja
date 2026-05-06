package codegen

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
)

// TestAssertCallbackComplexityUnderThreshold pins that a callback
// with branch count just below the cap passes.
func TestAssertCallbackComplexityUnderThreshold(t *testing.T) {
	insns := makeCallbackWithBranches(callbackBranchThreshold)
	if err := assertCallbackComplexity(insns, "test_under"); err != nil {
		t.Errorf("threshold case rejected: %v", err)
	}
}

// TestAssertCallbackComplexityOverThreshold pins that one extra
// branch trips the assertion with ErrNotImplemented and a message
// that names the callback symbol + branch count.
func TestAssertCallbackComplexityOverThreshold(t *testing.T) {
	insns := makeCallbackWithBranches(callbackBranchThreshold + 1)
	err := assertCallbackComplexity(insns, "test_over")
	if err == nil {
		t.Fatal("expected ErrNotImplemented, got nil")
	}
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("err does not wrap ErrNotImplemented: %v", err)
	}
	if !strings.Contains(err.Error(), "test_over") {
		t.Errorf("err missing callback symbol: %v", err)
	}
}

// TestAssertCallbackComplexityCountsAllBranchKinds confirms every
// JumpOp variant (Ja, JEq, JNE, JLT, JGT, JLE, JGE, JSet, JSGT,
// JSGE, JSLT, JSLE) counts toward the limit. Excludes Call and
// Exit (subprogram / return, not loop-internal control flow).
func TestAssertCallbackComplexityCountsAllBranchKinds(t *testing.T) {
	insns := asm.Instructions{
		asm.Ja.Label("a"),
		asm.JEq.Imm(asm.R0, 0, "b"),
		asm.JNE.Imm(asm.R0, 0, "c"),
		asm.JLT.Imm(asm.R0, 0, "d"),
		asm.JGT.Imm(asm.R0, 0, "e"),
		asm.JLE.Imm(asm.R0, 0, "f"),
		asm.JGE.Imm(asm.R0, 0, "g"),
		asm.JSet.Imm(asm.R0, 0, "h"),
		asm.JSGT.Imm(asm.R0, 0, "i"),
		asm.JSGE.Imm(asm.R0, 0, "j"),
		asm.JSLT.Imm(asm.R0, 0, "k"),
		asm.JSLE.Imm(asm.R0, 0, "l"),
		// Call + Mov + Return are NOT branches.
		asm.FnMapLookupElem.Call(),
		asm.Mov.Imm(asm.R0, 1),
		asm.Return(),
	}
	count := 0
	for i := range insns {
		if isBranchOpcode(insns[i].OpCode) {
			count++
		}
	}
	if count != 12 {
		t.Errorf("counted %d branches, want 12 (one per JumpOp kind, excluding Call/Exit)", count)
	}
}

// makeCallbackWithBranches builds a synthetic instruction slice with
// exactly n branch instructions plus a few non-branch fillers, so
// the assertion's count matches n.
func makeCallbackWithBranches(n int) asm.Instructions {
	var insns asm.Instructions
	for i := 0; i < n; i++ {
		insns = append(insns, asm.JNE.Imm(asm.R0, int32(i), "unreachable"))
	}
	insns = append(insns, asm.Mov.Imm(asm.R0, 0), asm.Return())
	return insns
}
