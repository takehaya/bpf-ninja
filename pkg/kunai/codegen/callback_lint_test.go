package codegen

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
)

// TestCallbackBranchThresholdValue pins the threshold constant itself
// to 64. A silent change to this number (= raising or lowering it)
// would shift the verifier-blowup risk envelope without surfacing in
// the parametric tests below, since those reference the const rather
// than a literal. The 64 number is rationalized in callback_lint.go's
// docblock (worst-case TCP options walk ≈ 44 branches + 50% headroom);
// a drift here MUST be accompanied by an update to that doc and to
// the matching paper §6 limitations sentence.
func TestCallbackBranchThresholdValue(t *testing.T) {
	if callbackBranchThreshold != 64 {
		t.Errorf("callbackBranchThreshold = %d, want 64 — see the callback_lint.go docblock for the rationale; if this is an intentional change, update it before bumping the literal here", callbackBranchThreshold)
	}
}

// TestAssertCallbackComplexityBoundary table-pins the threshold's
// pass/fail behaviour at the boundary. Three rows cover the standard
// "off-by-one" failure modes: just-below (passes), exactly-at
// (passes), and just-above (fails).
func TestAssertCallbackComplexityBoundary(t *testing.T) {
	cases := []struct {
		name     string
		branches int
		wantErr  bool
	}{
		{"just_below_threshold", callbackBranchThreshold - 1, false},
		{"at_threshold", callbackBranchThreshold, false},
		{"just_above_threshold", callbackBranchThreshold + 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insns := makeCallbackWithBranches(tc.branches)
			err := assertCallbackComplexity(insns, "test_"+tc.name)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error at %d branches, got nil", tc.branches)
				}
				if !errors.Is(err, ErrNotImplemented) {
					t.Errorf("err does not wrap ErrNotImplemented: %v", err)
				}
				if !strings.Contains(err.Error(), "test_"+tc.name) {
					t.Errorf("err missing callback symbol: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("expected pass at %d branches, got %v", tc.branches, err)
				}
			}
		})
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
