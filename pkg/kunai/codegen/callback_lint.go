package codegen

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
)

// callbackBranchThreshold caps the number of branch instructions
// (conditional jumps + unconditional Ja) a bpf_loop callback may
// contain. Round-2 review surfaced a systemic class of verifier
// blowups (B-2a, B-4 R1, B-4a R1) where a new branch added inside a
// bpf_loop callback inflated scalar IDs across MAX_DEPTH iterations
// and tripped the kernel's 1M-instruction cap. Static counting at
// compile time gives vocab authors a tripwire before hitting the
// kernel verifier.
//
// Caveat: branch count alone does not predict scalar-ID inflation —
// `parse_options` legitimately runs ~44 branches with the existing
// vocab and passes the verifier. The threshold below is sized for
// "tripwire against silent regression," not "verifier-budget oracle."
// A future feature that doubles a callback's branch count is far
// more likely to provoke the verifier than one that adds 1-2; the
// intent is to surface that signal at compile time.
//
// Measured worst case (bundled vocab):
//   - VLAN+ / MPLS+ chain callback:        ~3 branches
//   - IPv6 ext-header chain callback:      ~3 branches
//   - SRv6 segments walk callback:         ~6 branches
//   - TCP options parse_options self-loop: 44 branches
//
// Threshold = worst observed + 50% headroom. Raise only with
// commit-message-level justification (= a real new feature whose
// callback genuinely needs more branches and has been verifier-
// matrix-tested).
const callbackBranchThreshold = 64

// assertCallbackComplexity counts branch instructions in `insns`
// (the assembled bpf_loop callback body) and refuses compilation
// when the count exceeds callbackBranchThreshold. The chain callback
// path (genBpfLoopCallback in bpfloop.go) and the parser-machine
// self-loop callback path (emitSelfLoopCallback in parser_loop.go)
// both call this just before returning their final asm.Instructions.
func assertCallbackComplexity(insns asm.Instructions, sym string) error {
	count := countBranches(insns)
	if count > callbackBranchThreshold {
		return fmt.Errorf("%w: callback %q has %d branch instructions (threshold %d); risks verifier state-ID inflation across MAX_DEPTH iterations (B-2a class, see dsl-followups.md)", ErrNotImplemented, sym, count, callbackBranchThreshold)
	}
	return nil
}

// countBranches returns the count of branch instructions in insns —
// conditional jumps + unconditional Ja, excluding Call / Exit.
func countBranches(insns asm.Instructions) int {
	count := 0
	for i := range insns {
		if isBranchOpcode(insns[i].OpCode) {
			count++
		}
	}
	return count
}

// isBranchOpcode reports whether the OpCode is a conditional jump
// or an unconditional Ja. Excludes Call and Exit (= subprogram /
// return, not loop-internal control flow). JSet (bitwise-and test)
// is included because it produces the same kind of scalar-ID branch
// the verifier tracks.
func isBranchOpcode(op asm.OpCode) bool {
	if op.Class() != asm.JumpClass && op.Class() != asm.Jump32Class {
		return false
	}
	switch op.JumpOp() {
	case asm.Ja, asm.JEq, asm.JGT, asm.JGE, asm.JSet,
		asm.JNE, asm.JSGT, asm.JSGE, asm.JLT, asm.JLE,
		asm.JSLT, asm.JSLE:
		return true
	}
	return false
}
