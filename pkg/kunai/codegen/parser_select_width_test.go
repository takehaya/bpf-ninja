package codegen

import (
	"testing"

	"github.com/cilium/ebpf/asm"
)

// TestLoadBytesForBits pins the LDX width chosen per lookahead key
// width: the next power of two ≥ ceil(bits/8).
func TestLoadBytesForBits(t *testing.T) {
	for _, tc := range []struct{ bits, want int }{
		{8, 1}, {16, 2}, {24, 4},
	} {
		if got := loadBytesForBits(tc.bits); got != tc.want {
			t.Errorf("loadBytesForBits(%d) = %d; want %d", tc.bits, got, tc.want)
		}
	}
}

// TestSelectKeyNormalize pins the load→value normalization for each
// shape: an 8-bit lookahead needs nothing; a 24-bit lookahead loads a
// Word, byte-swaps to host order, and right-shifts 8 (no mask, the
// shift already zero-extends to the key bits); a sub-byte field key
// shifts then masks.
func TestSelectKeyNormalize(t *testing.T) {
	countOp := func(insns asm.Instructions, pred func(asm.Instruction) bool) int {
		n := 0
		for _, in := range insns {
			if pred(in) {
				n++
			}
		}
		return n
	}
	isEnd := func(in asm.Instruction) bool { return in.OpCode.ALUOp() == asm.Swap }
	isRSh := func(in asm.Instruction) bool { return in.OpCode.ALUOp() == asm.RSh }
	isAnd := func(in asm.Instruction) bool { return in.OpCode.ALUOp() == asm.And }

	// 8-bit lookahead: byte load, no swap/shift/mask.
	eight := selectKeyShape{loadSize: asm.Byte, bigEndian: false, shift: 0, mask: 0, bits: 8}
	if got := eight.normalize(asm.R3); len(got) != 0 {
		t.Errorf("8-bit normalize emitted %d insns; want 0 (%v)", len(got), got)
	}

	// 24-bit lookahead: Word load → HostTo(BE) → RSh 8, no mask.
	twentyFour := selectKeyShape{loadSize: asm.Word, bigEndian: true, shift: 8, mask: 0, bits: 24}
	got := twentyFour.normalize(asm.R3)
	if c := countOp(got, isEnd); c != 1 {
		t.Errorf("24-bit normalize: byte-swap count = %d; want 1 (%v)", c, got)
	}
	if c := countOp(got, isRSh); c != 1 {
		t.Errorf("24-bit normalize: RSh count = %d; want 1 (%v)", c, got)
	}
	if c := countOp(got, isAnd); c != 0 {
		t.Errorf("24-bit normalize: And count = %d; want 0 (%v)", c, got)
	}

	// Sub-byte field key (e.g. a 4-bit nibble): shift + mask, no swap.
	field := selectKeyShape{loadSize: asm.Byte, bigEndian: false, shift: 2, mask: 0x0f, bits: 4}
	gotF := field.normalize(asm.R3)
	if c := countOp(gotF, isEnd); c != 0 {
		t.Errorf("field normalize: byte-swap count = %d; want 0", c)
	}
	if c := countOp(gotF, isRSh); c != 1 {
		t.Errorf("field normalize: RSh count = %d; want 1", c)
	}
	if c := countOp(gotF, isAnd); c != 1 {
		t.Errorf("field normalize: And count = %d; want 1", c)
	}
}
