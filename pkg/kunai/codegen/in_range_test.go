package codegen

import (
	"testing"

	"github.com/cilium/ebpf/asm"
)

// TestInListRangeHostOrder pins the byte-order rule of `in` lists with a
// range: a multi-byte field is byte-swapped once and compared in host
// order (JLT/JLE against the plain bounds), a sub-byte field is narrowed
// first, and a range starting at 0 emits no lower-bound compare.
func TestInListRangeHostOrder(t *testing.T) {
	// count returns the number of compares of R3 against the constant:
	// `op R3, imm` when it fits int32, else `LoadImm R5, c; op R3, R5`.
	// Bounds checks also use JLT/JLE, the constant pins the predicate's
	// own compare.
	count := func(insns asm.Instructions, op asm.JumpOp, c int64) int {
		n := 0
		for i, ins := range insns {
			if ins.OpCode.JumpOp() != op {
				continue
			}
			switch {
			case ins.OpCode.Source() == asm.ImmSource && ins.Constant == c:
				n++
			case ins.OpCode.Source() == asm.RegSource && ins.Src == asm.R5 && i > 0 &&
				insns[i-1].OpCode.IsDWordLoad() && insns[i-1].Dst == asm.R5 && insns[i-1].Constant == c:
				n++
			}
		}
		return n
	}
	for _, tc := range []struct {
		expr   string
		hostTo int
		lo, hi int64 // bounds of the range alternative, as the compare sees them
		jeq    []int64
	}{
		{"eth/ipv4/tcp[dport in [79..81]]", 1, 79, 81, nil},                               // 16-bit: swap once
		{"eth/ipv4/tcp[dport in [0..1023]]", 1, -1, 1023, nil},                            // lo = 0: no JLT
		{"eth/ipv4/tcp[seq in [1..100]]", 1, 1, 100, nil},                                 // 32-bit
		{"eth/ipv4[ttl in [1..5]]/tcp", 0, 1, 5, nil},                                     // 1 byte: nothing to swap
		{"eth/ipv4[version in [4..6]]/tcp", 0, 4, 6, nil},                                 // sub-byte: narrowed, host order
		{"eth/ipv4/tcp[dport in [80, 443, 8000..8080]]", 1, 8000, 8080, []int64{80, 443}}, // equality alternatives stay host order too
		{"eth/ipv4/tcp[seq in [1..2, 0x80000000]]", 1, 1, 2, []int64{0x80000000}},         // above int32: register compare
		{"eth/ipv4/tcp[seq in [0x80000000..0xFFFFFFFF]]", 1, 0x80000000, 0xFFFFFFFF, nil},
	} {
		out := compileBundled(t, tc.expr)
		hostTo := 0
		for _, ins := range out.Main {
			if ins.OpCode.Class() == asm.ALUClass && ins.OpCode.ALUOp() == asm.Swap {
				hostTo++
			}
		}
		if hostTo != tc.hostTo {
			t.Errorf("%s: %d byte swaps, want %d", tc.expr, hostTo, tc.hostTo)
		}
		if tc.lo >= 0 {
			if got := count(out.Main, asm.JLT, tc.lo); got != 1 {
				t.Errorf("%s: %d `JLT R3, %d`, want 1", tc.expr, got, tc.lo)
			}
		} else if got := count(out.Main, asm.JLT, 0); got != 0 {
			t.Errorf("%s: %d `JLT R3, 0`, want none (lo = 0 is always satisfied)", tc.expr, got)
		}
		if got := count(out.Main, asm.JLE, tc.hi); got != 1 {
			t.Errorf("%s: %d `JLE R3, %d`, want 1", tc.expr, got, tc.hi)
		}
		for _, v := range tc.jeq {
			if got := count(out.Main, asm.JEq, v); got != 1 {
				t.Errorf("%s: %d `JEq R3, %d`, want 1", tc.expr, got, v)
			}
		}
	}
}

// TestInListAddressAlternatives pins the shape of address alternatives in
// an `in` list: an IPv4 host joins the load-once compares (one JEq per
// address, byte-swapped like an integer), a CIDR masks a copy in R2, and
// an IPv6 list reloads the field per alternative with its constants in R2.
func TestInListAddressAlternatives(t *testing.T) {
	count := func(insns asm.Instructions, pred func(asm.Instruction) bool) int {
		n := 0
		for _, ins := range insns {
			if pred(ins) {
				n++
			}
		}
		return n
	}
	jeq := func(reg asm.Register, c int64) func(asm.Instruction) bool {
		return func(ins asm.Instruction) bool {
			return ins.OpCode.JumpOp() == asm.JEq && ins.OpCode.Source() == asm.ImmSource && ins.Dst == reg && ins.Constant == c
		}
	}
	// A 64-bit constant into R2; the parser machine's callback reference
	// (`LdImmDW R2, <cb>`) carries a symbol and is not one.
	ldR2 := func(ins asm.Instruction) bool {
		return ins.OpCode.Class() == asm.LdClass && ins.OpCode.Mode() == asm.ImmMode && ins.Dst == asm.R2 && ins.Reference() == ""
	}
	andR2 := func(ins asm.Instruction) bool { return ins.OpCode.ALUOp() == asm.And && ins.Dst == asm.R2 }

	v4 := compileBundled(t, "eth/ipv4[dst in [10.0.0.1, 10.0.0.0/24, 7]]/tcp").Main
	if got := count(v4, jeq(asm.R3, 0x0100000a)); got != 1 {
		t.Errorf("ipv4 host: %d `JEq R3, 0x0100000a`, want 1", got)
	}
	if got := count(v4, jeq(asm.R3, 0x07000000)); got != 1 {
		t.Errorf("integer 7 byte-swapped: %d `JEq R3, 0x07000000`, want 1", got)
	}
	if got := count(v4, andR2); got != 1 {
		t.Errorf("cidr: %d `And R2`, want 1", got)
	}
	if got := count(v4, jeq(asm.R2, 0x0000000a)); got != 1 {
		t.Errorf("cidr network LE: %d `JEq R2, 0x0a`, want 1", got)
	}

	v6 := compileBundled(t, "eth/ipv6[dst in [fc00::1, fc00::2, fc00::/32]]/tcp").Main
	// Two hosts need two DWord constants each, the /32 one masked half:
	// mask and network, six 64-bit immediates into R2 in total.
	if got := count(v6, ldR2); got != 6 {
		t.Errorf("ipv6 list: %d `LdImmDW R2`, want 6", got)
	}
	loads := count(v6, func(ins asm.Instruction) bool {
		return ins.OpCode.Class() == asm.LdXClass && ins.OpCode.Size() == asm.DWord && ins.Offset < 0 && ins.Src == asm.R3
	})
	if loads != 5 {
		t.Errorf("ipv6 list: %d bounded DWord loads, want 5 (two per host, one for the masked half)", loads)
	}
}
