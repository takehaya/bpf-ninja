package codegen

import (
	"testing"

	"github.com/cilium/ebpf/asm"
)

// TestPushCountedStackGuards pins the push-count slot for stacks the
// parser machine pushes onto without a header-derived count (ipv6.exts,
// gtp.exts; spec D-031): the layer zero-inits one slot, the inline first
// push and the self-loop callback each add one to it, and every
// unrolled any/all iteration (and a static index) is guarded against
// it — once, since the rebound iterator carries no guard of its own.
func TestPushCountedStackGuards(t *testing.T) {
	count := func(insns asm.Instructions, match func(asm.Instruction) bool) int {
		n := 0
		for _, ins := range insns {
			if match(ins) {
				n++
			}
		}
		return n
	}
	// A count guard is `R3 = *(count slot); JLE R3, idx`.
	guards := func(insns asm.Instructions) int {
		n := 0
		for i := 0; i+1 < len(insns); i++ {
			ld, jle := insns[i], insns[i+1]
			if ld.OpCode == asm.LoadMem(asm.R3, asm.R10, 0, asm.DWord).OpCode && ld.Dst == asm.R3 && ld.Src == asm.R10 &&
				jle.OpCode == asm.JLE.Imm(asm.R3, 0, "").OpCode && jle.Dst == asm.R3 {
				n++
			}
		}
		return n
	}
	// A push increment is `reg = *(slot); reg += 1; *(slot) = reg`.
	increments := func(insns asm.Instructions, reg asm.Register) int {
		n := 0
		for i := 0; i+2 < len(insns); i++ {
			ld, add, st := insns[i], insns[i+1], insns[i+2]
			if ld.OpCode == asm.LoadMem(reg, asm.R10, 0, asm.DWord).OpCode && ld.Dst == reg &&
				add.OpCode == asm.Add.Imm(reg, 1).OpCode && add.Dst == reg && add.Constant == 1 &&
				st.OpCode == asm.StoreMem(asm.R10, 0, reg, asm.DWord).OpCode && st.Src == reg &&
				st.Dst == ld.Src && st.Offset == ld.Offset {
				n++
			}
		}
		return n
	}

	// ipv6 pushes at most 1 + IPV6_MAX_DEPTH (4) entries, so the unroll
	// stops at 5 of the declared capacity 8.
	all := compileBundled(t, "eth/ipv6/tcp where all(ipv6.exts.next_header != 1)")
	if got := guards(all.Main); got != 5 {
		t.Errorf("all(): %d count guards in main, want one per possible entry (5)", got)
	}
	if got := increments(all.Main, asm.R3); got != 1 {
		t.Errorf("all(): %d inline push increments, want 1", got)
	}
	if got := increments(all.Callbacks, asm.R0); got != 1 {
		t.Errorf("all(): %d callback push increments, want 1", got)
	}
	if got := countFnLoop(all.Main); got != 1 {
		t.Errorf("all(): %d bpf_loop calls, want 1 (the ext walk; the quantifier stays unrolled)", got)
	}

	static := compileBundled(t, "eth/ipv6/tcp where ipv6.exts[1].next_header == 6")
	if got := guards(static.Main); got != 1 {
		t.Errorf("static index: %d count guards, want 1", got)
	}

	// ipv6 evaluates bracket predicates after the walk (write-back), so a
	// bracket index is guarded the same way; gtp evaluates them before the
	// walk and refuses the shape (compile_test.go).
	bracket := compileBundled(t, "eth/ipv6[exts[1].next_header == 6]/tcp")
	if got := guards(bracket.Main); got != 1 {
		t.Errorf("bracket index: %d count guards, want 1", got)
	}

	// A dynamic index (fixed-size entries: gtp) is bounded by the count
	// too: `JGE idx, count`.
	dynamic := compileBundled(t, "eth/ipv4/udp/gtp/ipv4/tcp where gtp.exts[gtp.msg_type].next_ext == 6")
	if got := count(dynamic.Main, func(ins asm.Instruction) bool {
		return ins.OpCode == asm.JGE.Reg(asm.R3, asm.R2, "").OpCode && ins.Dst == asm.R3 && ins.Src == asm.R2
	}); got != 1 {
		t.Errorf("dynamic index: %d count bounds, want 1", got)
	}

	// gtp.exts: the first push happens in a non-entry state (parse_opt →
	// parse_ext), so the inline increment sits past the entry state. Its
	// push bound (1 + GTP_MAX_DEPTH 8) exceeds the capacity 8.
	gtp := compileBundled(t, "eth/ipv4/udp/gtp/ipv4/tcp where all(gtp.exts.next_ext != 1)")
	if got := guards(gtp.Main); got != 8 {
		t.Errorf("gtp all(): %d count guards, want 8", got)
	}

	// ipv6 ext entries are variable-length: a static index walks the
	// entries before it (one bounded length-byte load per entry), and a
	// dynamic index into such a stack is refused.
	walked := compileBundled(t, "eth/ipv6/tcp where ipv6.exts[2].next_header == 6")
	if got := count(walked.Main, func(ins asm.Instruction) bool {
		return ins.OpCode == asm.LoadMem(asm.R2, asm.R0, 0, asm.Byte).OpCode && ins.Dst == asm.R2
	}); got != 2 {
		t.Errorf("exts[2]: %d length-byte loads, want 2", got)
	}
	if got := increments(gtp.Main, asm.R3); got != 1 {
		t.Errorf("gtp all(): %d inline push increments, want 1", got)
	}
	if got := increments(gtp.Callbacks, asm.R0); got != 1 {
		t.Errorf("gtp all(): %d callback push increments, want 1", got)
	}

	// Without a stack reference nothing is demanded: no slot, no increment.
	plain := compileBundled(t, "eth/ipv6/tcp where tcp.dport == 80")
	if got := increments(plain.Main, asm.R3) + increments(plain.Callbacks, asm.R0); got != 0 {
		t.Errorf("no stack reference: %d push increments, want 0", got)
	}
}
