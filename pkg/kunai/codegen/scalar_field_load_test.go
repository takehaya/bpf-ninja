package codegen

import (
	"testing"

	"github.com/cilium/ebpf/asm"
)

// TestEmitScalarFieldLoadContract pins what the bracket and where
// emitters rely on from emitScalarFieldLoad at a bracket site (R4
// anchored, the one bpf_loop callbacks replay), for every shape it reads
// (a primary field, a slice, a sub-byte field, a gated aux, a static
// entry and a walked entry): R10 is never touched; the last instruction
// loads R3; every jump takes the site's fail label, or dslReject for the
// window bounds check emitFieldLoad owns, and a gated aux or a walked
// entry does reach the fail label; and the returned width matches the
// load.
func TestEmitScalarFieldLoadContract(t *testing.T) {
	cases := []struct {
		expr     string
		layer    int
		bytes    int
		failable bool
	}{
		{"eth/ipv4[ttl == 64]/tcp", 1, 1, false},
		{"eth/ipv4[src[24:32] == 5]/tcp", 1, 1, false},
		{"eth/ipv4[flags == 2]/tcp", 1, 1, false},
		{"eth/ipv4/udp/gtp[opt.next_ext == 0]/ipv4/tcp", 3, 1, true},
		{"eth/ipv6/srv6[segments[1].addr[96:128] == 5]/tcp", 2, 4, false},
		{"eth/ipv6[exts[1].next_header == 6]/tcp", 1, 1, true},
		{"eth/ipv4/udp/gtp[exts[1].next_ext == 0]/ipv4/tcp", 3, 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			prog := parseResolveBundled(t, tc.expr)
			ref := prog.Layers[tc.layer].Predicates[0].Field
			site := predicateLoadSite(nil)
			site.fail = "fail"
			insns, bytes, size, err := emitScalarFieldLoad(ref, site)
			if err != nil {
				t.Fatalf("emitScalarFieldLoad: %v", err)
			}
			if bytes != tc.bytes {
				t.Errorf("bytes = %d, want %d", bytes, tc.bytes)
			}
			reachesFail := false
			for _, ins := range insns {
				reachesFail = reachesFail || ins.Reference() == "fail"
				if ins.Dst == asm.R10 || ins.Src == asm.R10 {
					t.Errorf("%v touches R10", ins)
				}
				if ins.OpCode.Class().IsJump() && ins.Reference() != "fail" && ins.Reference() != dslReject {
					t.Errorf("%v jumps to %q, want the site's fail label", ins, ins.Reference())
				}
			}
			if reachesFail != tc.failable {
				t.Errorf("a jump to the fail label: %v, want %v", reachesFail, tc.failable)
			}
			last := insns[len(insns)-1]
			if last.OpCode.Class() != asm.LdXClass || last.Dst != asm.R3 || last.OpCode.Size() != size {
				t.Errorf("last insn %v, want a %v load into R3", last, size)
			}
		})
	}
}
