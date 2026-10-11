package codegen

import (
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
)

// TestEmitScalarFieldLoadContract pins what the bracket and where
// emitters rely on from emitScalarFieldLoad, for every shape it reads (a
// primary field, a slice, a sub-byte field, a gated aux, a static entry
// and a walked entry): R10 is never touched, so bpf_loop callbacks can
// replay the read; the last instruction loads R3; every jump takes the
// site's fail label, or dslReject for the window bounds check
// emitFieldLoad owns; and the returned width matches the load.
func TestEmitScalarFieldLoadContract(t *testing.T) {
	cases := []struct {
		expr  string
		layer int
		bytes int
	}{
		{"eth/ipv4[ttl == 64]/tcp", 1, 1},
		{"eth/ipv4[src[24:32] == 5]/tcp", 1, 1},
		{"eth/ipv4[flags == 2]/tcp", 1, 1},
		{"eth/ipv4[rr.pointer == 4]/tcp", 1, 1},
		{"eth/ipv6/srv6[segments[1].addr[96:128] == 5]/tcp", 2, 4},
		{"eth/ipv6[exts[1].next_header == 6]/tcp", 1, 1},
		{"eth/ipv4/udp/gtp[exts[1].next_ext == 0]/ipv4/tcp", 3, 1},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			prog := parseResolveBundled(t, tc.expr)
			ref := prog.Layers[tc.layer].Predicates[0].Field
			site := predicateLoadSite(nil)
			site.fail = "fail"
			site.entryAddr = func(ref *ir.FieldRef) (asm.Instructions, error) {
				return emitStackEntryAddress(ref, r4Anchor(), indexBound{}, "fail")
			}
			insns, bytes, size, err := emitScalarFieldLoad(ref, site)
			if err != nil {
				t.Fatalf("emitScalarFieldLoad: %v", err)
			}
			if bytes != tc.bytes {
				t.Errorf("bytes = %d, want %d", bytes, tc.bytes)
			}
			for _, ins := range insns {
				if ins.Dst == asm.R10 || ins.Src == asm.R10 {
					t.Errorf("%v touches R10", ins)
				}
				if ins.OpCode.Class().IsJump() && ins.Reference() != "fail" && ins.Reference() != dslReject {
					t.Errorf("%v jumps to %q, want the site's fail label", ins, ins.Reference())
				}
			}
			last := insns[len(insns)-1]
			if last.OpCode.Class() != asm.LdXClass || last.Dst != asm.R3 || last.OpCode.Size() != size {
				t.Errorf("last insn %v, want a %v load into R3", last, size)
			}
		})
	}
}
