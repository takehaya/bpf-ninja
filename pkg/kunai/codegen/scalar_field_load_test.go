package codegen

import (
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
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
			if len(insns) == 0 {
				t.Fatal("no instructions")
			}
			last := insns[len(insns)-1]
			if last.OpCode.Class() != asm.LdXClass || last.Dst != asm.R3 || last.OpCode.Size() != size {
				t.Errorf("last insn %v, want a %v load into R3", last, size)
			}
		})
	}
}

// TestEmitScalarFieldLoadAnchors pins which anchor each part of the read
// goes through: an aux's gating through the gate anchor, the field
// through the load anchor (a bracket predicate behind a write-back
// overlay gates off R4 but reads through the overlay slot), and a walked
// entry from the gate anchor with the site's fail label, as
// predicateLoadSite builds it.
func TestEmitScalarFieldLoadAnchors(t *testing.T) {
	readsSlot := func(insns asm.Instructions) bool {
		for _, ins := range insns {
			if ins.OpCode.Class() == asm.LdXClass && ins.Src == asm.R10 && ins.Offset == -240 {
				return true
			}
		}
		return false
	}
	gated := parseResolveBundled(t, "eth/ipv4/udp/gtp[opt.next_ext == 0]/ipv4/tcp").Layers[3].Predicates[0].Field
	primary := parseResolveBundled(t, "eth/ipv4[ttl == 64]/tcp").Layers[1].Predicates[0].Field
	walked := parseResolveBundled(t, "eth/ipv6[exts[1].next_header == 6]/tcp").Layers[1].Predicates[0].Field
	for _, tc := range []struct {
		name       string
		gate, load layerAnchor
		ref        *ir.FieldRef
		want       bool
	}{
		{"primary through the load slot", r4Anchor(), slotAnchor(-240), primary, true},
		{"primary ignores the gate slot", slotAnchor(-240), r4Anchor(), primary, false},
		{"gating through the gate slot", slotAnchor(-240), r4Anchor(), gated, true},
		{"walked entry from the gate slot", slotAnchor(-240), r4Anchor(), walked, true},
		{"walked entry ignores the load slot", r4Anchor(), slotAnchor(-240), walked, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := predicateLoadSite(nil)
			site.gate, site.load = tc.gate, tc.load
			insns, _, _, err := emitScalarFieldLoad(tc.ref, site)
			if err != nil {
				t.Fatalf("emitScalarFieldLoad: %v", err)
			}
			if got := readsSlot(insns); got != tc.want {
				t.Errorf("reads slot -240: %v, want %v", got, tc.want)
			}
		})
	}
	insns, _, _, err := emitScalarFieldLoad(walked, predicateLoadSite(nil))
	if err != nil {
		t.Fatalf("emitScalarFieldLoad: %v", err)
	}
	for _, ins := range insns {
		if ins.OpCode.Class().IsJump() && ins.Reference() != dslReject {
			t.Errorf("predicateLoadSite: %v jumps to %q, want %q", ins, ins.Reference(), dslReject)
		}
	}
}
