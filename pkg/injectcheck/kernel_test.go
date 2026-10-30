package injectcheck

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// Loads and TEST_RUNs a map-swap fixture without attaching or pinning.
func TestBpfAssociatedMapSwap(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	maps := make([]*ebpf.Map, 2)
	for i := range maps {
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Close() })
		if err := m.Put(uint32(0), uint32(2-i)); err != nil {
			t.Fatal(err)
		}
		maps[i] = m
	}
	x := asm.LoadMapPtr(asm.R1, 0)
	if err := x.AssociateMap(maps[0]); err != nil {
		t.Fatal(err)
	}
	in := asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord), x,
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "end"), asm.LoadMem(asm.R0, asm.R0, 0, asm.Word), asm.Return().WithSymbol("end")}
	out := append(asm.Instructions(nil), in...)
	if err := out[2].AssociateMap(maps[1]); err != nil {
		t.Fatal(err)
	}
	c := fixtureCertificate{LowestOffset: -8}
	for i := range in {
		c.Original = append(c.Original, i)
	}
	_, err := checkFixture(in, out, c)
	assertKind(t, err, AssociatedMap)
	if err == nil {
		t.Fatal("accepted associated map swap")
	} else {
		t.Logf("map-swap rejected: %v", err)
	}
	for i, is := range []asm.Instructions{in, out} {
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: is})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		ret, _, err := p.Test(make([]byte, 64))
		if err != nil || ret != uint32(2-i) {
			t.Fatalf("program %d: retval=%d error=%v", i, ret, err)
		}
		t.Logf("map-swap program=%d verifier=accepted TEST_RUN_retval=%d", i, ret)
	}
}

// Verifier pruning of the infeasible register read is the premise used by
// helper postlude checking, tested for lookup, delete and tail-call helpers.
func TestBpfHelperCallingConvention(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, helper := range []asm.BuiltinFunc{asm.FnMapLookupElem, asm.FnMapDeleteElem, asm.FnTailCall} {
		t.Run(helper.String(), func(t *testing.T) {
			tail := helper == asm.FnTailCall
			mapType := ebpf.Array
			if tail {
				mapType = ebpf.ProgramArray
			}
			m, err := ebpf.NewMap(&ebpf.MapSpec{Type: mapType, KeySize: 4, ValueSize: 4, MaxEntries: 1})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = m.Close() })
			in, out, c := callingConventionFixture(tail)
			if helper == asm.FnMapDeleteElem {
				_, base, _ := callingConventionFixture(false)
				post := append(clone(base[8:9]), base[10:15]...)
				in, out, c = replacePostlude(post)
				in[5] = helper.Call()
				out[c.Original[5]] = in[5]
			}
			if _, err := checkFixture(in, out, c); err != nil {
				t.Fatal(err)
			}
			for i, is := range []asm.Instructions{in, out} {
				if err := is.AssociateMap("m", m); err != nil {
					t.Fatal(err)
				}
				p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: is})
				if err != nil {
					t.Fatalf("program %d: %v", i, err)
				}
				t.Cleanup(func() { _ = p.Close() })
				ret, _, err := p.Test(make([]byte, 64))
				if err != nil || ret != 2 {
					t.Fatalf("program %d: retval=%d err=%v", i, ret, err)
				}
				t.Logf("program=%d verifier=accepted TEST_RUN_retval=%d", i, ret)
			}
		})
	}
}
