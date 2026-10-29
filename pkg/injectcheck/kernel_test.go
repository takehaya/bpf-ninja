package injectcheck

import (
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Opt-in: this is the review's nine-instruction reproducer, using load and
// TEST_RUN only. No host interface, attachment or pin is needed.
func TestAssociatedMapKernelRegression(t *testing.T) {
	if os.Getenv("BPF_NINJA_CHECK_MAP_KERNEL") == "" {
		t.Skip("set BPF_NINJA_CHECK_MAP_KERNEL=1 to load the map-swap reproducer")
	}
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
	c := Certificate{LowestOffset: -8}
	for i := range in {
		c.Original = append(c.Original, i)
	}
	if _, err := Check(in, out, c); err == nil {
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

// This opt-in test confirms that the branch-sensitive P2/P4 fixtures satisfy
// the verifier-validity premise used by TestHelperCallingConvention.
func TestHelperCallingConventionKernel(t *testing.T) {
	if os.Getenv("BPF_NINJA_CHECK_MAP_KERNEL") == "" {
		t.Skip("set BPF_NINJA_CHECK_MAP_KERNEL=1 to load calling-convention fixtures")
	}
	for _, tail := range []bool{false, true} {
		t.Run(fmt.Sprintf("tail=%t", tail), func(t *testing.T) {
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
			if _, err := Check(in, out, c); err != nil {
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
