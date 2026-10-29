package injectcheck

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf/asm"
)

type testFD int

func (f testFD) FD() int { return int(f) }
func TestAssociatedMapMutation(t *testing.T) {
	a := asm.LoadMapPtr(asm.R1, 0)
	if err := a.AssociateMap(testFD(100)); err != nil {
		t.Fatal(err)
	}
	b := asm.LoadMapPtr(asm.R1, 0)
	if err := b.AssociateMap(testFD(101)); err != nil {
		t.Fatal(err)
	}
	in := asm.Instructions{a, asm.Mov.Imm(asm.R0, 2), asm.Return()}
	out := asm.Instructions{b, in[1], in[2]}
	_, err := checkFixture(in, out, fixtureCertificate{Original: []int{0, 1, 2}})
	var x, y bytes.Buffer
	if e := in.Marshal(&x, binary.LittleEndian); e != nil {
		t.Fatal(e)
	}
	if e := out.Marshal(&y, binary.LittleEndian); e != nil {
		t.Fatal(e)
	}
	t.Logf("Check error=%v original FD=100 transformed FD=101 marshaled_equal=%t", err, bytes.Equal(x.Bytes(), y.Bytes()))
	assertKind(t, err, AssociatedMap)
}
func TestU32RegionMutations(t *testing.T) {
	in := asm.Instructions{asm.Mov.Reg(asm.R0, asm.R1), asm.LoadMem(asm.R2, asm.R0, 0, asm.Word), asm.Mov.Imm(asm.R1, 0), asm.Mov.Reg(asm.R0, asm.R2), asm.Return()}
	out := append(asm.Instructions(nil), in[:2]...)
	out = append(out, asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord), asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord), asm.Mov.Imm32(asm.R1, 42), asm.Call.Label("hook"), asm.LoadMem(asm.R0, asm.RFP, -8, asm.DWord), asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord))
	out = append(out, in[2:]...)
	out = append(out, asm.Mov.Reg32(asm.R0, asm.R1).WithSymbol("hook"), asm.Xor.Reg32(asm.R0, asm.R2), asm.Return())
	c := fixtureCertificate{Original: []int{0, 1, 8, 9, 10}, Hooks: []Span{{11, 14}}}
	if _, e := checkFixture(in, out, c); e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name string
		at   int
		ins  asm.Instruction
		kind Kind
	}{
		{"overlapping_R0_R2_spills", 3, asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord), U32Shape},
		{"R0_restore_zero_extends", 6, asm.LoadMem(asm.R0, asm.RFP, -8, asm.Word), U32Shape},
		{"R2_restore_from_R0_slot", 7, asm.LoadMem(asm.R2, asm.RFP, -8, asm.DWord), U32Shape},
		{"hook_reads_mutated_register", 12, asm.Xor.Reg32(asm.R0, asm.R3), HookShape},
		{"hook_call_targets_original", 5, asm.Call.Label("original"), CallTarget},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := append(asm.Instructions(nil), out...)
			bad[tc.at] = tc.ins
			bad[8] = bad[8].WithSymbol("original")
			_, e := checkFixture(in, bad, c)
			t.Logf("%v", e)
			assertKind(t, e, tc.kind)
		})
	}
}
