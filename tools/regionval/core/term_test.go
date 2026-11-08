package core

import (
	"math/rand/v2"
	"testing"
)

// Every normalisation N1-N4 is an identity, checked
// under random valuations; and N4 only fires for bytes 0..7 of one term in
// order.
func TestNormalisationIdentities(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x5eed_7a5b_0003, 0))
	for i := 0; i < 10000; i++ {
		v := &Valuation{Base: [2]uint64{rng.Uint64(), rng.Uint64()}, Fresh: func(n int) uint64 { return uint64(n) * 0x9e3779b97f4a7c15 }}
		for k := range v.Regs {
			v.Regs[k] = rng.Uint64()
		}
		c1, c2 := rng.Uint64(), rng.Uint64()
		if got := Eval(AddC(AddC(FrameBase(0), c1), c2), v); got != v.Base[0]+c1+c2 { // N1
			t.Fatalf("N1: %#x", got)
		}
		x := Or(Reg(rng.IntN(10)), Fresh(rng.IntN(5), 8))
		if Eval(Zext32(Zext32(x)), v) != Eval(x, v)&0xffffffff { // N3
			t.Fatal("N3")
		}
		bs := make([]*Term, 8)
		for k := range bs {
			bs[k] = Byte(x, k)
		}
		if got := Cat(bs); !Equal(got, x) || Eval(got, v) != Eval(x, v) { // N4
			t.Fatalf("N4: %v", got)
		}
		j := rng.IntN(8)
		bs[j] = Byte(x, (j+1+rng.IntN(7))%8) // one byte out of place
		if got := Cat(bs); got.Op != TCat {
			t.Fatalf("N4 fired on misordered bytes: %v", got)
		}
	}
}

// Two 4-byte stores of r1 read back as one 8-byte word are not r1
// (N4 must not fire): the entry prologue that does this changes
// r1.
func TestNormalisationMisorderedWord(t *testing.T) {
	w := Window{Kind: KindEntry, Floor: -8, HasFloor: true, Insns: []Insn{
		{Op: 0x63, Dst: 10, Src: 1, Off: -16}, {Op: 0x63, Dst: 10, Src: 1, Off: -12}, ld(1, -16)}}
	if v := Check(w); v.Validated || v.Rule != "P1" {
		t.Errorf("%+v", v)
	}
}
