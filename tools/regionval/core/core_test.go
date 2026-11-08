package core

import (
	"slices"
	"strings"
	"testing"
)

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.ReplaceAll(s, " ", "")
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for _, c := range s[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			case c >= 'a' && c <= 'f':
				v |= byte(c - 'a' + 10)
			default:
				t.Fatalf("bad hex %q", s)
			}
		}
		b[i] = v
	}
	return b
}

func TestDecodeFields(t *testing.T) {
	// r2 = r10; r2 += -4; r1 = ld_imm64 (src 1) 0x5_00000003; *(u64 *)(r10-8) = r1; exit
	b := hexBytes(t, "bfa2000000000000 07020000fcffffff 1811000003000000 0000000005000000 7b1af8ff00000000 9500000000000000")
	is, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	want := []Insn{
		{Op: 0xbf, Dst: 2, Src: 10, Raw: 0},
		{Op: 0x07, Dst: 2, Imm: -4, Raw: 1},
		{Op: 0x18, Dst: 1, Src: 1, Imm: 3, Imm64: 5<<32 | 3, Raw: 2},
		{Op: 0x7b, Dst: 10, Src: 1, Off: -8, Raw: 4},
		{Op: 0x95, Raw: 5},
	}
	if !slices.Equal(is, want) {
		t.Fatalf("got %v\nwant %v", is, want)
	}
	if is[2].Slots() != 2 || is[1].Slots() != 1 || is[1].Class() != ClassALU64 || is[3].Class() != ClassSTX {
		t.Fatal("slots/class")
	}
}

func TestDecodeErrors(t *testing.T) {
	for name, s := range map[string]string{
		"not a multiple of 8":         "bfa20000000000",
		"wide without second slot":    "1811000003000000",
		"wide second slot opcode":     "1811000003000000 0700000000000000",
		"wide second slot registers":  "1811000003000000 0010000000000000",
		"wide second slot offset":     "1811000003000000 0000010000000000",
		"wide then truncated at tail": "9500000000000000 1800000000000000",
	} {
		if _, err := Decode(hexBytes(t, s)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	if is, err := Decode(nil); err != nil || len(is) != 0 {
		t.Errorf("empty stream: %v %v", is, err)
	}
}

func TestTargets(t *testing.T) {
	cases := []struct {
		x            Insn
		jump         bool
		target, call int
	}{
		{Insn{Op: 0x05, Off: 2, Raw: 3}, true, 6, 0},
		{Insn{Op: 0x05, Off: -1, Raw: 3}, true, 3, 0},
		{Insn{Op: 0x06, Imm: 5, Off: 9, Raw: 1}, true, 7, 0}, // JMP32 JA uses imm
		{Insn{Op: 0x15, Off: 4, Raw: 0}, true, 5, 0},
		{Insn{Op: 0x76, Off: -2, Raw: 10}, true, 9, 0},
		{Insn{Op: OpCall, Src: 1, Imm: 2, Raw: 12}, false, 0, 15},
		{Insn{Op: OpExit, Raw: 4}, false, 0, 0},
		{Insn{Op: 0x18, Src: 4, Imm: -7, Raw: 9}, false, 0, 3},
	}
	for _, c := range cases {
		if c.x.IsJump() != c.jump {
			t.Errorf("%v IsJump = %v", c.x, !c.jump)
		}
		if c.jump && c.x.JumpTarget() != c.target {
			t.Errorf("%v JumpTarget = %d, want %d", c.x, c.x.JumpTarget(), c.target)
		}
		if (c.x.IsPseudoCall() || c.x.IsFuncRef()) && c.x.CallTarget() != c.call {
			t.Errorf("%v CallTarget = %d, want %d", c.x, c.x.CallTarget(), c.call)
		}
	}
}

// example builds a valid instance of row r.
func example(r Row) Insn {
	x := Insn{Op: r.Op, Dst: 1, Src: 2, Off: 4, Imm: 3}
	if r.CallSrc >= 0 {
		x.Src = uint8(r.CallSrc)
	}
	if r.Zero&zDst != 0 {
		x.Dst = 0
	}
	if r.Zero&zSrc != 0 {
		x.Src = 0
	}
	if r.Zero&zOff != 0 {
		x.Off = 0
	}
	if r.Zero&zImm != 0 {
		x.Imm = 0
	}
	return x
}

func TestAllowedRows(t *testing.T) {
	for _, r := range table {
		x := example(r)
		if got, why := Allowed(x); why != "" || got.ID != r.ID {
			t.Errorf("%s: %v refused: %s", r.ID, x, why)
		}
		for _, f := range []struct {
			bit uint8
			set func(*Insn)
		}{{zDst, func(x *Insn) { x.Dst = 3 }}, {zSrc, func(x *Insn) { x.Src = 3 }}, {zOff, func(x *Insn) { x.Off = 1 }}, {zImm, func(x *Insn) { x.Imm = 1 }}} {
			if r.Zero&f.bit == 0 {
				continue
			}
			y := x
			f.set(&y)
			if _, why := Allowed(y); why == "" {
				t.Errorf("%s: reserved field %d accepted: %v", r.ID, f.bit, y)
			}
		}
		if r.WritesDst {
			y := x
			y.Dst = 10
			if _, why := Allowed(y); why == "" {
				t.Errorf("%s: write to r10 accepted", r.ID)
			}
		}
		for _, reg := range []uint8{11, 15} {
			y, z := x, x
			y.Dst, z.Src = reg, reg
			if _, why := Allowed(y); why == "" {
				t.Errorf("%s: dst r%d accepted", r.ID, reg)
			}
			if _, why := Allowed(z); why == "" {
				t.Errorf("%s: src r%d accepted", r.ID, reg)
			}
		}
	}
	// r10 as a source is fine (`rx = r10`); shift ranges are strict.
	if _, why := Allowed(Insn{Op: 0xbf, Dst: 2, Src: 10}); why != "" {
		t.Error(why)
	}
	for _, x := range []Insn{{Op: 0x67, Dst: 1, Imm: 64}, {Op: 0x67, Dst: 1, Imm: -1}, {Op: 0x64, Dst: 1, Imm: 32}} {
		if _, why := Allowed(x); why == "" {
			t.Errorf("%v accepted", x)
		}
	}
	for _, x := range []Insn{{Op: 0x67, Dst: 1, Imm: 63}, {Op: 0x64, Dst: 1, Imm: 31}} {
		if _, why := Allowed(x); why != "" {
			t.Error(why)
		}
	}
}

// Every opcode and src value outside the table is refused, whatever the
// other fields hold (fail-closed default).
func TestAllowedOpcodeSweep(t *testing.T) {
	inTable := map[[2]int]bool{}
	for _, r := range table {
		inTable[[2]int{int(r.Op), int(r.CallSrc)}] = true
	}
	fields := []Insn{{}, {Dst: 1, Src: 2, Off: 4, Imm: 3}, {Dst: 0, Src: 1, Off: -1, Imm: -1}}
	accepted := map[uint8]bool{}
	for op := 0; op < 256; op++ {
		for _, f := range fields {
			for src := uint8(0); src <= 10; src++ {
				x := f
				x.Op, x.Src = uint8(op), src
				r, why := Allowed(x)
				if why != "" {
					continue
				}
				key := [2]int{op, -1}
				if op == OpCall {
					key[1] = int(src)
				}
				if !inTable[key] || r.Op != x.Op {
					t.Errorf("%v accepted by %s but not in the table", x, r.ID)
				}
				accepted[uint8(op)] = true
			}
		}
	}
	want := map[uint8]bool{}
	for _, r := range table {
		want[r.Op] = true
	}
	if len(accepted) != len(want) {
		t.Errorf("accepted %d opcodes, table has %d", len(accepted), len(want))
	}
	for _, op := range []uint8{0x62, 0x7a, 0xc3, 0xdb, 0xa4, 0xac, 0x8d, 0x0d, 0x06, 0x18, 0x20, 0x30, 0x81, 0xff} {
		if accepted[op] {
			t.Errorf("excluded opcode 0x%02x accepted", op)
		}
	}
	for _, x := range []Insn{{Op: OpCall, Src: 2, Imm: 5}, {Op: 0xbf, Dst: 1, Src: 2, Off: 8}, {Op: 0xbc, Dst: 1, Src: 2, Off: 16}} {
		if _, why := Allowed(x); why == "" {
			t.Errorf("%v (kfunc / movsx) accepted", x)
		}
	}
}

func TestCheckFailClosed(t *testing.T) {
	var zero Verdict
	if zero.Validated {
		t.Fatal("zero verdict is validated")
	}
	ok := Window{Kind: KindSite, Insns: []Insn{{Op: 0x7b, Dst: 10, Src: 2, Off: -24}, {Op: OpCall, Imm: 1}}, Center: 1, Floor: -8, HasFloor: true}
	if v := Check(ok); !v.Validated {
		t.Errorf("allowlisted window: %+v", v)
	}
	unknown := ok
	unknown.Kind = "site-unknown"
	if v := Check(unknown); v.Validated || v.Rule != "kind" {
		t.Errorf("unknown kind: %+v", v)
	}
	bad := ok
	bad.Insns = append(slices.Clone(ok.Insns), Insn{Op: 0xdb, Dst: 10, Off: -40})
	if v := Check(bad); v.Validated || !strings.Contains(v.Reason, "0xdb") {
		t.Errorf("atomic in window: %+v", v)
	}
	callee := ok
	callee.Callee = []Insn{{Op: 0x62, Dst: 10, Off: -8}}
	if v := Check(callee); v.Validated || !strings.Contains(v.Reason, "callee") {
		t.Errorf("store-imm in wrapper body: %+v", v)
	}
}
