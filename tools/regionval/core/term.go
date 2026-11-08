package core

import (
	"fmt"
	"strings"
)

// Term is the symbolic value language.
// Terms are immutable; equality is structural (Equal).
type Term struct {
	Op   TermOp
	A, B *Term
	Args []*Term // TCat: bytes, least significant first
	C    uint64  // TConst value; TAdd/TLsh constant; TByte index
	N    int64   // TReg register; TStack offset; TFresh id
	F    int     // TFP/TStack frame (0 = window frame, 1 = wrapper frame)
	W    int     // TFresh width in bytes (1, 2, 4, 8)
}

type TermOp uint8

const (
	TConst  TermOp = iota // C
	TReg                  // entry register r_N of the window frame: sym(R_N)
	TFP                   // base of frame F (r10 at frame entry): FP
	TStack                // entry byte of frame F at offset N
	TFresh                // N-th unknown value of the path (helper result, havoc, other-memory load), W bytes
	TAdd                  // A + C (mod 2^64)
	TAnd                  // A & B
	TOr                   // A | B
	TLsh                  // A << C
	TZext32               // A & 0xffffffff
	TByte                 // byte C of A (little-endian)
	TCat                  // Args[0] | Args[1]<<8 | ... (zero-extended)
)

func Const(c uint64) *Term               { return &Term{Op: TConst, C: c} }
func Reg(k int) *Term                    { return &Term{Op: TReg, N: int64(k)} }
func FP(frame int) *Term                 { return &Term{Op: TFP, F: frame} }
func StackByte(frame int, o int64) *Term { return &Term{Op: TStack, F: frame, N: o} }
func Fresh(id, w int) *Term              { return &Term{Op: TFresh, N: int64(id), W: w} }
func And(a, b *Term) *Term               { return &Term{Op: TAnd, A: a, B: b} }
func Or(a, b *Term) *Term                { return &Term{Op: TOr, A: a, B: b} }
func Lsh(a *Term, c uint64) *Term        { return &Term{Op: TLsh, A: a, C: c} }
func Byte(a *Term, k int) *Term          { return &Term{Op: TByte, A: a, C: uint64(k)} }

// The only normalisations are N1-N4 below. Each is an identity under every
// valuation (TestNormalisationIdentities).

// AddC is a + c. N1: (FP + c1) + c2 -> FP + (c1+c2); r10 itself is FP + 0
// (FrameBase), so this is the only folding.
func AddC(a *Term, c uint64) *Term {
	if a.Op == TAdd && a.A.Op == TFP {
		return &Term{Op: TAdd, A: a.A, C: a.C + c}
	}
	return &Term{Op: TAdd, A: a, C: c}
}

// FrameBase is the value of r10 in frame f: FP + 0.
func FrameBase(f int) *Term { return &Term{Op: TAdd, A: FP(f), C: 0} }

// Zext32 is a & 0xffffffff. N3: zext32(zext32(t)) -> zext32(t). (N2,
// mov32 -> zext32, is the A32-2 row itself.)
func Zext32(a *Term) *Term {
	if a.Op == TZext32 {
		return a
	}
	return &Term{Op: TZext32, A: a}
}

// Cat assembles loaded bytes. N4: eight bytes that
// are bytes 0..7 of one term t, in order, are t.
func Cat(bs []*Term) *Term {
	if len(bs) == 8 && bs[0].Op == TByte {
		t := bs[0].A
		same := true
		for k, b := range bs {
			same = same && b.Op == TByte && b.C == uint64(k) && Equal(b.A, t)
		}
		if same {
			return t
		}
	}
	return &Term{Op: TCat, Args: bs}
}

// FrameOffset reports whether t is FP_f + c, the only address form the
// stepper stores through (C1).
func FrameOffset(t *Term) (frame int, off int64, ok bool) {
	if t.Op == TAdd && t.A.Op == TFP {
		return t.A.F, int64(t.C), true
	}
	return 0, 0, false
}

// Equal is syntactic identity. It is the only comparison the obligations use.
func Equal(a, b *Term) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil || a.Op != b.Op || a.C != b.C || a.N != b.N || a.F != b.F || a.W != b.W || len(a.Args) != len(b.Args) {
		return false
	}
	for i := range a.Args {
		if !Equal(a.Args[i], b.Args[i]) {
			return false
		}
	}
	return (a.A == nil) == (b.A == nil) && (a.B == nil) == (b.B == nil) &&
		(a.A == nil || Equal(a.A, b.A)) && (a.B == nil || Equal(a.B, b.B))
}

// Valuation gives every symbol a concrete value (ρ).
type Valuation struct {
	Regs  [10]uint64
	Base  [2]uint64
	Stack [2][]byte        // entry bytes of each frame, index offset+512
	Fresh func(int) uint64 // the path's unknowns, in order (oracle)
}

// Eval is the denotation ⟦t⟧ρ. It is not used by Check; it defines what a
// term means and is what the differential tests instantiate.
func Eval(t *Term, v *Valuation) uint64 {
	switch t.Op {
	case TConst:
		return t.C
	case TReg:
		return v.Regs[t.N]
	case TFP:
		return v.Base[t.F]
	case TStack:
		return uint64(v.Stack[t.F][t.N+512])
	case TFresh:
		return trunc(v.Fresh(int(t.N)), t.W)
	case TAdd:
		return Eval(t.A, v) + t.C
	case TAnd:
		return Eval(t.A, v) & Eval(t.B, v)
	case TOr:
		return Eval(t.A, v) | Eval(t.B, v)
	case TLsh:
		return Eval(t.A, v) << t.C
	case TZext32:
		return Eval(t.A, v) & 0xffffffff
	case TByte:
		return Eval(t.A, v) >> (8 * t.C) & 0xff
	case TCat:
		var x uint64
		for k, b := range t.Args {
			x |= Eval(b, v) << (8 * k)
		}
		return x
	}
	panic(fmt.Sprintf("Eval: term op %d", t.Op))
}

func trunc(x uint64, w int) uint64 {
	if w >= 8 {
		return x
	}
	return x & (1<<(8*w) - 1)
}

func (t *Term) String() string {
	switch t.Op {
	case TConst:
		return fmt.Sprintf("%#x", t.C)
	case TReg:
		return fmt.Sprintf("R%d", t.N)
	case TFP:
		return fmt.Sprintf("FP%d", t.F)
	case TStack:
		return fmt.Sprintf("S%d[%d]", t.F, t.N)
	case TFresh:
		return fmt.Sprintf("u%d/%d", t.N, t.W)
	case TAdd:
		return fmt.Sprintf("(%v+%d)", t.A, int64(t.C))
	case TAnd:
		return fmt.Sprintf("(%v&%v)", t.A, t.B)
	case TOr:
		return fmt.Sprintf("(%v|%v)", t.A, t.B)
	case TLsh:
		return fmt.Sprintf("(%v<<%d)", t.A, t.C)
	case TZext32:
		return fmt.Sprintf("zext32(%v)", t.A)
	case TByte:
		return fmt.Sprintf("%v.b%d", t.A, t.C)
	case TCat:
		s := make([]string, len(t.Args))
		for i, b := range t.Args {
			s[i] = b.String()
		}
		return "cat(" + strings.Join(s, ",") + ")"
	}
	return "?"
}
