package core

import (
	"fmt"
	"maps"
	"slices"
)

// Symbolic execution of one window. Explore enumerates
// every syntactic path; it never consults path conditions, so it explores
// a superset of the feasible paths. It implements only
// the semantics; the obligations are judged afterwards (oblig.go).

// Limits; exceeding one makes the window not validated.
const (
	MaxPaths = 1024
	MaxSteps = 4096
)

// Loc is a position: Depth 0 is the window, Depth 1 the inlined wrapper body.
type Loc struct{ Depth, PC int }

type EvKind uint8

const (
	EvStore  EvKind = iota // a store executed (Frame, Off, W, V the stored register's value)
	EvLoad                 // a load executed (Dst)
	EvHelper               // a helper call (Regs before, V the result, Imm the id)
	EvHook                 // a call to a hook
	EvCallW                // the call to the window's wrapper (Regs before)
	EvRet                  // exit of the wrapper body (Regs of the wrapper frame)
	EvExit                 // exit of a function-body window (Regs)
)

type Event struct {
	Kind  EvKind
	At    Loc
	Frame int
	Off   int64
	W     int
	Dst   uint8
	Imm   int32
	V     *Term
	Regs  [11]*Term
}

// Cond records a conditional branch on the path: Taken says which successor.
type Cond struct {
	T     *Term
	Op    uint8
	Imm   int32
	Taken bool
}

// Path is one completed path. Regs and Mem are the window frame at the end.
type Path struct {
	Locs   []Loc
	Conds  []Cond
	Events []Event
	Regs   [11]*Term
	Mem    map[int64]*Term // window-frame bytes written on the path
	Ref    map[int64]*Term // C3: what the original alone leaves in [f,0)
	Exit   bool            // ended by exit (function-body windows)
	Fresh  int             // unknowns introduced (oracle draws, in order)
}

// Fault is a refusal of the stepper: the window leaves the model. Rule names
// the obligation the refusal stands for.
type Fault struct{ Rule, Msg string }

func fault(rule, format string, a ...any) *Fault {
	return &Fault{Rule: rule, Msg: fmt.Sprintf(format, a...)}
}

type sframe struct {
	code []Insn
	hook map[int]bool
	pc   int
	r    [11]*Term
}

type sstate struct {
	fr  []sframe
	mem [2]map[int64]*Term
	ref map[int64]*Term
	p   Path
}

func (s *sstate) clone() *sstate {
	c := &sstate{fr: slices.Clone(s.fr), ref: maps.Clone(s.ref), p: s.p}
	for i := range s.mem {
		c.mem[i] = maps.Clone(s.mem[i])
	}
	c.p.Locs, c.p.Conds, c.p.Events = slices.Clone(s.p.Locs), slices.Clone(s.p.Conds), slices.Clone(s.p.Events)
	return c
}

// fresh introduces the next unknown of the path (the oracle order
// documented on interp.Input).
func (s *sstate) fresh(w int) *Term {
	t := Fresh(s.p.Fresh, w)
	s.p.Fresh++
	return t
}

// Explore returns every path of w from the entry state: r0-r9 = sym(R_k),
// r10 = FP+0, stack bytes = entry bytes.
func Explore(w Window) ([]Path, *Fault) {
	floor := int64(-512)
	if w.HasFloor {
		floor = int64(w.Floor)
	}
	s := &sstate{fr: []sframe{{code: w.Insns, hook: w.Hook}}, ref: map[int64]*Term{}}
	s.mem[0], s.mem[1] = map[int64]*Term{}, map[int64]*Term{}
	for k := 0; k < 10; k++ {
		s.fr[0].r[k] = Reg(k)
	}
	s.fr[0].r[10] = FrameBase(0)
	var out []Path
	work := []*sstate{s}
	for len(work) > 0 {
		s := work[len(work)-1]
		work = work[:len(work)-1]
		for {
			// Ending at pc == len(code) executes nothing: 4096 steps pass.
			if top := &s.fr[len(s.fr)-1]; len(s.p.Locs) >= MaxSteps && top.pc < len(top.code) { // rule:limit-steps
				return nil, fault("limit", "a path exceeds %d steps", MaxSteps)
			}
			done, fork, f := s.step(w, floor)
			if f != nil {
				return nil, f
			}
			if fork != nil {
				work = append(work, fork)
			}
			// +1 counts the running path, so the 1025th path is refused.
			if len(out)+len(work)+1 > MaxPaths { // rule:limit-paths
				return nil, fault("limit", "more than %d paths", MaxPaths)
			}
			if done {
				s.p.Regs, s.p.Mem, s.p.Ref = s.fr[0].r, s.mem[0], s.ref
				out = append(out, s.p)
				break
			}
		}
	}
	return out, nil
}

// width of a LDX/STX by its size bits (RFC §5.1 Table 9).
func width(op uint8) int { return [4]int{4, 2, 1, 8}[op>>3&3] }

// step executes one instruction of the top frame. It returns done when the
// path ends, and a forked state for the taken side of a conditional branch.
func (s *sstate) step(w Window, floor int64) (bool, *sstate, *Fault) {
	depth := len(s.fr) - 1
	fr := &s.fr[depth]
	n := len(fr.code)
	body := depth > 0 || w.Kind == KindHook
	if fr.pc == n {
		if body { // rule:C4-fall
			return false, nil, fault("C4", "depth %d: falls off the end of a function body", depth)
		}
		return true, nil, nil
	}
	x, at := fr.code[fr.pc], Loc{depth, fr.pc}
	s.p.Locs = append(s.p.Locs, at)
	r := &fr.r
	imm := uint64(int64(x.Imm)) // sext64(imm)
	jump := func(t int) *Fault {
		if t <= fr.pc { // rule:C4-fwd
			return fault("C4", "%v at %v: branch backward or onto itself", x, at)
		}
		if t > n || (body && t == n) { // rule:C4-land
			return fault("C4", "%v at %v: lands outside the window", x, at)
		}
		return nil
	}
	next := fr.pc + 1
	switch x.Op {
	case 0xb7: // A64-1
		r[x.Dst] = Const(imm)
	case 0xbf: // A64-2
		r[x.Dst] = r[x.Src]
	case 0x07: // A64-3
		r[x.Dst] = AddC(r[x.Dst], imm)
	case 0x57: // A64-4
		r[x.Dst] = And(r[x.Dst], Const(imm))
	case 0x5f: // A64-5
		r[x.Dst] = And(r[x.Dst], r[x.Src])
	case 0x47: // A64-6
		r[x.Dst] = Or(r[x.Dst], Const(imm))
	case 0x4f: // A64-7
		r[x.Dst] = Or(r[x.Dst], r[x.Src])
	case 0x67: // A64-8
		r[x.Dst] = Lsh(r[x.Dst], uint64(x.Imm))
	case 0xb4: // A32-1
		r[x.Dst] = Const(uint64(uint32(x.Imm)))
	case 0xbc: // A32-2
		r[x.Dst] = Zext32(r[x.Src])
	case 0x04: // A32-3
		r[x.Dst] = Zext32(AddC(r[x.Dst], imm))
	case 0x54: // A32-4
		r[x.Dst] = Zext32(And(r[x.Dst], Const(imm)))
	case 0x5c: // A32-5
		r[x.Dst] = Zext32(And(r[x.Dst], r[x.Src]))
	case 0x44: // A32-6
		r[x.Dst] = Zext32(Or(r[x.Dst], Const(imm)))
	case 0x4c: // A32-7
		r[x.Dst] = Zext32(Or(r[x.Dst], r[x.Src]))
	case 0x64: // A32-8
		r[x.Dst] = Zext32(Lsh(r[x.Dst], uint64(x.Imm)))
	case 0x61, 0x69, 0x71, 0x79: // LDX-1..4
		wd := width(x.Op)
		a := AddC(r[x.Src], uint64(int64(x.Off)))
		if f, o, ok := FrameOffset(a); ok {
			if f > depth || o < -512 || o+int64(wd) > 0 { // rule:model-load
				return false, nil, fault("model", "%v at %v: stack load outside a live frame", x, at)
			}
			bs := make([]*Term, wd)
			for k := range bs {
				if bs[k] = s.mem[f][o+int64(k)]; bs[k] == nil {
					bs[k] = StackByte(f, o+int64(k))
				}
			}
			r[x.Dst] = Cat(bs)
		} else {
			r[x.Dst] = s.fresh(wd) // other memory: a fresh value
		}
		s.p.Events = append(s.p.Events, Event{Kind: EvLoad, At: at, Dst: x.Dst})
	case 0x63, 0x6b, 0x73, 0x7b: // STX-1..4
		wd := width(x.Op)
		f, o, ok := FrameOffset(AddC(r[x.Dst], uint64(int64(x.Off))))
		v := r[x.Src]
		if !ok { // rule:C1-form
			return false, nil, fault("C1", "%v at %v: store address %v is not r10 + constant", x, at, r[x.Dst])
		}
		if f > depth || o < -512 || o+int64(wd) > 0 { // rule:C1-lo
			return false, nil, fault("C1", "%v at %v: store at FP%d%+d outside a live frame", x, at, f, o)
		}
		for k := 0; k < wd; k++ {
			s.mem[f][o+int64(k)] = Byte(r[x.Src], k)
		}
		s.p.Events = append(s.p.Events, Event{Kind: EvStore, At: at, Frame: f, Off: o, W: wd, V: v})
	case 0x05: // J-1
		if f := jump(next + int(x.Off)); f != nil {
			return false, nil, f
		}
		next += int(x.Off)
	case 0x15, 0x55, 0x76: // J-2..4: both successors
		t := next + int(x.Off)
		if f := jump(t); f != nil {
			return false, nil, f
		}
		c := Cond{T: r[x.Dst], Op: x.Op, Imm: x.Imm}
		fork := s.clone()
		fork.fr[depth].pc = t
		c.Taken = true
		fork.p.Conds = append(fork.p.Conds, c)
		c.Taken = false
		s.p.Conds = append(s.p.Conds, c)
		fr.pc = next
		return false, fork, nil
	case OpCall:
		ev := Event{At: at, Regs: *r, Imm: x.Imm}
		switch {
		case x.Src == 0: // C-1: r0 <- v, r1-r5 <- havoc, [f,0) of the window frame <- havoc
			ev.Kind, ev.V = EvHelper, s.fresh(8)
			r[0] = ev.V
			for k := 1; k <= 5; k++ {
				r[k] = s.fresh(8)
			}
			for o := floor; o < 0; o++ {
				b := s.fresh(1)
				s.mem[0][o], s.ref[o] = b, b
			}
		case depth == 0 && fr.pc == w.Center && w.Callee != nil: // C-2 wrapper: inline in frame 1
			ev.Kind = EvCallW
			s.p.Events = append(s.p.Events, ev)
			fr.pc = next
			callee := sframe{code: w.Callee, hook: w.CalleeHook}
			copy(callee.r[1:6], r[1:6])
			for _, k := range []int{0, 6, 7, 8, 9} {
				callee.r[k] = s.fresh(8)
			}
			callee.r[10] = FrameBase(1)
			s.fr = append(s.fr, callee)
			return false, nil, nil
		case fr.hook[fr.pc]: // rule:C5-target  C-2 hook: r0-r5 <- havoc; r6-r10 and every stack byte kept (trusted calling convention)
			ev.Kind = EvHook
			for k := 0; k <= 5; k++ {
				r[k] = s.fresh(8)
			}
		default:
			return false, nil, fault("C5", "%v at %v: call to a function that is neither a hook nor this window's wrapper", x, at)
		}
		s.p.Events = append(s.p.Events, ev)
	case OpExit: // E-1
		if depth == 1 { // return from the wrapper: r0 <- callee r0, r1-r5 <- havoc
			s.p.Events = append(s.p.Events, Event{Kind: EvRet, At: at, Regs: *r})
			r0 := r[0]
			s.fr = s.fr[:1]
			c := &s.fr[0].r
			c[0] = r0
			for k := 1; k <= 5; k++ {
				c[k] = s.fresh(8)
			}
			return false, nil, nil
		}
		if !body { // rule:C4-exit
			return false, nil, fault("C4", "%v at %v: exit outside a function body", x, at)
		}
		s.p.Events = append(s.p.Events, Event{Kind: EvExit, At: at, Regs: *r})
		s.p.Exit = true
		return true, nil, nil
	default:
		return false, nil, fault("C6", "%v at %v: no semantics", x, at)
	}
	fr.pc = next
	return false, nil, nil
}
