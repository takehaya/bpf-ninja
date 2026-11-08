package core

import "slices"

// Obligations (README.md, Obligations). validated is the only place that
// returns a validated verdict; every rule is one `if` tagged `rule:<id>`.

const tailCall = 12 // BPF_FUNC_tail_call

// lookups do not read r4 (P8 wrappers hold one of them).
func isLookup(id int32) bool { return id == 1 || id == 195 }

func regsEqual(r [11]*Term, ks ...int) (int, bool) {
	for _, k := range ks {
		if !Equal(r[k], Reg(k)) {
			return k, false
		}
	}
	return 0, true
}

var (
	kinds    = []string{KindSite, KindTail, KindWrap, KindEntry, KindCallback, KindPass, KindPassLoad, KindHook}
	r1to5    = []int{1, 2, 3, 4, 5}
	r6to9    = []int{6, 7, 8, 9}
	r0to9    = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	wpKept   = []int{0, 1, 2, 3, 5, 6, 7, 8, 9}
	wrapArgs = []int{1, 2, 3, 5}
)

// Writes is the set of registers x may write (rows A64, A32,
// LDX: dst; C-1/C-2: a call writes r0-r5).
func Writes(x Insn) uint16 {
	switch c := x.Class(); {
	case c == ClassALU || c == ClassALU64 || c == ClassLDX || x.Op == OpLdImm64:
		return bit(x.Dst)
	case x.Op == OpCall:
		return 0x3f
	}
	return 0
}

func lowest(m uint16) int {
	for k := 0; k < 16; k++ {
		if m&(1<<k) != 0 {
			return k
		}
	}
	return -1
}

// SpillSource is r_G of a pass prologue: the source of its only
// instruction of class STX, which must be `*(u64 *)(r10 + o) = r_G` with
// r_G one of r1-r5. 0 means no certificate.
func SpillSource(pro []Insn) int {
	src := 0
	for _, x := range pro {
		if x.Class() == ClassSTX {
			if src != 0 || x.Op != 0x7b || x.Dst != 10 || x.Src < 1 || x.Src > 5 {
				return 0
			}
			src = int(x.Src)
		}
	}
	return src
}

func validated(w Window, paths []Path) Verdict {
	site := w.Kind == KindSite || w.Kind == KindTail
	wrap := w.Kind == KindWrap
	hook := w.Kind == KindHook
	if !slices.Contains(kinds, w.Kind) { // rule:kind
		return notValidated("kind", "unknown window kind %q", w.Kind)
	}
	if !hook && !w.HasFloor { // rule:C1-floor
		return notValidated("C1", "no floor for the window's function")
	}
	if (site || wrap) && (w.Center < 0 || w.Center >= len(w.Insns)) { // rule:site-center
		return notValidated("site", "no centre")
	}
	if site && (!w.Insns[w.Center].IsHelperCall() || (w.Kind == KindTail) != (w.Insns[w.Center].Imm == tailCall)) { // rule:site-helper
		return notValidated("site", "centre %v is not this kind's helper call", w.Insns[w.Center])
	}
	if wrap && (w.Center != len(w.Insns)-1 || !w.Insns[w.Center].IsPseudoCall() || w.Callee == nil) { // rule:P8-shape
		return notValidated("P8", "wrapper site is not WP·call W with nothing after the call")
	}
	if wrap {
		if w.HelperPC < 0 || w.HelperPC >= len(w.Callee) || !w.Helper.IsHelperCall() || !w.Callee[w.HelperPC].Same(w.Helper) { // rule:P8-helper-id
			return notValidated("P8", "wrapper insn %d is not the original helper call %v", w.HelperPC, w.Helper)
		}
		for i, x := range w.Callee {
			if x.Op != OpCall && (x.Dst == 10 || x.Src == 10) { // rule:P8-r10
				return notValidated("P8", "wrapper insn %d %v names r10", i, x)
			}
			if x.IsHelperCall() && i != w.HelperPC { // rule:P8-helper-other
				return notValidated("P8", "wrapper insn %d %v is a helper call other than the original", i, x)
			}
		}
	}
	// P9: one certificate ties the pass load's destination and the callee
	// prologue's spill source to r_G, and r_G is dead at the callee entry.
	rG := 0
	if w.Kind == KindPass || w.Kind == KindPassLoad {
		pro := w.PassPrologue
		if w.Kind == KindPass {
			pro = w.Insns
		}
		if rG = SpillSource(pro); rG == 0 { // rule:P9-cert
			return notValidated("P9", "no pass certificate: the callee's pass prologue does not spill exactly one of r1-r5")
		}
		// S10 only where r_G is written: a pass prologue writes no register
		// (P9-writes), and r_G may be a live argument that
		// already holds ctx (no pass load before such calls).
		if w.Kind == KindPassLoad && w.PassLive&bit(uint8(rG)) != 0 { // rule:S10
			return notValidated("P9", "r_G = r%d is live at the callee entry", rG)
		}
	}
	f := int64(w.Floor)
	for _, p := range paths {
		var helper *Event
		helpers, hooks, stores := 0, 0, 0
		for i := range p.Events {
			e := &p.Events[i]
			switch e.Kind {
			case EvStore:
				stores++
				switch {
				case hook: // rule:P7-store
					return notValidated("P7", "store at %v in a hook body", e.At)
				case wrap && e.At.Depth == 1: // rule:P8-store
					return notValidated("P8", "store at %v in the wrapper body", e.At)
				case wrap: // rule:P8-wpstore
					return notValidated("P8", "store at %v in the wrapper prelude", e.At)
				case e.Off+int64(e.W) > f: // rule:C1-hi
					return notValidated("C1", "store at %v writes [%d,%d), floor %d", e.At, e.Off, e.Off+int64(e.W), f)
				}
			case EvLoad:
				if hook && e.Dst > 5 { // rule:P7-ld
					return notValidated("P7", "load at %v writes r%d", e.At, e.Dst)
				}
			case EvHelper, EvHook, EvCallW:
				if hook { // rule:P7-call
					return notValidated("P7", "call at %v in a hook body", e.At)
				}
				if e.Kind == EvHook {
					hooks++
				}
				if e.Kind == EvCallW { // WP writes only r4
					if k, ok := regsEqual(e.Regs, wpKept...); !ok { // rule:P8-wp
						return notValidated("P8", "wrapper prelude writes r%d", k)
					}
				}
				if e.Kind != EvHelper {
					break
				}
				helpers++
				helper = e
				original := (site && e.At == Loc{0, w.Center}) || (wrap && e.At == Loc{1, w.HelperPC})
				if !original { // rule:C5-helper
					return notValidated("C5", "helper call at %v is not the window's original call", e.At)
				}
			case EvRet:
				if helper == nil || !Equal(e.Regs[0], helper.V) { // rule:P8-ret
					return notValidated("P8", "wrapper returns r0 = %v, not the helper result", e.Regs[0])
				}
			case EvExit:
				if !Equal(e.Regs[0], Const(0)) { // rule:P7-r0
					return notValidated("P7", "hook exits with r0 = %v", e.Regs[0])
				}
			}
		}
		if hooks > 1 { // rule:C5-hooks
			return notValidated("C5", "%d hook calls on one path", hooks)
		}
		if site && helpers != 1 { // rule:site-once
			return notValidated("site", "a path executes the original call %d times", helpers)
		}
		// Also the only check for a prelude branch over `call W` (no EvRet).
		if wrap && helpers != 1 { // rule:P8-once
			return notValidated("P8", "a path executes the wrapper's helper %d times", helpers)
		}
		if site {
			if k, ok := regsEqual(helper.Regs, r1to5...); !ok { // rule:R15
				return notValidated("R15", "r%d at the helper call is %v, not its entry value", k, helper.Regs[k])
			}
		}
		if wrap {
			args := wrapArgs
			if !isLookup(helper.Imm) {
				args = r1to5
			}
			if k, ok := regsEqual(helper.Regs, args...); !ok { // rule:R15-wrap
				return notValidated("R15", "r%d at the wrapper's helper call is %v, not the site's entry value", k, helper.Regs[k])
			}
		}
		// Write set: registers written by executed window-frame
		// instructions (for P8 only the prelude, before `call W`).
		var wset uint16
		for _, at := range p.Locs {
			if prelude := !wrap || at.PC < w.Center; at.Depth == 0 && prelude {
				wset |= Writes(w.Insns[at.PC])
			}
		}
		if wrap && wset&^bit(4) != 0 { // rule:P8-wp-writes
			return notValidated("P8", "wrapper prelude writes r%d", lowest(wset&^bit(4)))
		}
		end := p.Regs
		switch w.Kind {
		case KindSite, KindWrap:
			if !Equal(end[0], helper.V) { // rule:R0
				return notValidated("R0", "r0 at the window exit is %v, not the helper result %v", end[0], helper.V)
			}
		case KindEntry:
			if k, ok := regsEqual(end, 1); !ok { // rule:P1
				return notValidated("P1", "r%d at the prologue exit is %v", k, end[k])
			}
		case KindCallback:
			// Covers the exit values r1-r9: a register no
			// executed instruction writes keeps its entry value.
			if wset&^1 != 0 { // rule:P1b-writes
				return notValidated("P1b", "callback prologue writes r%d", lowest(wset&^1))
			}
		case KindPass:
			if stores != 1 { // rule:P9-store
				return notValidated("P9", "pass prologue executes %d stores", stores)
			}
			if wset != 0 { // rule:P9-writes
				return notValidated("P9", "pass prologue writes r%d", lowest(wset))
			}
		case KindPassLoad:
			changed := slices.DeleteFunc(slices.Clone(r0to9), func(k int) bool { return k == rG || Equal(end[k], Reg(k)) })
			if stores != 0 || len(changed) > 0 { // rule:P9-load
				return notValidated("P9", "pass load changes r%v (r_G = r%d) and stores %d times", changed, rG, stores)
			}
			if wset&^bit(uint8(rG)) != 0 { // rule:P9-load-writes
				return notValidated("P9", "pass load writes r%d, not only r_G = r%d", lowest(wset&^bit(uint8(rG))), rG)
			}
		}
		k, ok := regsEqual(end, r6to9...)
		if !ok || !Equal(end[10], FrameBase(0)) { // rule:C2
			if ok {
				k = 10
			}
			return notValidated("C2", "r%d at the window exit differs from its entry value", k)
		}
		if !hook {
			for o := f; o < 0; o++ {
				want := p.Ref[o]
				if want == nil {
					want = StackByte(0, o)
				}
				got := p.Mem[o]
				if got == nil {
					got = StackByte(0, o)
				}
				if !Equal(got, want) { // rule:C3
					return notValidated("C3", "stack byte %d at the window exit is %v", o, got)
				}
			}
		}
	}
	// RB, record binding: checked once every preservation obligation holds,
	// since it is about what a hook records, not about the target.
	for _, p := range paths {
		var helper *Event
		for i := range p.Events {
			e := &p.Events[i]
			if e.Kind == EvHelper {
				helper = e
			}
			b, ok := w.Bind[e.At.PC]
			if e.Kind != EvHook || !ok || (e.At.Depth == 1) != wrap {
				continue
			}
			switch {
			case helper == nil: // rule:RB-order
				return notValidated("RB", "hook call at %v before the helper call", e.At)
			case b.Key != 0 && !Equal(e.Regs[b.Key], helper.Regs[2]): // rule:RB-key
				return notValidated("RB", "hook call at %v: key argument r%d is %v, not the helper's key %v", e.At, b.Key, e.Regs[b.Key], helper.Regs[2])
			case b.Value != 0 && !b.Copy && !Equal(e.Regs[b.Value], helper.V): // rule:RB-value
				return notValidated("RB", "hook call at %v: value argument r%d is %v, not the helper's result %v", e.At, b.Value, e.Regs[b.Value], helper.V)
			case b.Copy && !Equal(e.Regs[b.Value], AddC(FrameBase(0), uint64(int64(b.Off)))): // rule:RB-copy
				return notValidated("RB", "hook call at %v: value argument r%d is %v, not the copy at r10%+d", e.At, b.Value, e.Regs[b.Value], b.Off)
			case b.Copy && !Equal(e.Regs[0], helper.V): // rule:RB-copy-r0
				return notValidated("RB", "hook call at %v: r0 is %v, not the helper's result %v the copy reads", e.At, e.Regs[0], helper.V)
			}
		}
	}
	return Verdict{Validated: true, Paths: len(paths)}
}
