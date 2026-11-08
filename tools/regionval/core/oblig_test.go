package core

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

// One case per obligation rule (the `rule:<id>` tags). Each case starts from
// a window that is validated and breaks exactly the clause named by the
// tag; it must be refused with that rule's category and clause text.
// Weakening any tagged line makes at least one case fail.

func st(o int16, src uint8) Insn  { return Insn{Op: 0x7b, Dst: 10, Src: src, Off: o} }
func ld(d uint8, o int16) Insn    { return Insn{Op: 0x79, Dst: d, Src: 10, Off: o} }
func mv(d, s uint8) Insn          { return Insn{Op: 0xbf, Dst: d, Src: s} }
func mvi(d uint8, v int32) Insn   { return Insn{Op: 0xb7, Dst: d, Imm: v} }
func hc(id int32) Insn            { return Insn{Op: OpCall, Imm: id} }
func pc() Insn                    { return Insn{Op: OpCall, Src: 1, Imm: 7} }
func jeq(d uint8, off int16) Insn { return Insn{Op: 0x15, Dst: d, Off: off} }
func ex() Insn                    { return Insn{Op: OpExit} }

// siteW: prelude spill, helper, result spill, guard, hook call with
// arguments, restore (the HF layout of P2).
func siteW() Window {
	return Window{Kind: KindSite, Center: 1, Floor: -8, HasFloor: true, Hook: map[int]bool{6: true},
		Insns: []Insn{st(-24, 2), hc(1), st(-32, 0), jeq(0, 3), ld(1, -16), mv(4, 0), pc(), ld(0, -32)}}
}

// wrapW: WP loads ctx into r4, then the P8 wrapper template.
func wrapW() Window {
	return Window{Kind: KindWrap, Center: 1, Floor: -16, HasFloor: true, Insns: []Insn{ld(4, -24), pc()},
		Callee:     []Insn{mv(6, 4), mv(7, 2), hc(1), mv(8, 0), jeq(0, 5), mv(1, 6), {Op: 0xb4, Dst: 2, Imm: 12}, mv(3, 7), mv(4, 0), pc(), mv(0, 8), ex()},
		CalleeHook: map[int]bool{9: true}, HelperPC: 2, Helper: hc(1)}
}

func entryW() Window {
	return Window{Kind: KindEntry, Floor: -8, HasFloor: true, Insns: []Insn{st(-16, 1)}}
}
func cbW() Window {
	return Window{Kind: KindCallback, Floor: -16, HasFloor: true, Insns: []Insn{{Op: 0x79, Dst: 0, Src: 2, Off: -8}, st(-24, 0)}}
}
func passW() Window {
	return Window{Kind: KindPass, Floor: -16, HasFloor: true, Insns: []Insn{st(-24, 5)}}
}
func passLdW() Window {
	return Window{Kind: KindPassLoad, Floor: -16, HasFloor: true, Insns: []Insn{ld(5, -24)}, PassPrologue: []Insn{st(-24, 5)}}
}
func hookW() Window {
	return Window{Kind: KindHook, Insns: []Insn{{Op: 0x61, Dst: 0, Src: 1}, jeq(3, 1), {Op: 0x71, Dst: 0, Src: 3}, mvi(0, 0), ex()}}
}

// with returns a copy of w with Insns[i] (or Callee[i] for i < 0, as ^i)
// replaced.
func with(w Window, i int, x Insn) Window {
	w.Insns, w.Callee = slices.Clone(w.Insns), slices.Clone(w.Callee)
	w.Hook, w.CalleeHook = maps.Clone(w.Hook), maps.Clone(w.CalleeHook)
	if i >= 0 {
		w.Insns[i] = x
	} else {
		w.Callee[^i] = x
	}
	return w
}

func TestObligationsAccept(t *testing.T) {
	tail := siteW()
	tail.Kind, tail.Insns = KindTail, []Insn{st(-24, 3), hc(12), mv(1, 6), pc()}
	tail.Hook = map[int]bool{3: true}
	r4 := with(wrapW(), -1, mv(7, 2)) // the lookup does not read r4
	for name, w := range map[string]Window{"site": siteW(), "wrap": wrapW(), "entry": entryW(), "callback": cbW(),
		"pass": passW(), "passload": passLdW(), "hook": hookW(), "tail (no r0 obligation)": tail, "wrap r4": r4} {
		if v := Check(w); !v.Validated {
			t.Errorf("%s: %+v", name, v)
		}
	}
}

type ruleCase struct {
	tag, rule, clause string
	w                 Window
}

func ruleCases() []ruleCase {
	atomic := siteW()
	atomic.Insns = append(slices.Clone(atomic.Insns), Insn{Op: 0xdb, Dst: 10, Off: -40})
	noFloor := siteW()
	noFloor.HasFloor = false
	tail := siteW()
	tail.Kind = KindTail
	trailing := wrapW()
	trailing.Insns = append(slices.Clone(trailing.Insns), mv(1, 1))
	twoHelpers := wrapW()
	twoHelpers.Callee, twoHelpers.CalleeHook, twoHelpers.HelperPC = []Insn{hc(1), hc(1), ex()}, nil, 0
	notLookup := with(wrapW(), -3, hc(2))
	notLookup.Helper = hc(2)
	otherID := wrapW()
	otherID.Helper = hc(2) // the window names helper 2; W holds helper 1
	noStorePath := passW()
	noStorePath.Insns = []Insn{jeq(1, 1), st(-24, 5)}
	noCert := passLdW()
	noCert.PassPrologue = nil
	live := passLdW()
	live.PassLive = 1 << 5
	ws := func(w Window, xs ...Insn) Window { // prepend xs (shifting a P8 centre)
		w.Insns = append(xs, w.Insns...)
		if w.Kind == KindWrap {
			w.Center += len(xs)
		}
		return w
	}
	wpPointer := with(wrapW(), -2, Insn{Op: 0x7b, Dst: 4, Src: 6}) // WP passes FP-24 in r4; W stores through it
	wpPointer.Insns, wpPointer.Center = []Insn{mv(4, 10), {Op: 0x07, Dst: 4, Imm: -24}, pc()}, 2
	paths := entryW()
	for i := 0; i < 11; i++ {
		paths.Insns = append(paths.Insns, jeq(1, 0))
	}
	// A prelude branch lands on the window successor, over `call W`:
	// no helper and no return on that path (only P8-once sees it).
	skipCallW := wrapW()
	skipCallW.Insns, skipCallW.Center = []Insn{jeq(1, 2), ld(4, -24), pc()}, 2
	steps := entryW()
	for i := 0; i < MaxSteps; i++ {
		steps.Insns = append(steps.Insns, mv(1, 1))
	}
	extraHelper := entryW()
	extraHelper.Insns = append(slices.Clone(extraHelper.Insns), hc(1))
	twoHooks := with(siteW(), 4, pc())
	twoHooks.Hook[4] = true
	noHook := siteW()
	noHook.Hook = nil
	offCentre := siteW()
	offCentre.Center = 0
	fallOff := with(hookW(), 4, mvi(0, 0))
	return []ruleCase{
		{"kind", "kind", "unknown window kind", func() Window { w := siteW(); w.Kind = "site-x"; return w }()},
		{"C6", "C6", "not in the allowlist", atomic},
		{"C6-callee", "C6", "callee insn", with(wrapW(), -1, Insn{Op: 0x62, Dst: 10, Off: -8})},
		{"C1-floor", "C1", "no floor", noFloor},
		{"C1-form", "C1", "not r10 + constant", with(siteW(), 0, Insn{Op: 0x7b, Dst: 9, Src: 2, Off: -24})},
		{"C1-lo", "C1", "outside a live frame", with(siteW(), 0, st(-520, 2))},
		{"C1-hi", "C1", "floor -8", with(siteW(), 0, st(-12, 2))},
		{"C2", "C2", "r6", with(siteW(), 5, mv(6, 0))},
		{"C4-fwd", "C4", "backward", with(siteW(), 3, jeq(0, -1))},
		{"C4-land", "C4", "outside the window", with(siteW(), 3, jeq(0, 5))},
		{"C4-fall", "C4", "falls off", fallOff},
		{"C4-exit", "C4", "exit outside", with(siteW(), 4, ex())},
		{"C5-target", "C5", "neither a hook", noHook},
		{"C5-helper", "C5", "not the window's original call", extraHelper},
		{"C5-hooks", "C5", "2 hook calls", twoHooks},
		{"site-center", "site", "no centre", func() Window { w := siteW(); w.Center = -1; return w }()},
		{"site-helper", "site", "not this kind's helper", offCentre},
		{"site-helper", "site", "not this kind's helper", tail},
		{"site-once", "site", "0 times", with(siteW(), 0, Insn{Op: 0x05, Off: 1})},
		{"R15", "R15", "r2 at the helper call", with(siteW(), 0, mv(2, 10))},
		{"R0", "R0", "not the helper result", with(siteW(), 7, ld(0, -24))},
		{"P8-shape", "P8", "nothing after the call", trailing},
		{"P8-r10", "P8", "names r10", with(wrapW(), -6, mv(1, 10))},
		{"P8-store", "P8", "store at {1 1} in the wrapper body", wpPointer},
		{"P8-wpstore", "P8", "wrapper prelude", with(wrapW(), 0, st(-24, 1))},
		{"P8-wp", "P8", "prelude writes r3", with(wrapW(), 0, mv(3, 0))},
		{"P8-helper-other", "P8", "helper call other than the original", twoHelpers},
		{"P8-helper-id", "P8", "not the original helper call", otherID},
		{"P8-wp-writes", "P8", "prelude writes r1", ws(wrapW(), mv(4, 1), mvi(1, 0), mv(1, 4))},
		{"P8-ret", "P8", "wrapper returns", with(wrapW(), -11, mv(0, 7))},
		{"P8-once", "P8", "helper 0 times", skipCallW},
		{"R15-wrap", "R15", "r2 at the wrapper's helper", with(wrapW(), -2, mv(2, 6))},
		{"R15-wrap", "R15", "r4 at the wrapper's helper", notLookup},
		{"P1", "P1", "r1 at the prologue exit", func() Window { w := entryW(); w.Insns = append(w.Insns, mvi(1, 0)); return w }()},
		{"P1b-writes", "P1b", "writes r1", with(cbW(), 0, Insn{Op: 0x79, Dst: 1, Src: 2, Off: -8})},
		{"P1b-writes", "P1b", "writes r1", ws(cbW(), mv(0, 1), mvi(1, 0), mv(1, 0))},
		{"P9-store", "P9", "executes 0 stores", noStorePath},
		{"P9-writes", "P9", "writes r5", func() Window { w := passW(); w.Insns = append(w.Insns, mvi(5, 0), ld(5, -24)); return w }()},
		{"P9-cert", "P9", "no pass certificate", noCert},
		{"S10", "P9", "live at the callee entry", live},
		{"P9-load-writes", "P9", "writes r3", ws(passLdW(), mv(5, 3), mvi(3, 0), mv(3, 5))},
		{"P9-writes", "P9", "writes r0", func() Window { w := passW(); w.Insns = append(w.Insns, mvi(0, 1)); return w }()},
		{"P9-load", "P9", "stores 1 times", func() Window { w := passLdW(); w.Insns = append(w.Insns, st(-24, 1)); return w }()},
		{"P7-store", "P7", "store at", with(hookW(), 2, st(-8, 1))},
		{"P7-ld", "P7", "writes r6", with(hookW(), 2, Insn{Op: 0x71, Dst: 6, Src: 3})},
		{"P7-call", "P7", "call at", with(hookW(), 2, hc(5))},
		{"P7-r0", "P7", "exits with r0", with(hookW(), 3, mv(1, 1))},
		{"limit-paths", "limit", "paths", paths},
		{"limit-steps", "limit", "steps", steps},
		{"model-load", "model", "stack load outside", with(siteW(), 4, ld(1, -520))},
	}
}

func TestObligationRules(t *testing.T) {
	for _, c := range ruleCases() {
		t.Run(c.tag, func(t *testing.T) {
			v := Check(c.w)
			if v.Validated || v.Rule != c.rule || !strings.Contains(v.Reason, c.clause) {
				t.Errorf("rule:%s: got %+v, want rule %s with %q", c.tag, v, c.rule, c.clause)
			}
		})
	}
}

// C3 (no byte of [f,0) changed at exit) is implied by C1-hi in this model:
// every store passes C1-hi before C3 is checked, hook and wrapper calls
// write no stack, and a helper call changes [f,0) on both sides of the
// comparison. The exit comparison is a backstop that sees stores after the
// last helper call only (a store before it is hidden by the helper's
// havoc). The case below is what C3 alone catches once C1-hi is weakened
// (the two rules are tested together).
func TestC3BehindC1(t *testing.T) {
	w := Window{Kind: KindSite, Center: 0, Floor: -8, HasFloor: true, Insns: []Insn{hc(1), st(-12, 1), mv(1, 1)}}
	if v := Check(w); v.Validated || (v.Rule != "C1" && v.Rule != "C3") {
		t.Errorf("store over the floor after the helper: %+v", v)
	}
}

// Every opcode outside the allowlist, inserted into a validated window,
// makes it not validated.
func TestWindowOpcodeSweep(t *testing.T) {
	for op := 0; op < 256; op++ {
		for _, src := range []uint8{0, 1, 2} {
			x := Insn{Op: uint8(op), Dst: 1, Src: src}
			if _, why := Allowed(x); why == "" {
				continue
			}
			w := siteW()
			w.Insns = append(slices.Clone(w.Insns[:5]), append([]Insn{x}, w.Insns[5:]...)...)
			w.Insns[3].Off++ // keep the guard landing on the restore
			w.Hook = map[int]bool{7: true}
			if v := Check(w); v.Validated || v.Rule != "C6" {
				t.Errorf("opcode %#02x src %d: %+v", op, src, v)
			}
		}
	}
}
