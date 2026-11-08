package regionval

// Regression tests for faults the obligations once let through: a wrapper
// that is not the original call, a pass load into the wrong register, and
// write sets checked only by exit values. Each test also runs the reference
// interpreter to show that the planted fault changes behaviour.

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/tools/regionval/core"
	"github.com/takehaya/bpf-ninja/tools/regionval/interp"
)

func wantRefused(t *testing.T, r Result, rule, clause string) {
	t.Logf("refusal: %+v", r.Windows)
	t.Helper()
	if r.Validated {
		t.Fatalf("load validated: %+v", r)
	}
	if !r.Structure.OK {
		t.Fatalf("structure failed (%+v); the window obligation must refuse it", r.Structure)
	}
	for _, w := range r.Windows {
		if !w.Validated {
			if w.Rule != rule || !strings.Contains(w.Reason, clause) {
				t.Fatalf("refused by %q (%s), want rule %s with %q", w.Rule, w.Reason, rule, clause)
			}
			return
		}
	}
	t.Fatalf("no window refused: %+v", r)
}

func wantValidated(t *testing.T, r Result) {
	t.Helper()
	if !r.Validated || !r.Structure.OK {
		t.Fatalf("control not validated: %+v", r)
	}
}

// Finding 1. The wrapper holds the original helper 5 once, at a callee pc no
// path reaches; one path calls helper 7 instead.
func TestWrapperIdentity(t *testing.T) {
	p := pair{
		o:     []a{movi(1, 1).begins("main"), helper(5), exit()},
		t:     []a{movi(1, 1).begins("main"), call("w"), exit(), jeq(1, "original").begins("w"), helper(7), exit(), helper(5).at("original"), exit()},
		kappa: []int{0, 1, 2}, floor: 0,
	}
	c := p.capture(t)
	wantRefused(t, runFile(t, c), "P8", "helper")

	// Evidence: on r1 = 1 the reference interpreter executes helper 7.
	l, err := Analyze(c)
	if err != nil {
		t.Fatal(err)
	}
	w := l.CoreWindow(l.Windows[0])
	var in interp.Input
	in.Regs[1] = 1
	in.Oracle = func(int) uint64 { return 0 }
	out, err := interp.Run(w, in)
	if err != nil {
		t.Fatal(err)
	}
	called := int32(-1)
	for _, loc := range out.Locs {
		if loc.Depth == 1 && w.Callee[loc.PC].IsHelperCall() {
			called = w.Callee[loc.PC].Imm
		}
	}
	if called != 7 {
		t.Fatalf("reference interpreter called helper %d, want 7", called)
	}

	// Control: the same wrapper without the branch and the foreign helper.
	good := pair{
		o:     p.o,
		t:     []a{movi(1, 1).begins("main"), call("w"), exit(), helper(5).begins("w"), exit()},
		kappa: []int{0, 1, 2}, floor: 0,
	}
	wantValidated(t, runFile(t, good.capture(t)))
}

// Finding 1, core level: the helper the window names must be the one each
// path executes, and no other helper call may appear in the wrapper body,
// reachable or not.
func TestWrapperHelperCore(t *testing.T) {
	base := core.Window{Kind: core.KindWrap, Center: 0, Floor: 0, HasFloor: true,
		Insns:  []core.Insn{{Op: core.OpCall, Src: 1, Imm: 1}},
		Callee: []core.Insn{{Op: core.OpCall, Imm: 5}, {Op: core.OpExit}}, HelperPC: 0, Helper: core.Insn{Op: core.OpCall, Imm: 5}}
	if v := core.Check(base); !v.Validated {
		t.Fatalf("control: %+v", v)
	}
	wrongID := base
	wrongID.Helper = core.Insn{Op: core.OpCall, Imm: 7}
	unreachable := base
	unreachable.Callee = []core.Insn{{Op: core.OpCall, Imm: 5}, {Op: core.OpExit}, {Op: core.OpCall, Imm: 7}, {Op: core.OpExit}}
	wrongPC := base
	wrongPC.Callee = []core.Insn{{Op: 0x05, Off: 1}, {Op: core.OpCall, Imm: 5}, {Op: core.OpCall, Imm: 5}, {Op: core.OpExit}}
	wrongPC.HelperPC = 1
	for name, w := range map[string]core.Window{"helper identity differs": wrongID, "unreachable foreign helper": unreachable, "executed helper at another pc": wrongPC} {
		if v := core.Check(w); v.Validated || v.Rule != "P8" {
			t.Errorf("%s: %+v", name, v)
		}
	}
}

// Finding 2. sub's pass prologue spills r5, so r_G = 5; the pass load writes
// the live r4 instead. Originally sub returns 42, after the rewrite 7.
func TestPassLoadWrongRegister(t *testing.T) {
	mk := func(dst uint8, subReads uint8) pair {
		return pair{
			o: []a{movi(subReads, 42).begins("main"), call("sub"), exit(), mov(0, subReads).begins("sub"), exit()},
			t: []a{stx(-24, 1).begins("main"), movi(subReads, 42), ldx(dst, -24), call("sub"), exit(),
				stx(-24, 5).begins("sub"), mov(0, subReads), exit()},
			kappa: []int{1, 3, 4, 6, 7}, floor: -16,
		}
	}
	wantRefused(t, runFile(t, mk(4, 4).capture(t)), "P9", "changes r[4]")

	// Evidence: the pass load changes r4, which sub returns.
	w := core.Window{Kind: core.KindPassLoad, Floor: -16, HasFloor: true, Insns: []core.Insn{{Op: 0x79, Dst: 4, Src: 10, Off: -24}}}
	var in interp.Input
	in.Regs[1], in.Regs[4] = 7, 42
	binary.LittleEndian.PutUint64(in.Stack[0][488:], 7) // fp-24
	in.Oracle = func(int) uint64 { return 0 }
	out, err := interp.Run(w, in)
	if err != nil || out.Regs[4] != 7 {
		t.Fatalf("reference interpreter: r4 = %d, %v; want 7", out.Regs[4], err)
	}

	// Control: the pass load into r_G = r5, which sub does not read.
	wantValidated(t, runFile(t, mk(5, 4).capture(t)))
	// S10: r_G = r5 is tied correctly, but sub reads r5 at its entry.
	wantRefused(t, runFile(t, mk(5, 5).capture(t)), "P9", "live")
}

// Finding 3. The callback prologue writes r1 and restores it; P1b allows
// writes to r0 only.
func TestCallbackWriteSet(t *testing.T) {
	funcref := func(dst uint8, name string) a { return a{op: 0x18, dst: dst, src: 4, call: name} }
	p := pair{
		o: []a{funcref(1, "cb").begins("main"), exit(), movi(0, 0).begins("cb"), exit()},
		t: []a{funcref(1, "cb").begins("main"), exit(),
			mov(0, 1).begins("cb"), movi(1, 0), mov(1, 0), movi(0, 0), exit()},
		kappa: []int{0, 1, 5, 6}, floor: -16,
	}
	c := p.capture(t)
	wantRefused(t, runFile(t, c), "P1b", "r1")

	// Evidence: the reference interpreter sees r1 = 0 mid-window and 9 at exit.
	l, err := Analyze(c)
	if err != nil {
		t.Fatal(err)
	}
	var w core.Window
	for _, lw := range l.Windows {
		if cw := l.CoreWindow(lw); cw.Kind == core.KindCallback {
			w = cw
		}
	}
	run := func(n int) uint64 {
		var in interp.Input
		in.Regs[1] = 9
		in.Oracle = func(int) uint64 { return 0 }
		w2 := w
		w2.Insns = w.Insns[:n]
		out, err := interp.Run(w2, in)
		if err != nil {
			t.Fatal(err)
		}
		return out.Regs[1]
	}
	if mid, end := run(2), run(len(w.Insns)); mid != 0 || end != 9 {
		t.Fatalf("reference interpreter: r1 mid %d, exit %d; want 0, 9", mid, end)
	}
}

// Finding 3, the same transient write in the P8 prelude and the P9 windows:
// the exit values are restored, so only the write-set check refuses them.
func TestWriteSetCore(t *testing.T) {
	ins := func(xs ...core.Insn) []core.Insn { return xs }
	ld := func(d uint8, o int16) core.Insn { return core.Insn{Op: 0x79, Dst: d, Src: 10, Off: o} }
	st := func(o int16, s uint8) core.Insn { return core.Insn{Op: 0x7b, Dst: 10, Src: s, Off: o} }
	mv := func(d, s uint8) core.Insn { return core.Insn{Op: 0xbf, Dst: d, Src: s} }
	zero := func(d uint8) core.Insn { return core.Insn{Op: 0xb7, Dst: d} }
	wrap := core.Window{Kind: core.KindWrap, Center: 4, Floor: -16, HasFloor: true,
		Insns:  ins(mv(4, 1), zero(1), mv(1, 4), ld(4, -24), core.Insn{Op: core.OpCall, Src: 1, Imm: 1}),
		Callee: ins(core.Insn{Op: core.OpCall, Imm: 1}, core.Insn{Op: core.OpExit}), HelperPC: 0, Helper: core.Insn{Op: core.OpCall, Imm: 1}}
	pass := core.Window{Kind: core.KindPass, Floor: -16, HasFloor: true,
		Insns: ins(st(-24, 5), zero(5), ld(5, -24))}
	passLoad := core.Window{Kind: core.KindPassLoad, Floor: -16, HasFloor: true, PassPrologue: ins(st(-24, 5)),
		Insns: ins(mv(5, 3), zero(3), mv(3, 5), ld(5, -24))}
	for name, c := range map[string]struct {
		w      core.Window
		clause string
	}{"P8 prelude writes r1": {wrap, "r1"}, "P9 prologue writes r5": {pass, "r5"}, "P9 pass load writes r3": {passLoad, "r3"}} {
		v := core.Check(c.w)
		if v.Validated || !strings.Contains(v.Reason, c.clause) {
			t.Errorf("%s: %+v", name, v)
		}
	}
}

// Finding 4. 1024 paths are the limit; the 1025th path is refused.
func TestPathBoundary(t *testing.T) {
	for _, n := range []int{1024, 1025, 1026} {
		w := core.Window{Kind: core.KindEntry, HasFloor: true, Floor: 0, Center: -1}
		for i := 0; i < n-1024; i++ {
			w.Insns = append(w.Insns, core.Insn{Op: 0x15, Dst: 1, Off: int16(10 + n - 1024 - i - 1)})
		}
		for i := 0; i < 10; i++ {
			w.Insns = append(w.Insns, core.Insn{Op: 0x15, Dst: 1, Off: 0})
		}
		v := core.Check(w)
		if n == 1024 && (!v.Validated || v.Paths != 1024) {
			t.Errorf("1024 paths: %+v", v)
		}
		if n > 1024 && (v.Validated || v.Rule != "limit") {
			t.Errorf("%d paths: %+v", n, v)
		}
	}
}

// Run's deferred timing must reach the caller (it once returned the result
// by value before the defer ran, so time_ms was always 0).
func TestRunTiming(t *testing.T) {
	r := runFile(t, sitePair().capture(t))
	if r.TimeUs <= 0 {
		t.Fatalf("time_us = %d", r.TimeUs)
	}
}
