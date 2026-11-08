package xcheck

import (
	"encoding/hex"
	"fmt"
	"io/fs"
	"math/rand"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/tools/regionval"
	"github.com/takehaya/bpf-ninja/tools/regionval/core"
	rd "github.com/takehaya/bpf-ninja/tools/regionval/dafny/regionvaldafny"
	"github.com/takehaya/bpf-ninja/tools/regionval/interp"
)

const tailCallID = 12 // bpf_tail_call

// spillSource is r_G of a pass prologue (the source register of its single
// STX to r10), or 0 if the prologue is no certificate. It mirrors the
// unexported core.spillSource.
func spillSource(pro []core.Insn) int {
	src := 0
	for _, x := range pro {
		if x.Class() == core.ClassSTX {
			if src != 0 || x.Op != 0x7b || x.Dst != 10 || x.Src < 1 || x.Src > 5 {
				return 0
			}
			src = int(x.Src)
		}
	}
	return src
}

// writes is the set of registers an instruction may write, as a bit mask.
// It mirrors the unexported core.writes.
func writes(x core.Insn) uint16 {
	switch c := x.Class(); {
	case c == core.ClassALU || c == core.ClassALU64 || c == core.ClassLDX || x.Op == core.OpLdImm64:
		return 1 << x.Dst
	case x.Op == core.OpCall:
		return 0x3f
	}
	return 0
}

// writesOutside returns the first instruction that may write a register
// outside allowed, or -1.
func writesOutside(xs []core.Insn, allowed uint16) int {
	for i, x := range xs {
		if writes(x)&^allowed != 0 {
			return i
		}
	}
	return -1
}

// dafnySpec maps a window kind to its Dafny Spec (README.md, Dafny core).
// wbody and helper are W's raw instructions and the raw original helper
// call O[i]; they are used for site-P8 only. ok is false when the Dafny
// core has no spec for the window.
func dafnySpec(cw core.Window, wbody, helper []byte) (rd.Spec, bool) {
	f := int(cw.Floor)
	const (
		noHelper   = false
		checkArgs  = false
		restoreR0  = false
		noHook     = false
		notHookBdy = false
	)
	switch cw.Kind {
	case core.KindWrap:
		if cw.Callee == nil || len(helper) != 8 {
			return rd.Spec{}, false
		}
		return rd.WrapSiteSpec(f, wbody, helper), true
	case core.KindSite:
		return rd.SiteSpec(f), true
	case core.KindTail:
		return rd.TailSiteSpec(f), true
	case core.KindEntry:
		return rd.EntryPrologueSpec(f), true
	case core.KindCallback:
		return rd.CallbackPrologueSpec(f), true
	case core.KindPass: // no register changes; stores allowed
		return rd.CustomSpec(f, nil, noHelper, checkArgs, restoreR0, true, noHook, notHookBdy), true
	case core.KindPassLoad: // only r_G changes; no store
		g := spillSource(cw.PassPrologue)
		if g == 0 {
			return rd.Spec{}, false
		}
		return rd.CustomSpec(f, []int{g}, noHelper, checkArgs, restoreR0, false, noHook, notHookBdy), true
	case core.KindHook:
		return rd.HookBodySpec(), true
	}
	return rd.Spec{}, false
}

// contract returns why a window fails the checks a caller of the Dafny core
// makes outside Validate (README.md, Dafny core), or "" if it passes them.
// Where the Go core checks the instructions a path executes, these checks
// look at every instruction of the window, which is at least as strict.
func contract(cw core.Window) string {
	switch cw.Kind {
	case core.KindSite, core.KindTail, core.KindWrap, core.KindEntry, core.KindCallback, core.KindPass, core.KindPassLoad, core.KindHook:
	default:
		return "kind not supported by the Dafny core"
	}
	if cw.Kind != core.KindHook && !cw.HasFloor {
		return "no floor"
	}
	site := cw.Kind == core.KindSite || cw.Kind == core.KindTail
	wrap := cw.Kind == core.KindWrap
	for i, x := range cw.Insns {
		if x.IsPseudoCall() && !cw.Hook[i] && (!wrap || i != len(cw.Insns)-1) {
			return "pseudo call not to a hook"
		}
		if x.IsHelperCall() && (!site || i != cw.Center) {
			return "helper call not at the centre"
		}
	}
	switch cw.Kind {
	case core.KindSite, core.KindTail:
		if cw.Center < 0 || cw.Center >= len(cw.Insns) || !cw.Insns[cw.Center].IsHelperCall() {
			return "no centre"
		}
		if (cw.Kind == core.KindTail) != (cw.Insns[cw.Center].Imm == tailCallID) {
			return "centre is not this kind's helper"
		}
	case core.KindWrap:
		// The last instruction is call W, whose target the layout resolved;
		// every pseudo call inside W must be a hook call.
		if cw.Center != len(cw.Insns)-1 || cw.Callee == nil {
			return "P8 shape"
		}
		for i, x := range cw.Callee {
			if x.IsPseudoCall() && !cw.CalleeHook[i] {
				return "pseudo call in W not to a hook"
			}
		}
	case core.KindCallback:
		if writesOutside(cw.Insns, 1) >= 0 {
			return "P1b: writes a register other than r0"
		}
	case core.KindPass:
		if spillSource(cw.Insns) == 0 {
			return "P9 certificate"
		}
		if writesOutside(cw.Insns, 0) >= 0 {
			return "P9: pass prologue writes a register"
		}
		// Branches go forward only, so the store runs on every path when
		// no branch comes before it.
		for _, x := range cw.Insns {
			if x.Class() == core.ClassSTX {
				break
			}
			if x.IsJump() {
				return "P9: a branch may skip the store"
			}
		}
	case core.KindPassLoad:
		g := spillSource(cw.PassPrologue)
		if g == 0 {
			return "P9 certificate"
		}
		if cw.PassLive&(1<<uint(g)) != 0 {
			return "S10"
		}
		if writesOutside(cw.Insns, 1<<uint(g)) >= 0 {
			return "P9: pass load writes a register other than r_G"
		}
	case core.KindHook:
		for _, x := range cw.Insns {
			if x.Class() == core.ClassLDX && x.Dst > 5 {
				return "P7: load into r6-r9"
			}
		}
	}
	return ""
}

// rawRange is the wire-format bytes of T instructions [start, end).
func rawRange(l *regionval.Layout, blob []byte, start, end int) []byte {
	if end <= start {
		return nil
	}
	last := l.T[end-1]
	return blob[8*l.T[start].Raw : 8*(last.Raw+last.Slots())]
}

// sameInsns reports whether raw decodes to exactly the instructions xs.
func sameInsns(raw []byte, xs []core.Insn) bool {
	ys, err := core.Decode(raw)
	if err != nil || len(ys) != len(xs) {
		return false
	}
	for i := range xs {
		if !xs[i].Same(ys[i]) {
			return false
		}
	}
	return true
}

func captureFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir("../../testdata", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".json") {
			files = append(files, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	return files
}

// p8Runs compares interp.Run with the Dafny ConcreteWindowRun (WP, W's body
// as a second frame, the return) on random inputs for one site-P8 window.
// It returns a description of the first difference, or "".
func p8Runs(r *rand.Rand, cw core.Window, raw []byte, sp rd.Spec, wlen, n int) string {
	for i := 0; i < n; i++ {
		var in interp.Input
		for k := range in.Regs {
			in.Regs[k] = r.Uint64()
		}
		r.Read(in.Stack[0][:])
		r.Read(in.Stack[1][:])
		orc := make([]uint64, 6+512+64)
		for k := range orc {
			orc[k] = r.Uint64()
		}
		in.Oracle = func(k int) uint64 {
			if k < len(orc) {
				return orc[k]
			}
			return 0
		}
		out, err := interp.Run(cw, in)
		var regs [rd.NRegs]uint64
		copy(regs[:10], in.Regs[:])
		regs[10] = interp.Base0
		fin, k := rd.ConcreteWindowRun(raw, sp, rd.InitState(regs, in.Stack[0]), orc, len(raw)/8+wlen+1)
		switch {
		case err != nil && k != rd.Done: // both refuse
		case err != nil:
			return fmt.Sprintf("run %d: interp refuses (%v), Dafny completes", i, err)
		case k != rd.Done:
			return fmt.Sprintf("run %d: Dafny outcome %d, interp completes", i, k)
		case out.Regs != fin.Regs || out.Stack != fin.Stack || out.Used != fin.OC:
			return fmt.Sprintf("run %d: final states differ", i)
		}
	}
	return ""
}

// TestCaptureWindows runs the Go core and the Dafny core, used as the Go
// core's replacement (the contract checks, then Validate), on every window
// of every capture under testdata. A window the Dafny core validates and the
// Go core rejects fails the test. Every site-P8 window is also run on random
// inputs by both interpreters.
func TestCaptureWindows(t *testing.T) {
	files := captureFiles(t)
	if len(files) == 0 {
		t.Fatal("no captures under testdata")
	}
	// Windows the Go core validates and the Dafny core rejects. The Dafny
	// core does not allow a hook call in an entry prologue.
	wantGoOnly := map[string]bool{
		"export/clean/clean-katran-ctxwrite.json ctxwrite [0,3) prologue-P1": true,
	}
	type count struct{ windows, goV, dafnyV, both int }
	byKind := map[string]*count{}
	goRejected, p8Compared := 0, 0
	rng := rand.New(rand.NewSource(1))
	for _, f := range files {
		name, _ := filepath.Rel("../../testdata", f)
		c, err := regionval.LoadCapture(f)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		l, err := regionval.Analyze(c)
		if err != nil {
			t.Logf("%s: no windows (%v)", name, err) // neither core validates the load
			continue
		}
		blob, err := hex.DecodeString(c.TransformedInsnsHex)
		if err != nil {
			t.Fatalf("%s: transformed instructions: %v", name, err)
		}
		oblob, err := hex.DecodeString(c.OriginalInsnsHex)
		if err != nil {
			t.Fatalf("%s: original instructions: %v", name, err)
		}
		for _, w := range l.Windows {
			cw := l.CoreWindow(w)
			id := fmt.Sprintf("%s %s [%d,%d) %s", name, w.Func, w.Start, w.End, cw.Kind)
			raw := rawRange(l, blob, w.Start, w.End)
			var wbody, helper []byte
			if w.Callee >= 0 {
				tf := l.TFuncs[w.Callee]
				wbody = rawRange(l, blob, tf.Start, tf.End)
				if w.Orig >= 0 {
					if o := l.O[w.Orig]; 8*o.Raw+8 <= len(oblob) {
						helper = oblob[8*o.Raw : 8*o.Raw+8]
					}
				}
			}
			// The bytes given to Dafny are the instructions the Go core checks.
			if !sameInsns(raw, cw.Insns) {
				t.Errorf("%s: window bytes differ from the Go core's window", id)
			}
			if cw.Kind == core.KindWrap && (!sameInsns(wbody, cw.Callee) || !sameInsns(helper, []core.Insn{cw.Helper})) {
				t.Errorf("%s: W or O[i] bytes differ from the Go core's window", id)
			}
			rv := core.Check(cw)
			dv := false
			why := contract(cw)
			if why == "" {
				if sp, ok := dafnySpec(cw, wbody, helper); ok {
					v := rd.Validate(raw, sp)
					dv, why = v.Validated, v.Reason
					if cw.Kind == core.KindWrap {
						p8Compared++
						if d := p8Runs(rng, cw, raw, sp, len(wbody)/8, 50); d != "" {
							t.Errorf("%s: interp and Dafny differ: %s", id, d)
						}
					}
				} else {
					why = "no Dafny spec"
				}
			}
			k := byKind[cw.Kind]
			if k == nil {
				k = &count{}
				byKind[cw.Kind] = k
			}
			k.windows++
			if rv.Validated {
				k.goV++
			} else {
				goRejected++
			}
			if dv {
				k.dafnyV++
			}
			if dv && rv.Validated {
				k.both++
			}
			switch {
			case dv && !rv.Validated:
				t.Errorf("%s: Dafny validates, Go rejects (%s: %s)", id, rv.Rule, rv.Reason)
			case rv.Validated && !dv && !wantGoOnly[id]:
				t.Errorf("%s: Go validates, Dafny rejects (%s)", id, why)
			case rv.Validated && !dv:
				delete(wantGoOnly, id)
			}
		}
	}
	for id := range wantGoOnly {
		t.Errorf("%s: expected Go to validate and Dafny to reject", id)
	}
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		c := byKind[k]
		t.Logf("%-14s windows %4d  Go validated %4d  Dafny validated %4d  both %4d", k, c.windows, c.goV, c.dafnyV, c.both)
	}
	// Guard against a vacuous pass: the planted captures give windows the Go
	// core rejects, and wrapper sites reach the Dafny core.
	if goRejected == 0 {
		t.Error("no window rejected by the Go core")
	}
	if c := byKind[core.KindWrap]; c == nil || c.both == 0 || p8Compared == 0 {
		t.Error("no site-P8 window validated by both cores")
	}
}

// Each check of the contract on a window the Go core rejects. Where Validate
// alone would accept the window, the contract is what keeps the Dafny core
// from validating it.
func TestContract(t *testing.T) {
	mk := func(kind string, raw []byte, edit func(*core.Window)) core.Window {
		w, ok := window(kind, raw)
		if !ok {
			t.Fatalf("%s: undecodable", kind)
		}
		if edit != nil {
			edit(&w)
		}
		return w
	}
	passPro := func(w *core.Window) { w.PassPrologue, _ = core.Decode(stx(10, 3, -176)) }
	wrapW := func(body []byte) func(*core.Window) {
		return func(w *core.Window) {
			w.Center = len(w.Insns) - 1
			w.Hook = map[int]bool{}
			w.Callee, _ = core.Decode(body)
			w.CalleeHook = map[int]bool{}
			w.HelperPC = 0
			w.Helper = w.Callee[0]
		}
	}
	tail := ins(0x85, 0, 0, 0, tailCallID)
	cases := []struct {
		name string
		w    core.Window
	}{
		{"unknown kind", mk(core.KindSite, ldx(0, 10, -176), func(w *core.Window) { w.Kind = "site-wrapped-tail-call" })},
		{"no floor", mk(core.KindSite, site, func(w *core.Window) { w.HasFloor = false })},
		{"pseudo call not to a hook", mk(core.KindSite, site, func(w *core.Window) { w.Hook = map[int]bool{} })},
		{"helper call outside the centre", mk(core.KindEntry, cat(stx(10, 1, -176), helper), nil)},
		{"site without a helper call", mk(core.KindSite, ldx(0, 10, -176), nil)},
		{"site centre is bpf_tail_call", mk(core.KindSite, cat(tail, ldx(0, 10, -176)), nil)},
		{"tail site centre is another helper", mk(core.KindTail, helper, nil)},
		{"P8 not ending in call W", mk(core.KindWrap, cat(hook, movk(4, 0)), wrapW(cat(helper, exit)))},
		{"P8 without W", mk(core.KindWrap, hook, func(w *core.Window) { wrapW(cat(helper, exit))(w); w.Callee = nil })},
		{"pseudo call in W not to a hook", mk(core.KindWrap, hook, wrapW(cat(helper, hook, exit)))},
		{"P1b writes r2", mk(core.KindCallback, mov(2, 2), nil)},
		{"P9 pass prologue without certificate", mk(core.KindPass, stx(10, 6, -176), nil)},
		{"P9 pass prologue writes r2", mk(core.KindPass, cat(mov(2, 2), stx(10, 3, -176)), nil)},
		{"P9 branch over the store", mk(core.KindPass, cat(jeq(1, 0, 1), stx(10, 3, -176)), nil)},
		{"P9 pass load without certificate", mk(core.KindPassLoad, stx(10, 3, -176), func(w *core.Window) { w.PassPrologue = nil })},
		{"S10: r_G live at the callee", mk(core.KindPassLoad, ldx(3, 10, -176), func(w *core.Window) { passPro(w); w.PassLive = 1 << 3 })},
		{"P9 pass load writes r4", mk(core.KindPassLoad, cat(ldx(3, 10, -176), mov(4, 4)), passPro)},
		{"P7 load into r6", mk(core.KindHook, cat(mov(2, 6), ldx(6, 1, 0), mov(6, 2), movk(0, 0), exit), nil)},
	}
	for _, c := range cases {
		if v := core.Check(c.w); v.Validated {
			t.Errorf("%s: the Go core validates the window", c.name)
		}
		if why := contract(c.w); why == "" {
			t.Errorf("%s: contract passes", c.name)
		}
	}

	// R15 at bpf_tail_call is in TailSiteSpec, not in the contract.
	raw := cat(movk(3, 7), tail)
	w := mk(core.KindTail, raw, nil)
	if core.Check(w).Validated || contract(w) != "" || rd.Validate(raw, rd.TailSiteSpec(floor)).Validated {
		t.Error("tail site changing r3: want Go to reject, the contract to pass and Validate to reject")
	}
}
