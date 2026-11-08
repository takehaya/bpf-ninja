package xcheck

import (
	"fmt"
	"io/fs"
	"math/rand"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/tools/regionval"
	"github.com/takehaya/bpf-ninja/tools/regionval/core"
	"github.com/takehaya/bpf-ninja/tools/regionval/dafny/contract"
	rd "github.com/takehaya/bpf-ninja/tools/regionval/dafny/regionvaldafny"
	"github.com/takehaya/bpf-ninja/tools/regionval/interp"
)

const tailCallID = 12 // bpf_tail_call

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

// TestCaptureWindows runs the Go core and the Dafny core (contract.Validate,
// what the command decides with) on every window of every capture under
// testdata, and fails on any window where the two verdicts differ. Every
// site-P8 window is also run on random inputs by both interpreters.
func TestCaptureWindows(t *testing.T) {
	files := captureFiles(t)
	if len(files) == 0 {
		t.Fatal("no captures under testdata")
	}
	type count struct{ windows, goV, dafnyV int }
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
		for _, w := range l.Windows {
			cw := l.CoreWindow(w)
			id := fmt.Sprintf("%s %s [%d,%d) %s", name, w.Func, w.Start, w.End, cw.Kind)
			raw, wbody, helper := l.WindowBytes(w)
			rv := core.Check(cw)
			dv := contract.Validate(cw, raw, wbody, helper)
			if strings.Contains(dv.Reason, "bytes differ") {
				t.Errorf("%s: %s", id, dv.Reason)
			}
			if sp, ok := contract.Spec(cw, wbody, helper); ok && cw.Kind == core.KindWrap && contract.Check(cw) == "" {
				p8Compared++
				if d := p8Runs(rng, cw, raw, sp, len(wbody)/8, 50); d != "" {
					t.Errorf("%s: interp and Dafny differ: %s", id, d)
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
			if dv.Validated {
				k.dafnyV++
			}
			switch {
			case dv.Validated && !rv.Validated:
				t.Errorf("%s: Dafny validates, Go rejects (%s: %s)", id, rv.Rule, rv.Reason)
			case rv.Validated && !dv.Validated:
				t.Errorf("%s: Go validates, Dafny rejects (%s)", id, dv.Reason)
			}
		}
	}
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		c := byKind[k]
		t.Logf("%-14s windows %4d  Go validated %4d  Dafny validated %4d", k, c.windows, c.goV, c.dafnyV)
	}
	// Guard against a vacuous pass: the planted captures give windows the Go
	// core rejects, and wrapper sites reach the Dafny core.
	if goRejected == 0 {
		t.Error("no window rejected by the Go core")
	}
	if c := byKind[core.KindWrap]; c == nil || c.dafnyV == 0 || p8Compared == 0 {
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
		if why := contract.Check(c.w); why == "" {
			t.Errorf("%s: contract passes", c.name)
		}
		if v := contract.Validate(c.w, nil, nil, nil); v.Validated || !strings.HasPrefix(v.Reason, "contract: ") {
			t.Errorf("%s: Validate does not refuse by the contract: %+v", c.name, v)
		}
	}

	// R15 at bpf_tail_call is in TailSiteSpec, not in the contract.
	raw := cat(movk(3, 7), tail)
	w := mk(core.KindTail, raw, nil)
	if core.Check(w).Validated || contract.Check(w) != "" || rd.Validate(raw, rd.TailSiteSpec(floor)).Validated {
		t.Error("tail site changing r3: want Go to reject, the contract to pass and Validate to reject")
	}
}
