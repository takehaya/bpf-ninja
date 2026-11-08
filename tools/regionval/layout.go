package regionval

import (
	"fmt"
	"slices"

	"github.com/takehaya/bpf-ninja/tools/regionval/core"
)

// Func is one function of a stream, from func_info and BTF.
type Func struct {
	Name       string
	Start, End int // decoded indices [Start, End)
	Inserted   bool
}

// Window is one extracted window of the transformed stream T.
type Window struct {
	Kind       string // prologue | site | gap | hook
	Func       string
	Start, End int // decoded indices of T, [Start, End)
	Center     int // T index of the original helper call or `call W_i`; -1 if none
	Orig       int // O index of the centre, or of the original the window precedes; -1 for hooks
	Callee     int // TFuncs index of W_i (P8); -1 if none
}

// Layout is a structurally verified pair (README.md, Structure).
type Layout struct {
	O, T           []core.Insn
	OFuncs, TFuncs []Func
	Kappa          []int
	Windows        []Window
	Floors         map[string]int16
	Live           []uint16 // core.LiveIn(O): r1-r5 live at each original function's entry (S10)
	oRaw, tRaw     []byte   // wire bytes of O and T
}

// StructError fails the whole load (fail-closed).
type StructError struct {
	Stage string // decode | funcs | floors | kappa | windows | edges | calls
	Msg   string
}

func (e *StructError) Error() string { return e.Stage + ": " + e.Msg }

func fail(stage, format string, a ...any) error {
	return &StructError{Stage: stage, Msg: fmt.Sprintf(format, a...)}
}

func rawIndex(is []core.Insn) map[int]int {
	m := make(map[int]int, len(is))
	for i, x := range is {
		m[x.Raw] = i
	}
	return m
}

func buildFuncs(is []core.Insn, recs []FuncRec, names map[uint32]string, which string) ([]Func, error) {
	raw := rawIndex(is)
	var fs []Func
	seen := map[string]bool{}
	for k, r := range recs {
		start, ok := raw[int(r.InsnOff)]
		name, named := names[r.TypeID]
		switch {
		case !ok:
			return nil, fail("funcs", "%s func_info %d: insn_off %d is not an instruction boundary", which, k, r.InsnOff)
		case !named:
			return nil, fail("funcs", "%s func_info %d: type id %d is not a BTF FUNC", which, k, r.TypeID)
		case seen[name]:
			return nil, fail("funcs", "%s: duplicate function name %q", which, name)
		}
		seen[name] = true
		if len(fs) > 0 {
			fs[len(fs)-1].End = start
		}
		fs = append(fs, Func{Name: name, Start: start, End: len(is)})
	}
	return fs, nil
}

func funcAt(fs []Func, i int) int {
	return slices.IndexFunc(fs, func(f Func) bool { return f.Start <= i && i < f.End })
}

// funcStarting returns the function whose first instruction is at raw.
func funcStarting(fs []Func, raw map[int]int, at int) int {
	i, ok := raw[at]
	if !ok {
		return -1
	}
	return slices.IndexFunc(fs, func(f Func) bool { return f.Start == i })
}

// Analyze decodes the capture and checks S1-S3; it returns the windows.
func Analyze(c *Capture) (*Layout, error) {
	bl, err := c.blobs()
	if err != nil {
		return nil, fail("decode", "%v", err)
	}
	l := &Layout{oRaw: bl[0], tRaw: bl[1]}
	if l.O, err = core.Decode(bl[0]); err != nil {
		return nil, fail("decode", "original: %v", err)
	}
	if l.T, err = core.Decode(bl[1]); err != nil {
		return nil, fail("decode", "transformed: %v", err)
	}
	if err := l.functions(bl[2], bl[3], bl[4]); err != nil {
		return nil, err
	}
	l.Floors = map[string]int16{}
	for _, f := range c.Floors {
		if _, dup := l.Floors[f.Name]; dup || f.Floor > 0 || f.Floor < -512 {
			return nil, fail("floors", "floor entry %q %d duplicate or outside [-512, 0]", f.Name, f.Floor)
		}
		l.Floors[f.Name] = f.Floor
	}
	if c.Hints.Certificate == nil {
		return nil, fail("kappa", "no certificate hint (own κ search not implemented)")
	}
	l.Kappa = slices.Clone(c.Hints.Certificate.Original)
	wrapped, err := l.checkKappa()
	if err != nil {
		return nil, err
	}
	entry, err := l.extract(wrapped)
	if err != nil {
		return nil, err
	}
	if err := l.checkEdges(entry); err != nil {
		return nil, err
	}
	starts := make([]int, len(l.OFuncs))
	for i, f := range l.OFuncs {
		starts[i] = f.Start
	}
	l.Live = core.LiveIn(l.O, starts)
	return l, l.checkCalls(wrapped)
}

func (l *Layout) functions(ofi, tfi, blob []byte) error {
	names, err := ParseBTFFuncNames(blob)
	if err != nil {
		return fail("funcs", "%v", err)
	}
	orec, err := ParseFuncInfo(ofi)
	if err != nil {
		return fail("funcs", "original: %v", err)
	}
	trec, err := ParseFuncInfo(tfi)
	if err != nil {
		return fail("funcs", "transformed: %v", err)
	}
	if len(orec) == 0 {
		return fail("funcs", "original has no func_info")
	}
	if l.OFuncs, err = buildFuncs(l.O, orec, names, "original"); err != nil {
		return err
	}
	if l.TFuncs, err = buildFuncs(l.T, trec, names, "transformed"); err != nil {
		return err
	}
	orig := map[string]bool{}
	for _, f := range l.OFuncs {
		orig[f.Name] = true
	}
	var kept []string
	for i := range l.TFuncs {
		l.TFuncs[i].Inserted = !orig[l.TFuncs[i].Name]
		if !l.TFuncs[i].Inserted {
			kept = append(kept, l.TFuncs[i].Name)
		}
	}
	for i, f := range l.OFuncs {
		if i >= len(kept) || kept[i] != f.Name {
			return fail("funcs", "original functions are not kept in order in the transformed stream (%v)", kept)
		}
	}
	return nil
}

// checkKappa verifies S1 and returns the wrapped sites: O index -> TFuncs index of W_i.
func (l *Layout) checkKappa() (map[int]int, error) {
	k := l.Kappa
	if len(k) != len(l.O) {
		return nil, fail("kappa", "κ has %d entries for %d original instructions", len(k), len(l.O))
	}
	oRaw, tRaw := rawIndex(l.O), rawIndex(l.T)
	wrapped := map[int]int{}
	for i, o := range l.O {
		if k[i] < 0 || k[i] >= len(l.T) || (i > 0 && k[i] <= k[i-1]) {
			return nil, fail("kappa", "κ(%d) = %d out of range or not increasing", i, k[i])
		}
		if of, tf := funcAt(l.OFuncs, i), funcAt(l.TFuncs, k[i]); l.OFuncs[of].Name != l.TFuncs[tf].Name {
			return nil, fail("kappa", "κ(%d) = %d lies in %q, original in %q", i, k[i], l.TFuncs[tf].Name, l.OFuncs[of].Name)
		}
		t := l.T[k[i]]
		switch {
		case o.IsHelperCall() && t.IsPseudoCall():
			w := funcStarting(l.TFuncs, tRaw, t.CallTarget())
			if w < 0 || !l.TFuncs[w].Inserted {
				return nil, fail("kappa", "κ(%d): helper call replaced by a call to a non-inserted function", i)
			}
			n := 0
			for j := l.TFuncs[w].Start; j < l.TFuncs[w].End; j++ {
				if l.T[j].Same(o) {
					n++
				}
			}
			if n != 1 { // rule:S1-wrapper
				return nil, fail("kappa", "κ(%d): wrapper %q holds the original call %d times", i, l.TFuncs[w].Name, n)
			}
			wrapped[i] = w
		case o.IsJump():
			ja32 := o.Class() == core.ClassJMP32 && o.Op&0xf0 == 0
			if o.Op != t.Op || o.Dst != t.Dst || o.Src != t.Src || (!ja32 && o.Imm != t.Imm) {
				return nil, fail("kappa", "κ(%d): branch %v differs from original %v", i, t, o)
			}
		case o.IsPseudoCall() || o.IsFuncRef():
			a, b := o, t
			a.Imm, b.Imm, a.Imm64, b.Imm64 = 0, 0, o.Imm64>>32, t.Imm64>>32
			g, h := funcStarting(l.OFuncs, oRaw, o.CallTarget()), funcStarting(l.TFuncs, tRaw, t.CallTarget())
			if !a.Same(b) || g < 0 || h < 0 || l.OFuncs[g].Name != l.TFuncs[h].Name {
				return nil, fail("kappa", "κ(%d): function reference %v does not match original %v", i, t, o)
			}
		default:
			if !o.Same(t) { // rule:S1-fields
				return nil, fail("kappa", "κ(%d): %v differs from original %v", i, t, o)
			}
		}
	}
	return wrapped, nil
}

type span struct{ start, end int }

// extract partitions the inserted instructions into windows and
// returns e(i), the T index a branch to original i must land on.
func (l *Layout) extract(wrapped map[int]int) (map[int]int, error) {
	k := l.Kappa
	entry := map[int]int{}
	of := 0
	for _, F := range l.TFuncs {
		if F.Inserted {
			continue
		}
		G := l.OFuncs[of]
		of++
		pre, post := map[int]span{}, map[int]span{}
		for i := G.Start; i < G.End; i++ {
			entry[i] = k[i]
			lo := F.Start
			if i > G.Start {
				lo = k[i-1] + 1
			}
			if lo == k[i] {
				continue
			}
			g := span{lo, k[i]}
			helperBefore := i > G.Start && l.O[i-1].IsHelperCall()
			switch {
			case i == G.Start && l.O[i].IsHelperCall():
				return nil, fail("windows", "%q: prologue and prelude of original %d are not separable", F.Name, i)
			case i == G.Start:
				l.Windows = append(l.Windows, Window{Kind: "prologue", Func: F.Name, Start: g.start, End: g.end, Center: -1, Orig: i, Callee: -1})
			case helperBefore && l.O[i].IsHelperCall():
				return nil, fail("windows", "%q: inserted run between helper calls %d and %d is not separable", F.Name, i-1, i)
			case helperBefore:
				post[i-1] = g
			case l.O[i].IsHelperCall():
				pre[i], entry[i] = g, g.start
			default:
				l.Windows = append(l.Windows, Window{Kind: "gap", Func: F.Name, Start: g.start, End: g.end, Center: -1, Orig: i, Callee: -1})
				entry[i] = g.start
			}
		}
		if last := k[G.End-1]; last+1 < F.End {
			return nil, fail("windows", "%q: %d inserted instructions after the last original instruction", F.Name, F.End-last-1)
		}
		for i := G.Start; i < G.End; i++ {
			p, hasPre := pre[i]
			q, hasPost := post[i]
			w, isWrapped := wrapped[i]
			if !hasPre && !hasPost && !isWrapped {
				continue
			}
			win := Window{Kind: "site", Func: F.Name, Start: k[i], End: k[i] + 1, Center: k[i], Orig: i, Callee: -1}
			if hasPre {
				win.Start = p.start
			}
			if hasPost {
				win.End = q.end
			}
			if isWrapped {
				win.Callee = w
			}
			l.Windows = append(l.Windows, win)
		}
	}
	for fi, F := range l.TFuncs {
		if F.Inserted && !slices.Contains(mapValues(wrapped), fi) {
			l.Windows = append(l.Windows, Window{Kind: "hook", Func: F.Name, Start: F.Start, End: F.End, Center: -1, Orig: -1, Callee: -1})
		}
	}
	slices.SortFunc(l.Windows, func(a, b Window) int { return a.Start - b.Start })
	return entry, nil
}

func mapValues(m map[int]int) []int {
	var v []int
	for _, x := range m {
		v = append(v, x)
	}
	return v
}

// checkEdges verifies S2: every original branch to t lands on e(t).
func (l *Layout) checkEdges(entry map[int]int) error {
	oRaw, tRaw := rawIndex(l.O), rawIndex(l.T)
	for i, o := range l.O {
		if !o.IsJump() {
			continue
		}
		t, ok := oRaw[o.JumpTarget()]
		if !ok {
			return fail("edges", "original %d: branch target is not an instruction", i)
		}
		got, ok := tRaw[l.T[l.Kappa[i]].JumpTarget()]
		if !ok || got != entry[t] { // rule:S2-edges
			return fail("edges", "original %d -> %d: transformed branch lands on %d, want e(%d) = %d", i, t, got, t, entry[t])
		}
	}
	return nil
}

// checkCalls verifies S3 for inserted functions and instructions: every
// wrapper is called once, from its site; every hook only from windows; and
// every inserted instruction lies in exactly one window.
func (l *Layout) checkCalls(wrapped map[int]int) error {
	isOrig := make([]bool, len(l.T))
	for _, j := range l.Kappa {
		isOrig[j] = true
	}
	isWrapper := map[int]bool{}
	for _, w := range wrapped {
		isWrapper[w] = true
	}
	tRaw := rawIndex(l.T)
	calls := make([]int, len(l.TFuncs))
	for j, x := range l.T {
		if !x.IsPseudoCall() && !x.IsFuncRef() {
			continue
		}
		f := funcStarting(l.TFuncs, tRaw, x.CallTarget())
		if f < 0 {
			return fail("calls", "T[%d]: call target is not a function start", j)
		}
		if !l.TFuncs[f].Inserted {
			continue
		}
		if x.IsFuncRef() || (isWrapper[f] != isOrig[j]) {
			return fail("calls", "T[%d]: reference to inserted function %q from the wrong place", j, l.TFuncs[f].Name)
		}
		calls[f]++
	}
	for f, F := range l.TFuncs {
		if F.Inserted && (calls[f] == 0 || (isWrapper[f] && calls[f] != 1)) {
			return fail("calls", "inserted function %q called %d times", F.Name, calls[f])
		}
	}
	if n := l.unassigned(); n > 0 { // rule:S3-assigned
		return fail("calls", "%d inserted instructions are not in exactly one window", n)
	}
	return nil
}

// unassigned counts the inserted instructions of T (those that are not
// κ-images) that lie in no window or in more than one. A window covers its
// range [Start, End) and, for P8, the whole wrapper function W_i.
func (l *Layout) unassigned() int {
	covered := make([]int, len(l.T))
	for _, w := range l.Windows {
		for j := w.Start; j < w.End; j++ {
			covered[j]++
		}
		if w.Callee >= 0 {
			for j := l.TFuncs[w.Callee].Start; j < l.TFuncs[w.Callee].End; j++ {
				covered[j]++
			}
		}
	}
	for _, j := range l.Kappa {
		covered[j] = 1 // original instructions need no window
	}
	n := 0
	for _, c := range covered {
		if c != 1 {
			n++
		}
	}
	return n
}

// CoreWindow is the core's input for w.
func (l *Layout) CoreWindow(w Window) core.Window {
	cw := core.Window{Kind: l.windowKind(w), Insns: l.T[w.Start:w.End], Center: -1, Hook: l.hookCalls(w.Start, w.End)}
	if w.Center >= 0 {
		cw.Center = w.Center - w.Start
	}
	if w.Callee >= 0 {
		f := l.TFuncs[w.Callee]
		cw.Callee, cw.CalleeHook = l.T[f.Start:f.End], l.hookCalls(f.Start, f.End)
		// The original helper call, by full identity, and its pc in W
		// (S1-wrapper: exactly one instruction of W is the same).
		cw.Helper = l.O[w.Orig]
		cw.HelperPC = slices.IndexFunc(cw.Callee, cw.Helper.Same)
	}
	cw.Floor, cw.HasFloor = l.Floors[w.Func]
	if cw.Kind == core.KindPassLoad { // FP(G) of the called G; S10 of G
		cw.PassLive = core.ArgRegs // no callee found: everything live
		if g := funcStarting(l.OFuncs, rawIndex(l.O), l.O[w.Orig].CallTarget()); g >= 0 {
			cw.PassLive = l.Live[g]
			for _, pw := range l.Windows {
				if pw.Kind == "prologue" && pw.Func == l.OFuncs[g].Name && l.windowKind(pw) == core.KindPass {
					cw.PassPrologue = l.T[pw.Start:pw.End]
				}
			}
		}
	}
	return cw
}

// WindowBytes returns the wire bytes the Dafny core judges for window w: the
// window, and for a window with a wrapper the body of W and the original
// helper call O[i] (nil otherwise).
func (l *Layout) WindowBytes(w Window) (insns, body, helper []byte) {
	insns = l.tBytes(w.Start, w.End)
	if w.Callee >= 0 {
		f := l.TFuncs[w.Callee]
		body = l.tBytes(f.Start, f.End)
		if w.Orig >= 0 {
			if o := l.O[w.Orig]; 8*o.Raw+8 <= len(l.oRaw) {
				helper = l.oRaw[8*o.Raw : 8*o.Raw+8]
			}
		}
	}
	return insns, body, helper
}

// tBytes is the wire bytes of T[start:end].
func (l *Layout) tBytes(start, end int) []byte {
	if end <= start {
		return nil
	}
	last := l.T[end-1]
	return l.tRaw[8*l.T[start].Raw : 8*(last.Raw+last.Slots())]
}

// hookCalls marks the pseudo calls in T[start:end) whose target is a hook
// (an inserted function that is not a wrapper), by index from start.
func (l *Layout) hookCalls(start, end int) map[int]bool {
	tRaw := rawIndex(l.T)
	m := map[int]bool{}
	for j := start; j < end; j++ {
		if x := l.T[j]; x.IsPseudoCall() {
			if f := funcStarting(l.TFuncs, tRaw, x.CallTarget()); f >= 0 && l.TFuncs[f].Inserted && !l.isWrapper(f) {
				m[j-start] = true
			}
		}
	}
	return m
}

func (l *Layout) isWrapper(f int) bool {
	return slices.ContainsFunc(l.Windows, func(w Window) bool { return w.Callee == f })
}

// windowKind selects the obligations of w (README.md, Windows) from the verified
// original: the site helper, a wrapper, and the role of a prologue's
// function. A prologue whose function has no role or several roles, and a
// gap not before a call to an original function, get no known kind and so
// are not validated (fail-closed).
func (l *Layout) windowKind(w Window) string {
	switch w.Kind {
	case "hook":
		return core.KindHook
	case "site":
		switch {
		case w.Callee >= 0 && l.O[w.Orig].Imm != 12:
			return core.KindWrap
		case w.Callee >= 0:
			return "site-wrapped-tail-call"
		case l.O[w.Orig].Imm == 12: // rule:kind-select
			return core.KindTail
		}
		return core.KindSite
	case "gap":
		if l.O[w.Orig].IsPseudoCall() {
			return core.KindPassLoad
		}
		return "gap-unknown"
	case "prologue":
		start := l.O[w.Orig].Raw
		var roles []string
		if w.Orig == 0 {
			roles = append(roles, core.KindEntry)
		}
		for _, x := range l.O {
			if x.IsFuncRef() && x.CallTarget() == start && !slices.Contains(roles, core.KindCallback) {
				roles = append(roles, core.KindCallback)
			}
			if x.IsPseudoCall() && x.CallTarget() == start && !slices.Contains(roles, core.KindPass) {
				roles = append(roles, core.KindPass)
			}
		}
		if len(roles) == 1 {
			return roles[0]
		}
		return fmt.Sprintf("prologue-roles%v", roles)
	}
	return "unknown"
}
