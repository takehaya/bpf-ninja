package interp_test

// Differential tests: every symbolic path of a window,
// instantiated with a random concrete entry state and oracle, must equal the
// reference interpreter's run on the same input: exactly one path's
// conditions hold (coverage and determinism), and that path's positions,
// oracle use, registers r0-r10 and window-frame bytes equal the
// interpreter's (King's commutation).

import (
	"cmp"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/takehaya/bpf-ninja/tools/regionval"
	"github.com/takehaya/bpf-ninja/tools/regionval/core"
	"github.com/takehaya/bpf-ninja/tools/regionval/interp"
)

// Fixed seeds, so a failure reproduces.
const (
	seedRandom = 0x5eed_7a5b_0001
	seedExport = 0x5eed_7a5b_0002
)

var special = []uint64{0, 1, 0xffffffffffffffff, 0x7fffffff, 0x80000000, 0xffffffff, 0x100000000, 0x8000000000000000, 0x7fffffffffffffff, 0xff, 0x8000}

func draw(rng *rand.Rand) uint64 {
	switch rng.IntN(3) {
	case 0:
		return special[rng.IntN(len(special))]
	case 1:
		return uint64(rng.IntN(64))
	}
	return rng.Uint64()
}

func splitmix(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ x>>30) * 0xbf58476d1ce4e5b9
	x = (x ^ x>>27) * 0x94d049bb133111eb
	return x ^ x>>31
}

func randInput(rng *rand.Rand) interp.Input {
	var in interp.Input
	for k := range in.Regs {
		in.Regs[k] = draw(rng)
	}
	for f := range in.Stack {
		for i := 0; i < 512; i += 8 {
			v := draw(rng)
			for b := 0; b < 8; b++ {
				in.Stack[f][i+b] = byte(v >> (8 * b))
			}
		}
	}
	s := rng.Uint64()
	in.Oracle = func(i int) uint64 {
		h := splitmix(s ^ uint64(i)*0x9e3779b97f4a7c15)
		switch h % 4 {
		case 0:
			return 0 // guards test r0 == 0: take both sides often
		case 1:
			return special[h>>8%uint64(len(special))]
		}
		return splitmix(h)
	}
	return in
}

func holds(c core.Cond, x uint64) bool {
	switch c.Op {
	case 0x15:
		return x == uint64(int64(c.Imm))
	case 0x55:
		return x != uint64(int64(c.Imm))
	case 0x76:
		return int32(uint32(x)) >= c.Imm
	}
	panic(c.Op)
}

// compare checks one input against all symbolic paths of w.
func compare(w core.Window, paths []core.Path, in interp.Input) error {
	out, err := interp.Run(w, in)
	if err != nil {
		return fmt.Errorf("interpreter refused a window the stepper accepted: %v", err)
	}
	val := &core.Valuation{Regs: in.Regs, Base: [2]uint64{interp.Base0, interp.Base1},
		Stack: [2][]byte{in.Stack[0][:], in.Stack[1][:]}, Fresh: in.Oracle}
	var match []int
	for i, p := range paths {
		if !slices.ContainsFunc(p.Conds, func(c core.Cond) bool { return holds(c, core.Eval(c.T, val)) != c.Taken }) {
			match = append(match, i)
		}
	}
	if len(match) != 1 {
		return fmt.Errorf("%d symbolic paths match the input (want 1)", len(match))
	}
	p := paths[match[0]]
	if !slices.Equal(p.Locs, out.Locs) {
		return fmt.Errorf("path %v, interpreter %v", p.Locs, out.Locs)
	}
	if p.Fresh != out.Used || p.Exit != out.Exit {
		return fmt.Errorf("unknowns %d/%d, exit %v/%v", p.Fresh, out.Used, p.Exit, out.Exit)
	}
	for k, t := range p.Regs {
		if got := core.Eval(t, val); got != out.Regs[k] {
			return fmt.Errorf("r%d: symbolic %v = %#x, interpreter %#x", k, t, got, out.Regs[k])
		}
	}
	for o := int64(-512); o < 0; o++ {
		t := p.Mem[o]
		if t == nil {
			t = core.StackByte(0, o)
		}
		if got := core.Eval(t, val); got != uint64(out.Stack[o+512]) {
			return fmt.Errorf("stack byte %d: symbolic %v = %#x, interpreter %#x", o, t, got, out.Stack[o+512])
		}
	}
	return nil
}

// gen builds random allowlisted windows. It keeps values derived from r10
// (taint) away from and/or/lsh/ALU32 so that a pointer into a frame never
// becomes an address of a form the stepper treats as other memory (the
// stepper's answer would still be sound, but the concrete run would read
// the frame instead of drawing from the oracle).
type gen struct {
	rng   *rand.Rand
	taint [11]bool
}

func (g *gen) reg(maxr int) uint8 { return uint8(g.rng.IntN(maxr + 1)) }

func (g *gen) insn(pc, n int, body bool, hook map[int]bool) core.Insn {
	r := g.rng
	for {
		dst, src := g.reg(9), g.reg(10)
		switch r.IntN(16) {
		case 0, 1: // mov
			if r.IntN(2) == 0 {
				return core.Insn{Op: 0xb7, Dst: dst, Imm: int32(draw(r))}
			}
			if src == 10 || g.taint[src] {
				g.taint[dst] = true
			}
			return core.Insn{Op: 0xbf, Dst: dst, Src: src}
		case 2: // add imm
			if g.taint[dst] {
				return core.Insn{Op: 0x07, Dst: dst, Imm: -int32(r.IntN(64))}
			}
			return core.Insn{Op: 0x07, Dst: dst, Imm: int32(draw(r))}
		case 3, 4: // and/or/lsh, 64 and 32 bit
			if g.taint[dst] || g.taint[src] || src == 10 {
				continue
			}
			ops := []core.Insn{{Op: 0x57, Imm: int32(draw(r))}, {Op: 0x5f, Src: src}, {Op: 0x47, Imm: int32(draw(r))}, {Op: 0x4f, Src: src},
				{Op: 0x67, Imm: int32(r.IntN(64))}, {Op: 0xb4, Imm: int32(draw(r))}, {Op: 0xbc, Src: src}, {Op: 0x04, Imm: int32(draw(r))},
				{Op: 0x54, Imm: int32(draw(r))}, {Op: 0x5c, Src: src}, {Op: 0x44, Imm: int32(draw(r))}, {Op: 0x4c, Src: src}, {Op: 0x64, Imm: int32(r.IntN(32))}}
			x := ops[r.IntN(len(ops))]
			x.Dst = dst
			return x
		case 5, 6, 7: // load
			op := []uint8{0x61, 0x69, 0x71, 0x79}[r.IntN(4)]
			w := map[uint8]int{0x61: 4, 0x69: 2, 0x71: 1, 0x79: 8}[op]
			if r.IntN(2) == 0 {
				return core.Insn{Op: op, Dst: dst, Src: 10, Off: int16(-w - r.IntN(512-w+1))}
			}
			if g.taint[src] || src == 10 {
				continue
			}
			return core.Insn{Op: op, Dst: dst, Src: src, Off: int16(r.IntN(64) - 32)}
		case 8, 9: // store through r10
			op := []uint8{0x63, 0x6b, 0x73, 0x7b}[r.IntN(4)]
			w := map[uint8]int{0x63: 4, 0x6b: 2, 0x73: 1, 0x7b: 8}[op]
			return core.Insn{Op: op, Dst: 10, Src: src, Off: int16(-w - r.IntN(512-w+1))}
		case 10, 11, 12: // forward branch
			limit := n - pc - 1
			if body {
				limit--
			}
			if limit < 0 {
				continue
			}
			off := int16(r.IntN(limit + 1))
			switch r.IntN(4) {
			case 0:
				return core.Insn{Op: 0x05, Off: off}
			case 1:
				return core.Insn{Op: 0x15, Dst: dst, Off: off, Imm: int32(special[r.IntN(3)])}
			case 2:
				return core.Insn{Op: 0x55, Dst: dst, Off: off, Imm: int32(special[r.IntN(3)])}
			}
			return core.Insn{Op: 0x76, Dst: dst, Off: off, Imm: int32(draw(r))}
		case 13, 14: // hook call
			hook[pc] = true
			return core.Insn{Op: core.OpCall, Src: 1, Imm: int32(r.IntN(100))}
		case 15: // a stray helper call
			return core.Insn{Op: core.OpCall, Imm: int32(1 + r.IntN(200))}
		}
	}
}

func (g *gen) code(n, center int, body bool, centre core.Insn) ([]core.Insn, map[int]bool) {
	hook := map[int]bool{}
	var is []core.Insn
	for pc := 0; pc < n; pc++ {
		switch {
		case pc == center:
			is = append(is, centre)
		case body && pc == n-1:
			is = append(is, core.Insn{Op: core.OpExit})
		default:
			is = append(is, g.insn(pc, n, body, hook))
		}
	}
	return is, hook
}

var kinds = []string{core.KindSite, core.KindTail, core.KindWrap, core.KindEntry, core.KindCallback, core.KindPass, core.KindPassLoad, core.KindHook}

func genWindow(rng *rand.Rand, kind string) core.Window {
	g := &gen{rng: rng}
	g.taint[10] = true
	n := 2 + rng.IntN(16)
	w := core.Window{Kind: kind, Center: -1, Floor: int16(-8 * rng.IntN(64)), HasFloor: kind != core.KindHook}
	var centre core.Insn
	switch kind {
	case core.KindSite:
		w.Center, centre = rng.IntN(n), core.Insn{Op: core.OpCall, Imm: 1}
	case core.KindTail:
		w.Center, centre = rng.IntN(n), core.Insn{Op: core.OpCall, Imm: 12}
	case core.KindWrap:
		w.Center, centre = n-1, core.Insn{Op: core.OpCall, Src: 1, Imm: 40}
	}
	w.Insns, w.Hook = g.code(n, w.Center, kind == core.KindHook, centre)
	if kind == core.KindWrap {
		c := &gen{rng: rng}
		for _, k := range []int{1, 2, 3, 4, 5, 10} {
			c.taint[k] = true
		}
		m := 3 + rng.IntN(12)
		w.Callee, w.CalleeHook = c.code(m, rng.IntN(m-1), true, core.Insn{Op: core.OpCall, Imm: 1})
	}
	return w
}

func TestDifferentialRandomWindows(t *testing.T) {
	windows, inputs := 3000, 20
	if testing.Short() {
		windows = 200
	}
	for i, kind := range kinds {
		rng := rand.New(rand.NewPCG(seedRandom, uint64(i)))
		accepted, refused, cases, paths := 0, 0, 0, 0
		for accepted < windows {
			w := genWindow(rng, kind)
			ps, f := core.Explore(w)
			if f != nil {
				refused++
				continue
			}
			accepted++
			paths += len(ps)
			for j := 0; j < inputs; j++ {
				if err := compare(w, ps, randInput(rng)); err != nil {
					t.Fatalf("%s window %d input %d: %v\nwindow %+v", kind, accepted, j, err, w)
				}
				cases++
			}
		}
		t.Logf("random %-13s seed %#x/%d: %d windows (%d paths), %d refused by the stepper, %d cases, 0 mismatches", kind, seedRandom, i, accepted, paths, refused, cases)
	}
}

// Every window of the test captures whose structure is OK, 200 inputs each.
func TestDifferentialExportWindows(t *testing.T) {
	// REGIONVAL_DIFF_GLOB runs the same comparison over other capture files
	files, _ := filepath.Glob(cmp.Or(os.Getenv("REGIONVAL_DIFF_GLOB"), "../testdata/*/*/*.json"))
	if len(files) == 0 {
		t.Fatal("no test captures")
	}
	inputs := 200
	if testing.Short() {
		inputs = 5
	}
	rng := rand.New(rand.NewPCG(seedExport, 0))
	byKind := map[string][3]int{}
	for _, file := range files {
		c, err := regionval.LoadCapture(file)
		if err != nil {
			t.Fatal(err)
		}
		l, err := regionval.Analyze(c)
		if err != nil {
			continue
		}
		for _, lw := range l.Windows {
			w := l.CoreWindow(lw)
			ps, f := core.Explore(w)
			n := byKind[w.Kind]
			if f != nil {
				n[1]++
				byKind[w.Kind] = n
				continue
			}
			n[0]++
			for j := 0; j < inputs; j++ {
				if err := compare(w, ps, randInput(rng)); err != nil {
					t.Fatalf("%s %s [%d,%d) input %d: %v", file, w.Kind, lw.Start, lw.End, j, err)
				}
				n[2]++
			}
			byKind[w.Kind] = n
		}
	}
	for _, k := range slices.Sorted(maps.Keys(byKind)) {
		n := byKind[k]
		t.Logf("export %-28s seed %#x: %d windows, %d refused by the stepper, %d cases, 0 mismatches", k, seedExport, n[0], n[1], n[2])
	}
}
