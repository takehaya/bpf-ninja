package regionval

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/tools/regionval/core"
)

// Hand-written fixture pairs. a is one instruction of a tiny assembler:
// fn starts a function, label names it, jmp/call are resolved to raw
// offsets (target = raw + 1 + off).
type a struct {
	op, dst, src uint8
	off          int16
	imm          int32
	hi           int32 // ld_imm64 next_imm
	fn, label    string
	jmp, call    string
}

func mov(d, s uint8) a          { return a{op: 0xbf, dst: d, src: s} }
func movi(d uint8, v int32) a   { return a{op: 0xb7, dst: d, imm: v} }
func addi(d uint8, v int32) a   { return a{op: 0x07, dst: d, imm: v} }
func stx(o int16, s uint8) a    { return a{op: 0x7b, dst: 10, src: s, off: o} }
func ldx(d uint8, o int16) a    { return a{op: 0x79, dst: d, src: 10, off: o} }
func jeq(d uint8, to string) a  { return a{op: 0x15, dst: d, jmp: to} }
func helper(id int32) a         { return a{op: 0x85, imm: id} }
func call(to string) a          { return a{op: 0x85, src: 1, call: to} }
func mapfd(d uint8, fd int32) a { return a{op: 0x18, dst: d, src: 1, imm: fd} }
func exit() a                   { return a{op: 0x95} }
func (x a) at(label string) a   { x.label = label; return x }
func (x a) begins(fn string) a  { x.fn = fn; return x }

// assemble returns the wire bytes and func_info for prog; ids maps
// function names to BTF type ids.
func assemble(t *testing.T, prog []a, ids map[string]uint32) (insns, fi []byte) {
	t.Helper()
	raw, labels := 0, map[string]int{}
	pos := make([]int, len(prog))
	for i, x := range prog {
		pos[i] = raw
		for _, l := range []string{x.label, x.fn} {
			if l != "" {
				labels[l] = raw
			}
		}
		raw++
		if x.op == 0x18 {
			raw++
		}
	}
	le := binary.LittleEndian
	for i, x := range prog {
		if x.jmp != "" {
			x.off = int16(labels[x.jmp] - pos[i] - 1)
		}
		if x.call != "" {
			x.imm = int32(labels[x.call] - pos[i] - 1)
		}
		s := make([]byte, 8)
		s[0], s[1] = x.op, x.dst|x.src<<4
		le.PutUint16(s[2:], uint16(x.off))
		le.PutUint32(s[4:], uint32(x.imm))
		insns = append(insns, s...)
		if x.op == 0x18 {
			s2 := make([]byte, 8)
			le.PutUint32(s2[4:], uint32(x.hi))
			insns = append(insns, s2...)
		}
		if x.fn != "" {
			r := make([]byte, 8)
			le.PutUint32(r, uint32(pos[i]))
			le.PutUint32(r[4:], ids[x.fn])
			fi = append(fi, r...)
		}
	}
	return insns, fi
}

// btfFuncs builds a BTF blob: type 1 = FUNC_PROTO, then one FUNC per name
// (ids 2, 3, ...).
func btfFuncs(names ...string) ([]byte, map[string]uint32) {
	le := binary.LittleEndian
	strs := []byte{0}
	var types []byte
	put := func(v ...uint32) {
		for _, x := range v {
			types = le.AppendUint32(types, x)
		}
	}
	put(0, 13<<24, 0) // FUNC_PROTO, vlen 0, returns void
	ids := map[string]uint32{}
	for i, n := range names {
		put(uint32(len(strs)), 12<<24, 1)
		strs = append(append(strs, n...), 0)
		ids[n] = uint32(i + 2)
	}
	hdr := make([]byte, 24)
	le.PutUint16(hdr, 0xeb9f)
	hdr[2] = 1
	le.PutUint32(hdr[4:], 24)
	le.PutUint32(hdr[12:], uint32(len(types)))
	le.PutUint32(hdr[16:], uint32(len(types)))
	le.PutUint32(hdr[20:], uint32(len(strs)))
	return append(append(hdr, types...), strs...), ids
}

type pair struct {
	o, t  []a
	kappa []int
	floor int16
}

func (p pair) capture(t *testing.T) *Capture {
	t.Helper()
	var names []string
	for _, x := range append(slices.Clone(p.o), p.t...) {
		if x.fn != "" && !slices.Contains(names, x.fn) {
			names = append(names, x.fn)
		}
	}
	blob, ids := btfFuncs(names...)
	oi, ofi := assemble(t, p.o, ids)
	ti, tfi := assemble(t, p.t, ids)
	c := &Capture{Format: 1, OriginalInsnsHex: hex.EncodeToString(oi), OriginalFuncInfoHex: hex.EncodeToString(ofi),
		TransformedInsnsHex: hex.EncodeToString(ti), TransformedFuncInfoHex: hex.EncodeToString(tfi), TransformedBTFHex: hex.EncodeToString(blob)}
	for _, x := range p.o {
		if x.fn != "" {
			c.Floors = append(c.Floors, Floor{Name: x.fn, Floor: p.floor})
		}
	}
	c.Hints.Certificate = &struct {
		Original []int `json:"original"`
	}{Original: p.kappa}
	return c
}

// sitePair: an entry prologue, a lookup site with prelude and postlude, and
// a hook; an original branch to the helper call must land on the prelude.
func sitePair() pair {
	o := []a{
		jeq(1, "call").begins("main"),
		mov(2, 10), addi(2, -4), mapfd(1, 3),
		helper(1).at("call"),
		exit(),
	}
	t := []a{
		stx(-16, 1).begins("main"), // prologue
		jeq(1, "pl"),
		mov(2, 10), addi(2, -4), mapfd(1, 3),
		stx(-24, 2).at("pl"), // prelude
		helper(1),
		stx(-32, 0), jeq(0, "restore"), ldx(1, -16), mov(4, 0), call("hook"), // postlude
		ldx(0, -32).at("restore"),
		exit(),
		movi(0, 0).begins("hook"), exit(),
	}
	return pair{o: o, t: t, kappa: []int{1, 2, 3, 4, 6, 13}, floor: -8}
}

// wrapperPair: the helper call is replaced by `call W`; W holds it once.
func wrapperPair() pair {
	o := []a{mov(2, 10).begins("main"), addi(2, -4), mapfd(1, 3), helper(1), exit()}
	t := []a{
		mov(2, 10).begins("main"), addi(2, -4), mapfd(1, 3),
		ldx(4, -16), call("w"), // WP, `call W`
		exit(),
		mov(6, 4).begins("w"), helper(1), mov(8, 0), jeq(0, "out"), mov(1, 6), call("hook"), mov(0, 8).at("out"), exit(),
		movi(0, 0).begins("hook"), exit(),
	}
	return pair{o: o, t: t, kappa: []int{0, 1, 2, 4, 5}, floor: -8}
}

// passPair: a callee with a pass prologue and a pass load before the call.
func passPair() pair {
	o := []a{
		mov(6, 1).begins("main"), jeq(6, "c"), movi(1, 7), call("sub").at("c"), exit(),
		movi(0, 0).begins("sub"), exit(),
	}
	t := []a{
		stx(-24, 1).begins("main"), mov(6, 1), jeq(6, "pl"), movi(1, 7),
		ldx(5, -24).at("pl"), call("sub"), exit(),
		stx(-24, 5).begins("sub"), movi(0, 0), exit(),
	}
	return pair{o: o, t: t, kappa: []int{1, 2, 3, 5, 6, 8, 9}, floor: -16}
}

type win struct {
	kind              string
	start, end, centr int
}

func windows(l *Layout) []win {
	var ws []win
	for _, w := range l.Windows {
		ws = append(ws, win{w.Kind, w.Start, w.End, w.Center})
	}
	return ws
}

func TestWindowsSite(t *testing.T) {
	l, err := Analyze(sitePair().capture(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []win{{"prologue", 0, 1, -1}, {"site", 5, 13, 6}, {"hook", 14, 16, -1}}
	if got := windows(l); !slices.Equal(got, want) {
		t.Fatalf("windows %v, want %v", got, want)
	}
	cw := l.CoreWindow(l.Windows[1])
	if len(cw.Insns) != 8 || cw.Center != 1 || cw.Floor != -8 || !cw.HasFloor || cw.Callee != nil {
		t.Fatalf("core window %+v", cw)
	}
	if hw := l.CoreWindow(l.Windows[2]); hw.HasFloor {
		t.Fatal("hook window has a floor")
	}
}

func TestWindowsWrapper(t *testing.T) {
	l, err := Analyze(wrapperPair().capture(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []win{{"site", 3, 5, 4}, {"hook", 14, 16, -1}}
	if got := windows(l); !slices.Equal(got, want) {
		t.Fatalf("windows %v, want %v", got, want)
	}
	if cw := l.CoreWindow(l.Windows[0]); len(cw.Callee) != 8 || cw.Callee[1].Op != 0x85 {
		t.Fatalf("wrapper body %v", cw.Callee)
	}
}

func TestWindowsPass(t *testing.T) {
	l, err := Analyze(passPair().capture(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []win{{"prologue", 0, 1, -1}, {"gap", 4, 5, -1}, {"prologue", 7, 8, -1}}
	if got := windows(l); !slices.Equal(got, want) {
		t.Fatalf("windows %v, want %v", got, want)
	}
}

// Each mutation must fail structurally at the named stage.
func TestStructureRejects(t *testing.T) {
	type mut struct {
		name, stage string
		base        func() pair
		edit        func(*pair)
	}
	ins := func(p *pair, at int, x a) {
		p.t = slices.Insert(slices.Clone(p.t), at, x)
		for i := range p.kappa {
			if p.kappa[i] >= at {
				p.kappa[i]++
			}
		}
	}
	muts := []mut{
		{"κ hint shifted by one", "kappa", sitePair, func(p *pair) { p.kappa[4]++ }},
		{"κ hint too short", "kappa", sitePair, func(p *pair) { p.kappa = p.kappa[:5] }},
		{"κ not increasing", "kappa", sitePair, func(p *pair) { p.kappa[1], p.kappa[2] = p.kappa[2], p.kappa[1] }},
		{"original imm changed", "kappa", sitePair, func(p *pair) { p.t[3].imm = -8 }},
		{"map fd changed", "kappa", sitePair, func(p *pair) { p.t[4].imm = 4 }},
		{"helper id changed", "kappa", sitePair, func(p *pair) { p.t[6].imm = 2 }},
		{"branch lands on κ(t), skipping the prelude", "edges", sitePair, func(p *pair) { p.t[1].jmp = ""; p.t[1].off = 5 }},
		{"branch lands in the prologue's successor", "edges", sitePair, func(p *pair) { p.t[1].jmp = ""; p.t[1].off = 3 }},
		{"inserted instruction after the last exit", "windows", sitePair, func(p *pair) { ins(p, 14, movi(0, 0)) }},
		{"hook never called", "calls", sitePair, func(p *pair) { p.t[11] = mov(0, 0) }},
		{"call from a window to the wrapper", "calls", wrapperPair, func(p *pair) { ins(p, 5, call("w")) }},
		{"wrapper holds the helper twice", "kappa", wrapperPair, func(p *pair) { ins(p, 8, helper(1)) }},
		{"wrapper holds the helper zero times", "kappa", wrapperPair, func(p *pair) { p.t[7] = movi(0, 0) }},
		{"pass call relocated to the wrong function", "kappa", passPair, func(p *pair) {
			p.t = append(p.t, movi(0, 1).begins("other"), exit())
			p.t[5].call = "other"
		}},
		{"original function missing", "funcs", passPair, func(p *pair) { p.t[7].fn = "renamed" }},
		{"inserted run between two helper calls", "windows", func() pair {
			return pair{o: []a{helper(5).begins("main"), helper(5), exit()}, t: []a{helper(5).begins("main"), stx(-16, 0), helper(5), exit()}, kappa: []int{0, 2, 3}, floor: -8}
		}, nil},
		{"floor above zero", "floors", sitePair, func(p *pair) { p.floor = 8 }},
	}
	for _, m := range muts {
		t.Run(m.name, func(t *testing.T) {
			p := m.base()
			p.kappa = slices.Clone(p.kappa)
			p.t = slices.Clone(p.t)
			if m.edit != nil {
				m.edit(&p)
			}
			_, err := Analyze(p.capture(t))
			var se *StructError
			if !errors.As(err, &se) || se.Stage != m.stage {
				t.Fatalf("got %v, want stage %s", err, m.stage)
			}
		})
	}
}

func TestFuncInfoAndBTF(t *testing.T) {
	blob, _ := btfFuncs("main", "hook")
	names, err := ParseBTFFuncs(blob)
	if err != nil || names[2].Name != "main" || names[3].Name != "hook" || len(names) != 2 {
		t.Fatalf("names %v %v", names, err)
	}
	bad := slices.Clone(blob)
	bad[24+4+3] = 20 // first type's kind -> 20 (unknown)
	if _, err := ParseBTFFuncs(bad); err == nil {
		t.Error("unknown BTF kind accepted")
	}
	if _, err := ParseBTFFuncs(blob[:30]); err == nil {
		t.Error("truncated BTF accepted")
	}
	// A FUNC_PROTO with parameters ctx, key, value and a FUNC of it.
	le := binary.LittleEndian
	var types []byte
	for _, v := range []uint32{0, 13<<24 | 3, 0, 1, 0, 5, 0, 9, 0, 15, 12 << 24, 1} {
		types = le.AppendUint32(types, v)
	}
	strs := []byte("\x00ctx\x00key\x00value\x00hook\x00")
	hdr := make([]byte, 24)
	le.PutUint16(hdr, 0xeb9f)
	hdr[2] = 1
	le.PutUint32(hdr[4:], 24)
	le.PutUint32(hdr[12:], uint32(len(types)))
	le.PutUint32(hdr[16:], uint32(len(types)))
	le.PutUint32(hdr[20:], uint32(len(strs)))
	fs, err := ParseBTFFuncs(append(append(hdr, types...), strs...))
	if err != nil || fs[2].Name != "hook" || !slices.Equal(fs[2].Params, []string{"ctx", "key", "value"}) {
		t.Fatalf("funcs %v %v", fs, err)
	}
	if _, err := ParseFuncInfo([]byte{1, 0, 0, 0, 2, 0, 0, 0}); err == nil {
		t.Error("func_info not starting at 0 accepted")
	}
	if _, err := ParseFuncInfo([]byte{0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0}); err == nil {
		t.Error("non-increasing func_info accepted")
	}
	// func_info pointing into the second slot of ld_imm64, or at a FUNC_PROTO.
	for name, edit := range map[string]func(c *Capture){
		"insn_off inside ld_imm64": func(c *Capture) { c.TransformedFuncInfoHex = "00000000020000000500000003000000" },
		"type id of a FUNC_PROTO":  func(c *Capture) { c.OriginalFuncInfoHex = "0000000001000000" },
		"no original func_info":    func(c *Capture) { c.OriginalFuncInfoHex = "" },
	} {
		c := sitePair().capture(t)
		edit(c)
		var se *StructError
		if _, err := Analyze(c); !errors.As(err, &se) || se.Stage != "funcs" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func runFile(t *testing.T, c *Capture) Result {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	r := Run(path)
	if r.Counts.Disagree != 0 {
		t.Errorf("the Dafny and Go cores disagree on %d windows: %+v", r.Counts.Disagree, r.Windows)
	}
	return r
}

// Identity rewrite: no windows, structure OK, validated. Any
// failing window makes the load not validated.
func TestRunAggregation(t *testing.T) {
	o := sitePair().o
	id := pair{o: o, t: o, kappa: []int{0, 1, 2, 3, 4, 5}, floor: -8}
	if r := runFile(t, id.capture(t)); !r.Validated || !r.Structure.OK || r.Counts.Windows != 0 {
		t.Fatalf("identity: %+v", r)
	}
	r := runFile(t, sitePair().capture(t))
	if !r.Validated || !r.Structure.OK || r.Counts.Windows != 3 || r.Counts.Validated != 3 {
		t.Fatalf("site: %+v", r)
	}
	clob := sitePair()
	clob.t = slices.Clone(clob.t)
	clob.t[10] = mov(6, 0) // C2: the postlude writes r6
	r = runFile(t, clob.capture(t))
	if r.Validated || !r.Structure.OK || r.Counts.NotValidated != 1 || r.Windows[1].Rule != "C2" {
		t.Fatalf("site with r6 written: %+v", r)
	}
	bad := sitePair()
	bad.kappa = slices.Clone(bad.kappa)
	bad.kappa[0] = 0
	if r := runFile(t, bad.capture(t)); r.Validated || r.Structure.OK || r.Structure.KappaOK || r.Structure.Stage != "kappa" {
		t.Fatalf("bad κ: %+v", r)
	}
	if r := Run(filepath.Join(t.TempDir(), "missing.json")); r.Validated || r.Structure.OK {
		t.Fatalf("missing file: %+v", r)
	}
}

// RB binds the hook parameters named key and value. A value copied to the
// stack right before the call (copyBlock) is bound as the copy's address;
// a lone load through r0 is not a copy.
func TestBinds(t *testing.T) {
	ld := func(d, s uint8, o int16) core.Insn { return core.Insn{Op: 0x79, Dst: d, Src: s, Off: o} }
	st := func(o int16, s uint8) core.Insn { return core.Insn{Op: 0x7b, Dst: 10, Src: s, Off: o} }
	call := core.Insn{Op: core.OpCall, Src: 1}
	mk := func(body ...core.Insn) *Layout {
		xs := append(append(body, call), core.Insn{Op: core.OpExit}, core.Insn{Op: 0xb7}, core.Insn{Op: core.OpExit})
		for i := range xs {
			xs[i].Raw = i
		}
		h := len(body)
		xs[h].Imm = 1 // to the hook at h+2
		return &Layout{T: xs, TFuncs: []Func{{Name: "p", Start: 0, End: h + 2},
			{Name: "hook", Params: []string{"ctx", "site", "key", "value"}, Sizes: []int{24, 0, 4, 16}, Start: h + 2, End: h + 4, Inserted: true}}}
	}
	copy16 := []core.Insn{ld(1, 0, 0), st(-48, 1), ld(1, 0, 8), st(-40, 1), ld(3, 10, -24), {Op: 0xbf, Dst: 4, Src: 10}, {Op: 0x07, Dst: 4, Imm: -48}}
	for _, c := range []struct {
		name string
		body []core.Insn
		want core.Binding
	}{
		{"plain", []core.Insn{{Op: 0xbf, Dst: 4}, ld(3, 10, -24)}, core.Binding{Key: 3, Value: 4, Hit: true}},
		{"copy", copy16, core.Binding{Key: 3, Value: 4, Copy: true, Off: -48, Hit: true}},
		{"one load through r0 is no copy", []core.Insn{ld(4, 0, 0), ld(3, 10, -24)}, core.Binding{Key: 3, Value: 4, Hit: true}},
		{"copy of 8 of 16 bytes", append([]core.Insn{ld(1, 0, 0), st(-48, 1)}, copy16[4:]...), core.Binding{Key: 3, Value: 4, Hit: true}},
		{"copy with a gap", append([]core.Insn{ld(1, 0, 0), st(-48, 1), ld(1, 0, 8), st(-32, 1)}, copy16[4:]...), core.Binding{Key: 3, Value: 4, Hit: true}},
		{"store after the copy", append(slices.Clone(copy16), st(-48, 3)), core.Binding{Key: 3, Value: 4, Hit: true}},
		{"r0 written after the copy", append(slices.Clone(copy16), core.Insn{Op: 0xbf, Dst: 0, Src: 10}), core.Binding{Key: 3, Value: 4, Hit: true}},
		{"jump into the copy", append([]core.Insn{{Op: 0x15, Dst: 0, Off: 2}}, copy16...), core.Binding{Key: 3, Value: 4, Hit: true}},
	} {
		l := mk(c.body...)
		h := len(c.body)
		if b := l.binds(0, h+2); len(b) != 1 || b[h] != c.want {
			t.Errorf("%s: binds %v, want %v at %d", c.name, b, c.want, h)
		}
	}
	l := mk(copy16...)
	l.TFuncs[1].Params = []string{"ctx", "k", "v"}
	if b := l.binds(0, len(copy16)+2); len(b) != 0 {
		t.Errorf("other names: binds %v", b)
	}
}

func kfunc(id int32, off int16) a { return a{op: 0x85, src: 2, off: off, imm: id} }
func movw(d uint8, v int32) a     { return a{op: 0xb4, dst: d, imm: v} }

// callA: the result-only sequence around c (ctx at r10-8, result at r10-16).
func callA(c a) pair {
	o := []a{mov(6, 1).begins("main"), c, exit()}
	t := []a{
		stx(-8, 1).begins("main"), mov(6, 1), c,
		stx(-16, 0), ldx(1, -8), movw(2, 1), mov(3, 0), call("hook"), ldx(0, -16), // postlude
		exit(),
		movi(0, 0).begins("hook"), exit(),
	}
	return pair{o: o, t: t, kappa: []int{1, 2, 9}, floor: 0}
}

// callB: the argument-and-result sequence around c, saving r2 (ctx at
// r10-72, argument at r10-80, result at r10-88, below the floor -64).
func callB(c a) pair {
	o := []a{mov(6, 1).begins("main"), mov(2, 10), addi(2, -64), movi(3, 64), movi(4, 0), mov(1, 6), c, exit()}
	t := []a{
		stx(-72, 1).begins("main"), mov(6, 1), mov(2, 10), addi(2, -64), movi(3, 64), movi(4, 0), mov(1, 6),
		stx(-80, 2), // prelude
		c,
		stx(-88, 0), ldx(1, -72), movw(2, 6), ldx(3, -80), mov(4, 0), call("hook"), ldx(0, -88), // postlude
		exit(),
		movi(0, 0).begins("hook"), exit(),
	}
	return pair{o: o, t: t, kappa: []int{1, 2, 3, 4, 5, 6, 8, 16}, floor: -64}
}

func rejectedBy(r Result) []string {
	var got []string
	for _, w := range r.Windows {
		if !w.Validated {
			got = append(got, w.Rule)
		}
	}
	return got
}

// Both sequences validate at a helper and at a kfunc centre (one with a
// module BTF), as kind site, in both cores (runFile fails on a
// disagreement). A kfunc centre is shown to the cores as a helper call.
func TestCallSequences(t *testing.T) {
	for name, p := range map[string]pair{
		"A at helper 5": callA(helper(5)), "B at helper 69": callB(helper(69)),
		"A at a kfunc": callA(kfunc(60001, 0)), "B at a module kfunc": callB(kfunc(1, 1)),
	} {
		r := runFile(t, p.capture(t))
		if !r.Validated || r.Counts.Windows != 3 || r.Windows[1].CoreKind != core.KindSite {
			t.Errorf("%s: %+v", name, r)
		}
	}
	l, err := Analyze(callB(kfunc(1, 1)).capture(t))
	if err != nil {
		t.Fatal(err)
	}
	cw := l.CoreWindow(l.Windows[1])
	if x := cw.Insns[cw.Center]; !x.IsHelperCall() || x.Imm != 1 || x.Off != 0 || !l.T[l.Windows[1].Center].IsKfuncCall() || cw.Bind != nil {
		t.Errorf("centre %v, T %v, binds %v", x, l.T[l.Windows[1].Center], cw.Bind)
	}
}

// Planted faults at kfunc centres. A kfunc whose BTF id is 12, the helper
// id of bpf_tail_call, reaches the cores as call 12 and is never validated:
// rule site refuses a site window whose centre is the tail call before any
// obligation is checked, so the fault is never looked at. Were the window
// made site-P4 instead, its r0 would be free and the missing reload would be
// accepted.
func TestCallSequencesPlanted(t *testing.T) {
	noR0 := callB(kfunc(1, 1))
	noR0.t = slices.Clone(noR0.t)
	noR0.t[15] = movi(0, 0)
	clobbered := callB(kfunc(1, 1))
	clobbered.t = slices.Clone(clobbered.t)
	clobbered.t[7] = addi(2, 8) // the argument register changed before the call
	tail := callA(kfunc(12, 0))
	tail.t = slices.Clone(tail.t)
	tail.t[8] = mov(0, 0) // no r0 reload: r0 is what the hook returned
	for _, c := range []struct {
		name, rule string
		p          pair
	}{{"no R0 restore", "R0", noR0}, {"argument register clobbered", "R15", clobbered}, {"kfunc centre with immediate 12", "site", tail},
		{"correct sequence at a kfunc with immediate 12", "site", callA(kfunc(12, 0))}} {
		r := runFile(t, c.p.capture(t))
		if got := rejectedBy(r); r.Validated || !slices.Equal(got, []string{c.rule}) {
			t.Errorf("%s: rejected by %v, want [%s]: %+v", c.name, got, c.rule, r.Windows)
		}
	}
}

// Window cutting next to a kfunc call: a kfunc centres a site only when
// neither original neighbour is a call; otherwise each run keeps the cut it
// had before kfunc centres.
func TestKfuncCutting(t *testing.T) {
	post := []a{stx(-16, 0), ldx(1, -8), movw(2, 1), mov(3, 0), call("hook"), ldx(0, -16)}
	hook := []a{movi(0, 0).begins("hook"), exit()}
	for _, c := range []struct {
		name string
		p    pair
		want []win
		kind string // CoreKind of the window that is not a prologue or hook
	}{
		{"helper-run-kfunc", pair{
			o:     []a{mov(6, 1).begins("main"), helper(5), kfunc(60001, 0), exit()},
			t:     slices.Concat([]a{stx(-8, 1).begins("main"), mov(6, 1), helper(5)}, post, []a{kfunc(60001, 0), exit()}, hook),
			kappa: []int{1, 2, 9, 10}, floor: 0,
		}, []win{{"prologue", 0, 1, -1}, {"site", 2, 9, 2}, {"hook", 11, 13, -1}}, core.KindSite},
		{"kfunc-run-helper", pair{
			o:     []a{mov(6, 1).begins("main"), kfunc(60001, 0), helper(5), exit()},
			t:     slices.Concat([]a{stx(-8, 1).begins("main"), mov(6, 1), kfunc(60001, 0), stx(-24, 6), helper(5)}, post, []a{exit()}, hook),
			kappa: []int{1, 2, 4, 11}, floor: 0,
		}, []win{{"prologue", 0, 1, -1}, {"site", 3, 11, 4}, {"hook", 12, 14, -1}}, core.KindSite},
		{"kfunc-run-pseudo-call", pair{
			o: []a{mov(6, 1).begins("main"), kfunc(60001, 0), call("sub"), exit(), movi(0, 0).begins("sub"), exit()},
			t: []a{stx(-24, 1).begins("main"), mov(6, 1), kfunc(60001, 0), ldx(5, -24), call("sub"), exit(),
				stx(-24, 5).begins("sub"), movi(0, 0), exit()},
			kappa: []int{1, 2, 4, 5, 7, 8}, floor: -16,
		}, []win{{"prologue", 0, 1, -1}, {"gap", 3, 4, -1}, {"prologue", 6, 7, -1}}, core.KindPassLoad},
		{"kfunc-run-other", callA(kfunc(60001, 0)), []win{{"prologue", 0, 1, -1}, {"site", 2, 9, 2}, {"hook", 10, 12, -1}}, core.KindSite},
	} {
		l, err := Analyze(c.p.capture(t))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := windows(l); !slices.Equal(got, c.want) {
			t.Errorf("%s: windows %v, want %v", c.name, got, c.want)
		}
		if k := l.windowKind(l.Windows[1]); k != c.kind {
			t.Errorf("%s: kind %s, want %s", c.name, k, c.kind)
		}
		if r := runFile(t, c.p.capture(t)); !r.Validated {
			t.Errorf("%s: %+v", c.name, r)
		}
	}
}

// A call centre at the first instruction of a function: code inserted
// before it could be the function's prologue or the call's prelude, so a
// helper or a hooked kfunc centre (a run follows it) there is refused with
// stage windows. A kfunc that starts its function with nothing inserted
// before it, that is next to another call and so centres no site, or that
// no run follows (unhooked) keeps its cut: the code before it is the
// prologue.
func TestCallAtFunctionStart(t *testing.T) {
	post := []a{stx(-16, 0), ldx(1, -8), movw(2, 1), mov(3, 0), call("hook"), ldx(0, -16)}
	hook := []a{movi(0, 0).begins("hook"), exit()}
	atMain := func(c a) pair {
		return pair{
			o:     []a{c.begins("main"), exit()},
			t:     slices.Concat([]a{stx(-8, 1).begins("main"), c}, post, []a{exit()}, hook),
			kappa: []int{1, 8}, floor: 0,
		}
	}
	argStoreAtSub := func(c a) pair {
		return pair{
			o: []a{mov(6, 1).begins("main"), call("sub"), exit(), c.begins("sub"), exit()},
			t: []a{stx(-8, 1).begins("main"), mov(6, 1), call("sub"), exit(),
				stx(-24, 2).begins("sub"), c, exit()},
			kappa: []int{1, 2, 3, 5, 6}, floor: -16,
		}
	}
	for _, c := range []struct {
		name string
		p    pair
	}{
		{"helper at main", atMain(helper(5))},
		{"kfunc at main", atMain(kfunc(60001, 0))},
		{"helper at sub after an argument store", argStoreAtSub(helper(5))},
	} {
		_, err := Analyze(c.p.capture(t))
		var se *StructError
		if !errors.As(err, &se) || se.Stage != "windows" || !strings.Contains(err.Error(), "not separable") {
			t.Errorf("%s: got %v, want stage windows, not separable", c.name, err)
		}
	}
	for _, c := range []struct {
		name string
		p    pair
		want []win
	}{
		{"kfunc starts sub, nothing inserted", pair{
			o:     []a{mov(6, 1).begins("main"), call("sub"), exit(), kfunc(60001, 0).begins("sub"), exit()},
			t:     []a{mov(6, 1).begins("main"), call("sub"), exit(), kfunc(60001, 0).begins("sub"), exit()},
			kappa: []int{0, 1, 2, 3, 4}, floor: 0,
		}, nil},
		{"kfunc at main before a helper", pair{
			o:     []a{kfunc(60001, 0).begins("main"), helper(5), exit()},
			t:     slices.Concat([]a{stx(-8, 1).begins("main"), kfunc(60001, 0), helper(5)}, post, []a{exit()}, hook),
			kappa: []int{1, 2, 9}, floor: 0,
		}, []win{{"prologue", 0, 1, -1}, {"site", 2, 9, 2}, {"hook", 10, 12, -1}}},
		{"unhooked kfunc at sub after an argument store", argStoreAtSub(kfunc(60001, 0)), []win{{"prologue", 0, 1, -1}, {"prologue", 4, 5, -1}}},
		// The transformer spills ctx before the entry's first instruction, an
		// unhooked kfunc here, and hooks a helper later.
		{"unhooked kfunc at main, hooked helper later", pair{
			o: []a{kfunc(60001, 0).begins("main"), mov(6, 0), helper(7), exit()},
			t: slices.Concat([]a{stx(-8, 1).begins("main"), kfunc(60001, 0), mov(6, 0), helper(7)},
				[]a{stx(-16, 0), ldx(1, -8), movw(2, 3), mov(3, 0), call("hook"), ldx(0, -16)}, []a{exit()}, hook),
			kappa: []int{1, 2, 3, 10}, floor: 0,
		}, []win{{"prologue", 0, 1, -1}, {"site", 3, 10, 3}, {"hook", 11, 13, -1}}},
	} {
		l, err := Analyze(c.p.capture(t))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := windows(l); !slices.Equal(got, c.want) {
			t.Errorf("%s: windows %v, want %v", c.name, got, c.want)
		}
		if strings.HasPrefix(c.name, "unhooked kfunc at main") {
			if r := runFile(t, c.p.capture(t)); !r.Validated {
				t.Errorf("%s: not validated, rejected by %v", c.name, rejectedBy(r))
			}
		}
	}
}

// A function that receives the context from its caller and calls
// bpf_get_prandom_u32 (helper 7, no arguments): r5 = r_G is not live at
// its entry, so the pass load is validated (S10).
func TestPassCalleeCallsHelper7(t *testing.T) {
	p := pair{
		o: []a{
			mov(6, 1).begins("main"), jeq(6, "c"), movi(1, 7), call("sub").at("c"), exit(),
			movi(0, 0).begins("sub"), helper(7), exit(),
		},
		t: []a{
			stx(-24, 1).begins("main"), mov(6, 1), jeq(6, "pl"), movi(1, 7),
			ldx(5, -24).at("pl"), call("sub"), exit(),
			stx(-24, 5).begins("sub"), movi(0, 0), helper(7), exit(),
		},
		kappa: []int{1, 2, 3, 5, 6, 8, 9, 10}, floor: -16,
	}
	if r := runFile(t, p.capture(t)); !r.Validated || r.Counts.ByKind["gap"] != 1 {
		t.Errorf("%+v", r)
	}
}

// A function that receives the context from its caller and calls
// bpf_get_current_pid_tgid (helper 14, none of the 20 ids the validator
// listed by hand before its table was generated), with a result-only hook
// after the call: helper 14 reads no argument, so r5 = r_G is not live at
// the function's entry and both the pass load and the site validate.
func TestPassCalleeSiteAtHelper14(t *testing.T) {
	p := pair{
		o: []a{
			mov(6, 1).begins("main"), jeq(6, "c"), movi(1, 7), call("sub").at("c"), exit(),
			movi(0, 0).begins("sub"), helper(14), exit(),
		},
		t: []a{
			stx(-24, 1).begins("main"), mov(6, 1), jeq(6, "pl"), movi(1, 7),
			ldx(5, -24).at("pl"), call("sub"), exit(),
			stx(-24, 5).begins("sub"), movi(0, 0), helper(14),
			stx(-32, 0), ldx(1, -24), movw(2, 6), mov(3, 0), call("hook"), ldx(0, -32), // postlude
			exit(),
			movi(0, 0).begins("hook"), exit(),
		},
		kappa: []int{1, 2, 3, 5, 6, 8, 9, 16}, floor: -16,
	}
	r := runFile(t, p.capture(t))
	if !r.Validated || r.Counts.ByKind["gap"] != 1 || r.Counts.ByKind["site"] != 1 {
		t.Errorf("%+v", r)
	}
}
