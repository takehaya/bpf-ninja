package regionval

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
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

// RB binds the hook parameters named key and value; a window that copies
// the value through r0 (CopyReadOnly) keeps only its key binding.
func TestBinds(t *testing.T) {
	call := core.Insn{Op: core.OpCall, Src: 1, Imm: 1, Raw: 2} // to T[4]
	l := &Layout{
		T: []core.Insn{{Op: 0xbf, Dst: 4, Src: 0, Raw: 0}, {Op: 0x79, Dst: 3, Src: 10, Off: -24, Raw: 1}, call, {Op: core.OpExit, Raw: 3},
			{Op: 0xb7, Raw: 4}, {Op: core.OpExit, Raw: 5}},
		TFuncs: []Func{{Name: "p", Start: 0, End: 4}, {Name: "hook", Params: []string{"ctx", "site", "key", "value"}, Start: 4, End: 6, Inserted: true}},
	}
	if b := l.binds(0, 4); len(b) != 1 || b[2] != (core.Binding{Key: 3, Value: 4}) {
		t.Errorf("binds %v", b)
	}
	l.T[0] = core.Insn{Op: 0x79, Dst: 1, Src: 0, Raw: 0} // r1 = *(u64 *)(r0 + 0)
	if b := l.binds(0, 4); len(b) != 1 || b[2] != (core.Binding{Key: 3}) {
		t.Errorf("copy: binds %v", b)
	}
	l.TFuncs[1].Params = []string{"ctx", "k", "v"}
	if b := l.binds(0, 4); len(b) != 0 {
		t.Errorf("other names: binds %v", b)
	}
}
