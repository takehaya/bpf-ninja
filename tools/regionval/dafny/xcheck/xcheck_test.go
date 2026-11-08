// Cross-check of the Dafny core against the Go core (core.Check) and the
// reference interpreter (interp.Run) on hand-made windows.
package xcheck

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/takehaya/bpf-ninja/tools/regionval/core"
	"github.com/takehaya/bpf-ninja/tools/regionval/dafny/contract"
	rd "github.com/takehaya/bpf-ninja/tools/regionval/dafny/regionvaldafny"
	"github.com/takehaya/bpf-ninja/tools/regionval/interp"
)

func ins(op byte, dst, src byte, off int16, imm int32) []byte {
	b := make([]byte, 8)
	b[0], b[1] = op, dst&0xf|src<<4
	binary.LittleEndian.PutUint16(b[2:], uint16(off))
	binary.LittleEndian.PutUint32(b[4:], uint32(imm))
	return b
}

func cat(xs ...[]byte) (out []byte) {
	for _, x := range xs {
		out = append(out, x...)
	}
	return
}

func ins8(w []byte, pc int, x []byte) []byte { return cat(w[:8*pc], x, w[8*pc:]) }
func rep8(w []byte, pc int, x []byte) []byte { return cat(w[:8*pc], x, w[8*pc+8:]) }

var (
	helper = ins(0x85, 0, 0, 0, 1)
	hook   = ins(0x85, 0, 1, 0, 40)
	exit   = ins(0x95, 0, 0, 0, 0)
	stx    = func(b, s byte, o int16) []byte { return ins(0x7b, b, s, o, 0) }
	ldx    = func(d, b byte, o int16) []byte { return ins(0x79, d, b, o, 0) }
	mov    = func(d, s byte) []byte { return ins(0xbf, d, s, 0, 0) }
	movk   = func(d byte, k int32) []byte { return ins(0xb7, d, 0, 0, k) }
	addk   = func(d byte, k int32) []byte { return ins(0x07, d, 0, 0, k) }
	jeq    = func(d byte, k int32, o int16) []byte { return ins(0x15, d, 0, o, k) }
	ja     = func(o int16) []byte { return ins(0x05, 0, 0, o, 0) }
)

const floor = -168

var site = cat(helper, stx(10, 0, -176), jeq(0, 0, 3), mov(1, 10), addk(1, -176), hook, ldx(0, 10, -176))

// window: regionval Window from raw bytes; centre = first helper call,
// every pseudo call is a hook call.
func window(kind string, raw []byte) (core.Window, bool) {
	xs, err := core.Decode(raw)
	if err != nil {
		return core.Window{}, false
	}
	w := core.Window{Kind: kind, Insns: xs, Center: -1, Hook: map[int]bool{}, Floor: floor, HasFloor: kind != core.KindHook}
	if kind == core.KindPassLoad {
		// pass certificate: G's prologue spills r3 (r_G = r3), nothing live at G's entry
		w.PassPrologue, _ = core.Decode(stx(10, 3, -176))
	}
	for i, x := range xs {
		if x.IsHelperCall() && w.Center < 0 {
			w.Center = i
		}
		if x.IsPseudoCall() {
			w.Hook[i] = true
		}
	}
	return w, true
}

func dafnyVerdict(kind string, raw []byte) bool {
	switch kind {
	case core.KindSite:
		return rd.Validate(raw, rd.SiteSpec(floor)).Validated
	case core.KindEntry:
		return rd.Validate(raw, rd.EntryPrologueSpec(floor)).Validated
	case core.KindCallback:
		return rd.Validate(raw, rd.CallbackPrologueSpec(floor)).Validated
	case core.KindPassLoad: // no store; only r_G (= r3, see window) changes
		return rd.Validate(raw, rd.CustomSpec(floor, []int{3}, false, false, false, false, false, false)).Validated
	case core.KindHook:
		return rd.Validate(raw, rd.HookBodySpec()).Validated
	}
	panic(kind)
}

type tc struct {
	name, kind string
	raw        []byte
}

func cases() []tc {
	S := core.KindSite
	return []tc{
		{"site", S, site},
		{"site no hook", S, cat(helper, stx(10, 0, -176), ldx(0, 10, -176))},
		{"site skip to end on r0==0", S, rep8(site, 2, jeq(0, 0, 4))},
		{"C1 at floor", S, rep8(site, 1, stx(10, 0, -168))},
		{"C1 base r9", S, rep8(site, 1, stx(9, 0, -176))},
		{"C2 r6=r0", S, ins8(site, 6, mov(6, 0))},
		{"C2 r9+=1", S, ins8(site, 1, addk(9, 1))},
		{"C3 stx above floor", S, ins8(site, 1, stx(10, 1, -8))},
		{"C4 backward", S, rep8(site, 2, jeq(0, 0, -1))},
		{"C4 past end", S, rep8(site, 2, jeq(0, 0, 5))},
		{"C5 two hooks", S, ins8(site, 6, hook)},
		{"C5 two helpers", S, ins8(site, 1, helper)},
		{"C6 xor32", S, ins8(site, 1, ins(0xac, 3, 3, 0, 0))},
		{"C6 st", S, ins8(site, 1, ins(0x7a, 10, 0, -176, 0))},
		{"r0 restore removed", S, site[:48]},
		{"r0 restore width w", S, rep8(site, 6, ins(0x61, 0, 10, -176, 0))},
		{"r0 restore skipped", S, ins8(site, 6, ja(1))},
		{"r2=r10 before helper", S, ins8(site, 0, mov(2, 10))},
		{"P1 ok", core.KindEntry, stx(10, 1, -176)},
		{"P1 r1 clobbered", core.KindEntry, cat(stx(10, 1, -176), movk(1, 0))},
		{"P1b ok", core.KindCallback, ldx(0, 6, 8)},
		{"P1b r2", core.KindCallback, ldx(2, 6, 8)},
		{"P9 load ok", core.KindPassLoad, ldx(3, 10, -176)},
		{"P9 load two regs", core.KindPassLoad, cat(ldx(3, 10, -176), movk(4, 0))},
		{"P7 ok", core.KindHook, cat(jeq(1, 0, 1), ldx(2, 1, 0), movk(0, 0), exit)},
		{"P7 store", core.KindHook, cat(stx(10, 1, -8), movk(0, 0), exit)},
		{"P7 no r0=0", core.KindHook, cat(ldx(2, 1, 0), exit)},
		{"P7 r6 written", core.KindHook, cat(ldx(6, 1, 0), movk(0, 0), exit)},
	}
}

func TestVerdictsAgree(t *testing.T) {
	for _, c := range cases() {
		w, ok := window(c.kind, c.raw)
		rv := ok && core.Check(w).Validated
		dv := dafnyVerdict(c.kind, c.raw)
		mark := "agree"
		if rv != dv {
			mark = "DISAGREE"
			t.Errorf("%-28s regionval=%v dafny=%v (%s)", c.name, rv, dv, core.Check(w).Reason)
		}
		t.Logf("%-28s regionval=%-5v dafny=%-5v %s", c.name, rv, dv, mark)
	}
}

// Reference interpreters: regionval/interp.Run and the Dafny ConcreteRun
// produce the same final registers and frame on the same inputs.
func TestInterpretersAgree(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for _, c := range cases() {
		if c.kind == core.KindHook {
			continue // different frame for hook bodies (interp: no floor)
		}
		w, ok := window(c.kind, c.raw)
		if !ok {
			continue
		}
		for it := 0; it < 200; it++ {
			var in interp.Input
			for i := range in.Regs {
				in.Regs[i] = r.Uint64()
			}
			r.Read(in.Stack[0][:])
			om := make([]uint64, 600)
			for i := range om {
				om[i] = r.Uint64()
			}
			in.Oracle = func(i int) uint64 { return om[i] }
			var regs [rd.NRegs]uint64
			copy(regs[:], in.Regs[:])
			regs[10] = interp.Base0
			out, err := interp.Run(w, in)
			fin, kind := rd.ConcreteRun(c.raw, floor, rd.InitState(regs, in.Stack[0]), om, len(c.raw)/8+1)
			if err != nil {
				// interp stops on what it does not model (e.g. a store outside
				// every frame); the Dafny model records the store instead, and
				// its obligations must then fail on this run.
				if _, _, okOb := rd.RunAndCheck(c.raw, rd.SiteSpec(floor), regs, in.Stack[0], om); okOb {
					t.Errorf("%s: interp error %v but Dafny obligations hold", c.name, err)
				}
				break
			}
			if kind != rd.Done {
				t.Errorf("%s: Dafny outcome %d, interp finished", c.name, kind)
				break
			}
			if fin.Regs != out.Regs || fin.Stack != out.Stack || fin.OC != out.Used {
				t.Errorf("%s: final states differ (iteration %d)", c.name, it)
				break
			}
		}
	}
}

// Record binding (rule RB): both cores on site windows whose hook calls
// bind the key and the value, in the forms the rewriter emits, and on
// rewrites that pass the wrong pointer. A window without bindings keeps its
// verdict whatever the hook gets: RB is separate from preservation.
func TestRecordBinding(t *testing.T) {
	jne := func(d byte, k int32, o int16) []byte { return ins(0x55, d, 0, o, k) }
	// key spill, helper, result spill, skip the hook on NULL, ctx, key, value, hook, restore
	auto := cat(stx(10, 2, -176), helper, stx(10, 0, -184), jeq(0, 0, 4), ldx(1, 10, -192), ldx(3, 10, -176), mov(4, 0), hook, ldx(0, 10, -184))
	plain := rep8(rep8(auto, 5, ldx(2, 10, -176)), 6, mov(3, 0)) // HOOK(ctx, key, value)
	// miss-first: the miss hook gets the key, the hit hook key and value
	missFirst := cat(stx(10, 2, -176), helper, stx(10, 0, -184), jne(0, 0, 4), ldx(1, 10, -192), ldx(3, 10, -176), hook, ja(4),
		ldx(1, 10, -192), ldx(3, 10, -176), mov(4, 0), hook, ldx(0, 10, -184))
	generic := cat(stx(10, 2, -176), helper, stx(10, 0, -184), ldx(1, 10, -192), ldx(3, 10, -176), mov(4, 0), hook, ldx(0, 10, -184))
	kv := func(pc, k, v int) map[int]core.Binding { return map[int]core.Binding{pc: {Key: k, Value: v}} }
	// CopyReadOnly: an 8-byte copy of the value at r10-200, its address in r4
	cp := cat(stx(10, 2, -176), helper, stx(10, 0, -184), jeq(0, 0, 7), ldx(1, 0, 0), stx(10, 1, -200), ldx(1, 10, -192), ldx(3, 10, -176),
		mov(4, 10), addk(4, -200), hook, ldx(0, 10, -184))
	cb := map[int]core.Binding{10: {Key: 3, Value: 4, Copy: true, Off: -200}}
	for _, c := range []struct {
		name string
		raw  []byte
		bind map[int]core.Binding
		ok   bool
	}{
		{"auto", auto, kv(7, 3, 4), true},
		{"plain", plain, kv(7, 2, 3), true},
		{"miss-first", missFirst, map[int]core.Binding{6: {Key: 3}, 11: {Key: 3, Value: 4}}, true},
		{"generic, NULL on a miss", generic, kv(6, 3, 4), true},
		{"value = r10 (wrong frame)", rep8(auto, 6, mov(4, 10)), kv(7, 3, 4), false},
		{"value = r10, unbound", rep8(auto, 6, mov(4, 10)), nil, true},
		{"value = key", rep8(auto, 6, ldx(4, 10, -176)), kv(7, 3, 4), false},
		{"key = result slot", rep8(auto, 5, ldx(3, 10, -184)), kv(7, 3, 4), false},
		{"plain, key and value swapped", rep8(rep8(auto, 5, ldx(3, 10, -176)), 6, mov(2, 0)), kv(7, 2, 3), false},
		{"copy", cp, cb, true},
		{"copy, value = r0", rep8(rep8(cp, 8, mov(4, 0)), 9, mov(4, 4)), cb, false},
		{"copy, wrong offset", rep8(cp, 9, addk(4, -192)), cb, false},
		{"copy, r0 changed", rep8(cp, 7, mov(0, 10)), cb, false},
		{"miss-first, miss key from the result slot", rep8(missFirst, 5, ldx(3, 10, -184)), map[int]core.Binding{6: {Key: 3}, 11: {Key: 3, Value: 4}}, false},
	} {
		w, ok := window(core.KindSite, c.raw)
		if !ok {
			t.Fatalf("%s: decode", c.name)
		}
		w.Bind = c.bind
		gv := core.Check(w)
		dv := contract.Validate(w, c.raw, nil, nil)
		if gv.Validated != c.ok || dv.Validated != c.ok || (!c.ok && gv.Rule != "RB") {
			t.Errorf("%s: Go %+v, Dafny %+v, want validated=%v (rule RB if not)", c.name, gv, dv, c.ok)
		}
	}
}
