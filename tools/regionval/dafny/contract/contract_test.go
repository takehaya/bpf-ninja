package contract

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/tools/regionval/core"
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

var (
	helper = ins(0x85, 0, 0, 0, 1)
	hook   = ins(0x85, 0, 1, 0, 40)
	exit   = ins(0x95, 0, 0, 0, 0)
	stx    = func(b, s byte, o int16) []byte { return ins(0x7b, b, s, o, 0) }
	ldx    = func(d, b byte, o int16) []byte { return ins(0x79, d, b, o, 0) }
	movk   = func(d byte, k int32) []byte { return ins(0xb7, d, 0, 0, k) }
)

const floor = -168

// window decodes raw into a window of kind; every pseudo call is a hook call
// and the centre is the first helper call.
func window(t *testing.T, kind string, raw []byte) core.Window {
	t.Helper()
	xs, err := core.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	w := core.Window{Kind: kind, Insns: xs, Center: -1, Hook: map[int]bool{}, Floor: floor, HasFloor: kind != core.KindHook}
	for i, x := range xs {
		if x.IsHelperCall() && w.Center < 0 {
			w.Center = i
		}
		if x.IsPseudoCall() {
			w.Hook[i] = true
		}
	}
	return w
}

// Validate refuses, before the Dafny core runs, a window whose bytes are not
// the decoded window, a wrapper site without the original call, and an
// unknown kind.
func TestValidateFailsClosed(t *testing.T) {
	site := cat(helper, stx(10, 0, -176), ldx(0, 10, -176))
	w := window(t, core.KindSite, site)
	if v := Validate(w, site, nil, nil); !v.Validated {
		t.Fatalf("site: %+v", v)
	}
	wrap := window(t, core.KindWrap, hook)
	wrap.Center, wrap.Hook = 0, map[int]bool{}
	wrap.Callee, _ = core.Decode(cat(helper, exit))
	wrap.Helper = wrap.Callee[0]
	unknown := window(t, core.KindSite, site)
	unknown.Kind = "site-wrapped-tail-call"
	for _, c := range []struct {
		name                string
		w                   core.Window
		insns, body, helper []byte
	}{
		{"window bytes differ", w, cat(helper, stx(10, 0, -184), ldx(0, 10, -176)), nil, nil},
		{"window bytes short", w, site[:16], nil, nil},
		{"W bytes differ", wrap, hook, cat(helper, movk(0, 0)), helper},
		{"O[i] missing", wrap, hook, cat(helper, exit), nil},
		{"O[i] differs", wrap, hook, cat(helper, exit), ins(0x85, 0, 0, 0, 2)},
		{"unknown kind", unknown, site, nil, nil},
	} {
		v := Validate(c.w, c.insns, c.body, c.helper)
		if v.Validated || v.PC != -1 || !strings.HasPrefix(v.Reason, "contract: ") {
			t.Errorf("%s: %+v", c.name, v)
		}
	}
	if v := Validate(wrap, hook, cat(helper, exit), helper); !v.Validated {
		t.Errorf("wrapper site: %+v", v)
	}
}

// The spec chosen for each kind: an entry prologue may call one hook if it
// restores r1, and a pass load may not store.
func TestSpec(t *testing.T) {
	passLoad := func(w *core.Window) { w.PassPrologue, _ = core.Decode(stx(10, 3, -176)) }
	for _, c := range []struct {
		name string
		kind string
		raw  []byte
		want bool
	}{
		{"entry prologue, hook call, r1 reloaded", core.KindEntry, cat(stx(10, 1, -176), hook, ldx(1, 10, -176)), true},
		{"entry prologue, hook call clobbers r1", core.KindEntry, cat(stx(10, 1, -176), hook), false},
		{"entry prologue, two hook calls", core.KindEntry, cat(stx(10, 1, -176), hook, ldx(1, 10, -176), hook, ldx(1, 10, -176)), false},
		{"pass load", core.KindPassLoad, ldx(3, 10, -176), true},
		{"pass load stores", core.KindPassLoad, cat(ldx(3, 10, -176), stx(10, 3, -184)), false},
	} {
		w := window(t, c.kind, c.raw)
		if c.kind == core.KindPassLoad {
			passLoad(&w)
		}
		if why := Check(w); why != "" {
			t.Fatalf("%s: contract rejects (%s)", c.name, why)
		}
		if v := Validate(w, c.raw, nil, nil); v.Validated != c.want {
			t.Errorf("%s: validated %v, want %v (%s)", c.name, v.Validated, c.want, v.Reason)
		}
	}
}
