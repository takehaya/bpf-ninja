package resolve

import (
	"reflect"
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
)

// TestDropEmptyLayers pins that a `{0,0}` layer resolves to the chain
// without it: the same protocols, each dispatched off the same parent.
func TestDropEmptyLayers(t *testing.T) {
	for expr, plain := range map[string]string{
		"eth/mpls{0,0}/mpls/ipv4/tcp":              "eth/mpls/ipv4/tcp",
		"eth/mpls{0}/mpls/ipv4/tcp":                "eth/mpls/ipv4/tcp",
		"eth/mpls[label == 99]{0,0}/mpls/ipv4/tcp": "eth/mpls/ipv4/tcp",
		"eth/ipv4/tcp{0,0}":                        "eth/ipv4",
		"eth/ipv4/ipv4{0,0}/tcp":                   "eth/ipv4/tcp",
		"eth/mpls?/mpls{0,0}/ipv4/tcp":             "eth/mpls?/ipv4/tcp",
		"eth/vlan{0,0}/vlan{0,0}/ipv4/tcp":         "eth/ipv4/tcp",
		"eth/(vlan|qinq)/vlan{0,0}/ipv4/tcp":       "eth/(vlan|qinq)/ipv4/tcp",
		"eth/vlan{0,0}/(ipv4|ipv6)/tcp":            "eth/(ipv4|ipv6)/tcp",
	} {
		got, want := resolveOK(t, expr, nil), resolveOK(t, plain, nil)
		if len(got.Layers) != len(want.Layers) {
			t.Errorf("%s: %d layers; want %d like %s", expr, len(got.Layers), len(want.Layers), plain)
			continue
		}
		for i := range got.Layers {
			g, w := got.Layers[i], want.Layers[i]
			if g.DisplayName() != w.DisplayName() || g.LayerPos != i {
				t.Errorf("%s: layer %d is %s at position %d; want %s at %d", expr, i, g.DisplayName(), g.LayerPos, w.DisplayName(), i)
			}
			if !reflect.DeepEqual(g.Dispatch, w.Dispatch) {
				t.Errorf("%s: layer %d dispatch %+v; want %+v", expr, i, g.Dispatch, w.Dispatch)
			}
			for j := range g.Alternation {
				if !reflect.DeepEqual(g.Alternation[j].Dispatch, w.Alternation[j].Dispatch) {
					t.Errorf("%s: member %d of layer %d dispatch %+v; want %+v", expr, j, i, g.Alternation[j].Dispatch, w.Alternation[j].Dispatch)
				}
			}
		}
	}
}

// TestDropEmptyLayersWhere pins that a where atom reading a `{0,0}` layer
// becomes `false` in place (D-003), any()/all() over its stack too, while
// the atoms around it stay.
func TestDropEmptyLayersWhere(t *testing.T) {
	isFalse := func(c *ir.Condition) bool { return c != nil && c.Kind == ast.WAtomBoolLit && !c.BoolLitValue }

	if w := resolveOK(t, "eth/vlan@v{0,0}/ipv4/tcp where v.tci == 100", nil).Where; !isFalse(w) {
		t.Errorf("v.tci == 100: where %+v; want false", w)
	}
	if w := resolveOK(t, "eth/vlan@v{0,0}/ipv4/tcp where not (v.tci == 100)", nil).Where; w.Kind != ast.WNot || !isFalse(w.Inner) {
		t.Errorf("not (v.tci == 100): where %+v; want not false", w)
	}
	w := resolveOK(t, "eth/vlan@v{0,0}/ipv4/tcp where v.tci == 100 or tcp.dport == 80", nil).Where
	if w.Kind != ast.WOr || !isFalse(w.Left) || w.Right.Kind != ast.WAtomArith {
		t.Errorf("v.tci == 100 or tcp.dport == 80: where %+v; want false or the tcp atom", w)
	}
	w = resolveOK(t, "eth/ipv6/srv6@s{0,0}/tcp where any(s.segments.addr == fc00::1) == false", nil).Where
	if w.Kind != ast.WAtomBoolEq || !isFalse(w.BoolL) {
		t.Errorf("any(...) == false: where %+v; want false == false", w)
	}
	p := resolveOK(t, "eth/vlan@v{0,0}/ipv4/tcp capture v + 4 where v.tci == 1", nil)
	if c := p.Captures[0]; c.TargetLayer != p.Layers[0] || c.Extra != 4 || !isFalse(c.Where) {
		t.Errorf("capture v + 4: target %s, extra %d, where %+v; want eth, 4, false", c.TargetLayer.DisplayName(), c.Extra, c.Where)
	}
	if c := resolveOK(t, "eth/(vlan|qinq)/vlan@v{0,0}/ipv4/tcp capture v", nil).Captures[0]; c.Unsupported == "" {
		t.Error("capture of a {0,0} layer after an alternation: want Unsupported")
	}
}

// TestDropEmptyLayersStaticChecks pins that the static rules still see a
// `{0,0}` layer before it is dropped.
func TestDropEmptyLayersStaticChecks(t *testing.T) {
	for expr, want := range map[string]string{
		// It needs an edge from its predecessor, and its follower an edge
		// from the layer before it.
		"eth/ipv4{0,0}/tcp":                "no dispatch constant",
		"eth/ipv4/tcp/vxlan{0,0}":          "no dispatch constant",
		"eth/ipv4/udp/vxlan{0,0}/eth/ipv4": "no dispatch constant",
		// Its brackets are typed, and a bare name counts it.
		"eth/ipv4/tcp[dport in @s]{0,0}":                    "only supported on a mandatory layer",
		"eth/vlan{0,0}/ipv4/tcp where vlan.tci == 1":        "matches no header",
		"eth/mpls{0,0}/mpls/ipv4/tcp where mpls.label == 1": "ambiguous",
	} {
		resolveErr(t, expr, nil, want)
	}
}
