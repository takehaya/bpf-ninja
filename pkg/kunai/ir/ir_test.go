package ir

import (
	"testing"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// TestBuildMinimalProgram exercises a hand-built Program that matches
// what the resolver will produce for "eth/ipv4/tcp[dport==443]". It
// locks in the shape the codegen phase will walk.
func TestBuildMinimalProgram(t *testing.T) {
	ipv4Spec := &vocab.ProtocolSpec{
		Name:       "ipv4",
		HeaderName: "ipv4_h",
		Fields:     []vocab.Field{{Name: "protocol", Bits: 8}},
	}
	tcpSpec := &vocab.ProtocolSpec{
		Name:       "tcp",
		HeaderName: "tcp_h",
		Fields:     []vocab.Field{{Name: "dport", Bits: 16}},
	}
	dispatch := &vocab.DispatchConst{
		Type:   vocab.DispatchField,
		Name:   "TCP_IPV4_PROTOCOL",
		Parent: "ipv4",
		FieldName: "protocol",
		Bits:   8,
		Value:  6,
	}
	ethLayer := &LayerInstance{Spec: &vocab.ProtocolSpec{Name: "eth", HeaderName: "eth_h"}}
	ipv4Layer := &LayerInstance{Spec: ipv4Spec}
	tcpLayer := &LayerInstance{
		Spec:     tcpSpec,
		Dispatch: &DispatchChoice{Type: vocab.DispatchField, Const: dispatch},
		Predicates: []*Predicate{
			{
				Kind:  ast.PredCmp,
				Op:    ast.CmpEq,
				Value: &ast.Value{Kind: ast.ValInt, Int: 443},
				Field: &FieldRef{Field: &tcpSpec.Fields[0]},
			},
		},
	}
	p := &Program{
		Layers: []*LayerInstance{ethLayer, ipv4Layer, tcpLayer},
	}
	if len(p.Layers) != 3 {
		t.Fatalf("layers==%d", len(p.Layers))
	}
	if tcpLayer.Dispatch.Const.Value != 6 {
		t.Errorf("dispatch value = %d, want 6", tcpLayer.Dispatch.Const.Value)
	}
	if tcpLayer.Predicates[0].Field.Field.Name != "dport" {
		t.Errorf("predicate field = %q", tcpLayer.Predicates[0].Field.Field.Name)
	}
}

// TestUnsupportedFlag ensures the Unsupported string field is surfaced
// on every type that a later pass needs to inspect.
func TestUnsupportedFlag(t *testing.T) {
	li := &LayerInstance{Unsupported: "alternation+quantifier"}
	pr := &Predicate{Unsupported: "in operator"}
	cd := &Condition{Unsupported: "flow state"}
	cp := &CaptureClause{Unsupported: "field list"}
	for i, s := range []string{li.Unsupported, pr.Unsupported, cd.Unsupported, cp.Unsupported} {
		if s == "" {
			t.Errorf("field %d missing Unsupported string", i)
		}
	}
}
