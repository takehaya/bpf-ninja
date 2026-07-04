package codegen

import (
	"errors"
	"strings"
	"testing"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// qinqSpec mirrors the bundled 802.1ad header shape (4 bytes: tpid +
// ethertype) so alternation tests can pair it with vlan without
// running the full vocab loader.
var (
	qinqFromEthConst = &vocab.DispatchConst{
		Type: vocab.DispatchField, Name: "QINQ_ETH_ETHERTYPE",
		Parent: "eth", FieldName: "ethertype", Bits: 16, Value: 0x88A8,
	}
	qinqSpec = newSpecWithConsts(
		"qinq", "qinq_h",
		[]vocab.Field{
			{Name: "tpid", Bits: 16},
			{Name: "ethertype", Bits: 16},
		},
		*qinqFromEthConst,
	)
)

func TestGenAlternationEmitsSequencedDispatch(t *testing.T) {
	eth := &ir.LayerInstance{Spec: ethSpec}
	vlanAlt := &ir.LayerInstance{
		Spec:     vlanSpecForChain,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: vlanFromEthConst},
	}
	qinqAlt := &ir.LayerInstance{
		Spec:     qinqSpec,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: qinqFromEthConst},
	}
	group := &ir.LayerInstance{Alternation: []*ir.LayerInstance{vlanAlt, qinqAlt}}
	p := &ir.Program{Layers: []*ir.LayerInstance{eth, group}}

	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}

	// Alt 1 (qinq) is the jump target from alt 0's dispatch miss, so
	// the stream must carry `dsl_alt_<index>_1` on some instruction.
	// The group-end label also lands on the final advance.
	sawAlt1, sawEnd := false, false
	for _, ins := range out.Main {
		sym := ins.Symbol()
		if strings.HasPrefix(sym, "dsl_alt_") && strings.HasSuffix(sym, "_1") {
			sawAlt1 = true
		}
		if strings.HasPrefix(sym, "dsl_alt_end_") {
			sawEnd = true
		}
	}
	if !sawAlt1 {
		t.Error("expected dsl_alt_<i>_1 symbol marking the second alternative's entry")
	}
	if !sawEnd {
		t.Error("expected dsl_alt_end_<i> landing on the shared advance")
	}

	// One advance per alt now that P3-12 lifted the uniform-size
	// constraint — each alt block bumps R4 by its own header size
	// inline before falling through to altEnd.
	if got := countOffsetAdvances(out.Main, 4); got != 2 {
		t.Errorf("expected 2 offsetBase advances (one per alt) for the alt group, got %d", got)
	}
}

func TestGenAlternationAcceptsNonUniformSize(t *testing.T) {
	// P3-12: alts of different header sizes (vlan 4B vs ipv4 20B) now
	// compile. Each alt advances R4 by its own size inline; the post-
	// group landing is just a Mov R3,R3 noop. Heterogeneous dispatch
	// is also exercised (vlan dispatches via ethertype=0x8100, ipv4
	// via ethertype=0x0800) — same field, different values, so
	// IsAltDiverged stays false (the next-layer dispatch isn't
	// affected by the disagreement on the alt's *own* parent value).
	eth := &ir.LayerInstance{Spec: ethSpec}
	vlanAlt := &ir.LayerInstance{
		Spec:     vlanSpecForChain,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: vlanFromEthConst},
	}
	ipv4Alt := &ir.LayerInstance{
		Spec:     ipv4Spec,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: ipv4EthertypeConst},
	}
	group := &ir.LayerInstance{Alternation: []*ir.LayerInstance{vlanAlt, ipv4Alt}}
	p := &ir.Program{Layers: []*ir.LayerInstance{eth, group}}

	out, err := Gen(p, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if got := countOffsetAdvances(out.Main, 4); got != 1 {
		t.Errorf("expected 1 advance of 4 bytes (vlan), got %d", got)
	}
	if got := countOffsetAdvances(out.Main, 20); got != 1 {
		t.Errorf("expected 1 advance of 20 bytes (ipv4), got %d", got)
	}
}

func TestGenAlternationRejectsSingleAlt(t *testing.T) {
	eth := &ir.LayerInstance{Spec: ethSpec}
	vlanAlt := &ir.LayerInstance{
		Spec:     vlanSpecForChain,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: vlanFromEthConst},
	}
	group := &ir.LayerInstance{Alternation: []*ir.LayerInstance{vlanAlt}}
	p := &ir.Program{Layers: []*ir.LayerInstance{eth, group}}
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented for single-alt group", err)
	}
}

func TestGenAlternationRejectsFirstLayer(t *testing.T) {
	vlanAlt := &ir.LayerInstance{
		Spec:     vlanSpecForChain,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: vlanFromEthConst},
	}
	qinqAlt := &ir.LayerInstance{
		Spec:     qinqSpec,
		Dispatch: &ir.DispatchChoice{Type: vocab.DispatchField, Const: qinqFromEthConst},
	}
	group := &ir.LayerInstance{Alternation: []*ir.LayerInstance{vlanAlt, qinqAlt}}
	p := &ir.Program{Layers: []*ir.LayerInstance{group}}
	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented for first-layer alt group", err)
	}
}
