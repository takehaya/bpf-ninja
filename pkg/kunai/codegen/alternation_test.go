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

	// Exactly one offsetBase advance for the whole group.
	if got := countOffsetAdvances(out.Main, 4); got != 1 {
		t.Errorf("expected 1 offsetBase advance for uniform alt group, got %d", got)
	}
}

func TestGenAlternationRejectsNonUniformSize(t *testing.T) {
	// vlan (4 bytes) vs ipv4 (20 bytes) is a realistic-looking but
	// MVP-invalid mix.
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

	_, err := Gen(p, Capabilities{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v; want ErrNotImplemented for mixed-size alternation", err)
	}
	if !strings.Contains(err.Error(), "uniform size") {
		t.Errorf("error should mention uniform size: %v", err)
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

