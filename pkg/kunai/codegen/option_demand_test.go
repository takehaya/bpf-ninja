package codegen

import (
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/dslvocab"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// auxRefForOption returns a synthesized AuxRef + Layer pair that
// looks like what the resolver would produce for
// `<proto>.options.<NAME>.value`. Used by demand-walker tests so
// they don't need to spin up the parser+resolver pipeline.
func auxRefForOption(t *testing.T, specs map[string]*vocab.ProtocolSpec, proto, optName string) (*ir.LayerInstance, *ir.FieldRef) {
	t.Helper()
	spec, ok := specs[proto]
	if !ok {
		t.Fatalf("vocab missing %q", proto)
	}
	if spec.ParseStateMachine == nil {
		t.Fatalf("%q has no parse state machine", proto)
	}
	layout, ok := spec.ParseStateMachine.AuxLayouts[optName]
	if !ok {
		t.Fatalf("%q has no aux %q", proto, optName)
	}
	if !layout.IsDynamicEligible {
		t.Fatalf("%q.%q is not dynamic-eligible", proto, optName)
	}
	layer := &ir.LayerInstance{Spec: spec, LayerPos: 0}
	field := layout.HeaderRef.Fields[0]
	return layer, &ir.FieldRef{
		Layer: layer,
		Field: &vocab.Field{Name: field.Name, Bits: field.Bits},
		Aux: &ir.AuxRef{
			OutParam:      layout.OutParam,
			HeaderName:    layout.HeaderName,
			HeaderSize:    layout.HeaderSize,
			FieldBitOff:   0,
			FieldBitWidth: field.Bits,
		},
	}
}

// TestCollectQueriedOptionsEmpty pins the vacuous case: a program
// with no where / no captures / no bracket predicates produces no
// queried options, regardless of how many TLV-walk-bearing layers
// are in the chain. The demand walker is what gates slot
// allocation, so a zero-demand program must not allocate any.
func TestCollectQueriedOptionsEmpty(t *testing.T) {
	specs, err := dslvocab.Bundled()
	if err != nil {
		t.Fatalf("Bundled: %v", err)
	}
	tcp := &ir.LayerInstance{Spec: specs["tcp"], LayerPos: 2}
	p := &ir.Program{Layers: []*ir.LayerInstance{tcp}}
	qo := collectQueriedOptions(p)
	if len(qo) != 0 {
		t.Errorf("got %d demand entries, want 0 (no where / capture references)", len(qo))
	}
}

// TestCollectQueriedOptionsDirectArith covers the common shape
// `tcp.options.MSS.value == 1460`: a top-level where condition
// whose ArithL is the aux field load. Demand walker should pick up
// MSS and only MSS.
func TestCollectQueriedOptionsDirectArith(t *testing.T) {
	specs, err := dslvocab.Bundled()
	if err != nil {
		t.Fatalf("Bundled: %v", err)
	}
	layer, mss := auxRefForOption(t, specs, "tcp", "mss")
	p := &ir.Program{
		Layers: []*ir.LayerInstance{layer},
		Where: &ir.Condition{
			ArithL: &ir.ArithExpr{Kind: ast.ArithField, Field: mss},
		},
	}
	qo := collectQueriedOptions(p)
	demand, ok := qo[layer]
	if !ok {
		t.Fatalf("layer not in demand set")
	}
	if len(demand) != 1 || demand[0].OutParam != "mss" {
		t.Errorf("demand = %+v, want [mss]", demand)
	}
}

// TestCollectQueriedOptionsHandlesAnyAllNot covers the recursive
// shapes the walker has to descend into. The demand walker missing
// any of these would silently fail to allocate the slot — and the
// where path would always reject because the slot would be sentinel.
func TestCollectQueriedOptionsHandlesAnyAllNot(t *testing.T) {
	specs, err := dslvocab.Bundled()
	if err != nil {
		t.Fatalf("Bundled: %v", err)
	}
	layer, mss := auxRefForOption(t, specs, "tcp", "mss")
	cases := map[string]*ir.Condition{
		"not": {Inner: &ir.Condition{ArithL: &ir.ArithExpr{Kind: ast.ArithField, Field: mss}}},
		"any": {Inner: &ir.Condition{ArithL: &ir.ArithExpr{Kind: ast.ArithField, Field: mss}}},
		"all": {Inner: &ir.Condition{ArithL: &ir.ArithExpr{Kind: ast.ArithField, Field: mss}}},
		"and": {Left: &ir.Condition{ArithL: &ir.ArithExpr{Kind: ast.ArithField, Field: mss}}},
		"or":  {Right: &ir.Condition{ArithL: &ir.ArithExpr{Kind: ast.ArithField, Field: mss}}},
		"arith-nest": {ArithL: &ir.ArithExpr{
			Left:  &ir.ArithExpr{Kind: ast.ArithField, Field: mss},
			Right: &ir.ArithExpr{Kind: ast.ArithConst, Const: 1},
		}},
		"literal-cmp": {LiteralField: mss},
		"bool-eq":     {BoolL: &ir.Condition{BoolField: mss}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := &ir.Program{Layers: []*ir.LayerInstance{layer}, Where: c}
			qo := collectQueriedOptions(p)
			if _, ok := qo[layer]; !ok {
				t.Errorf("walker did not record mss reference inside %q shape", name)
			}
		})
	}
}

// TestCollectQueriedOptionsBracketPredicate covers
// `tcp[mss.value == 1460]` — bracket predicates carry the aux
// reference on Predicate.Field, distinct from Program.Where.
func TestCollectQueriedOptionsBracketPredicate(t *testing.T) {
	specs, err := dslvocab.Bundled()
	if err != nil {
		t.Fatalf("Bundled: %v", err)
	}
	layer, mss := auxRefForOption(t, specs, "tcp", "mss")
	layer.Predicates = []*ir.Predicate{{Field: mss}}
	p := &ir.Program{Layers: []*ir.LayerInstance{layer}}
	qo := collectQueriedOptions(p)
	if _, ok := qo[layer]; !ok {
		t.Fatalf("walker did not record mss reference inside bracket predicate")
	}
}

// TestCollectQueriedOptionsCapture covers options inside capture
// clauses — both a Where and a Fields entry.
func TestCollectQueriedOptionsCapture(t *testing.T) {
	specs, err := dslvocab.Bundled()
	if err != nil {
		t.Fatalf("Bundled: %v", err)
	}
	layer, mss := auxRefForOption(t, specs, "tcp", "mss")
	t.Run("via-where", func(t *testing.T) {
		p := &ir.Program{
			Layers: []*ir.LayerInstance{layer},
			Captures: []*ir.CaptureClause{
				{Where: &ir.Condition{ArithL: &ir.ArithExpr{Kind: ast.ArithField, Field: mss}}},
			},
		}
		qo := collectQueriedOptions(p)
		if _, ok := qo[layer]; !ok {
			t.Errorf("walker did not record mss reference inside capture's where")
		}
	})
	t.Run("via-fields", func(t *testing.T) {
		p := &ir.Program{
			Layers:   []*ir.LayerInstance{layer},
			Captures: []*ir.CaptureClause{{Fields: []*ir.FieldRef{mss}}},
		}
		qo := collectQueriedOptions(p)
		if _, ok := qo[layer]; !ok {
			t.Errorf("walker did not record mss reference inside capture's fields")
		}
	})
}

// TestCollectQueriedOptionsDeterministicOrder pins the kind-byte
// sort: regardless of the order in which references are encountered,
// the per-layer demand slice is sorted by DynamicKindByte. This
// means slot index → option mapping is stable across compiles.
func TestCollectQueriedOptionsDeterministicOrder(t *testing.T) {
	specs, err := dslvocab.Bundled()
	if err != nil {
		t.Fatalf("Bundled: %v", err)
	}
	layer, mss := auxRefForOption(t, specs, "tcp", "mss") // kind 2
	_, ts := auxRefForOption(t, specs, "tcp", "ts")       // kind 8
	ts.Layer = layer
	_, sackPerm := auxRefForOption(t, specs, "tcp", "sack_perm") // kind 4
	sackPerm.Layer = layer
	// Reference in non-kind-byte order: TS, MSS, SACK_PERM.
	p := &ir.Program{
		Layers: []*ir.LayerInstance{layer},
		Where: &ir.Condition{
			Left: &ir.Condition{
				Left:  &ir.Condition{ArithL: &ir.ArithExpr{Kind: ast.ArithField, Field: ts}},
				Right: &ir.Condition{ArithL: &ir.ArithExpr{Kind: ast.ArithField, Field: mss}},
			},
			Right: &ir.Condition{ArithL: &ir.ArithExpr{Kind: ast.ArithField, Field: sackPerm}},
		},
	}
	qo := collectQueriedOptions(p)
	demand := qo[layer]
	if len(demand) != 3 {
		t.Fatalf("demand has %d entries, want 3", len(demand))
	}
	wantOrder := []string{"mss", "sack_perm", "ts"} // kinds 2, 4, 8
	for i, want := range wantOrder {
		if demand[i].OutParam != want {
			t.Errorf("demand[%d].OutParam = %q, want %q", i, demand[i].OutParam, want)
		}
	}
}

// TestDynamicAuxSentinelOutsideValidRange pins the sentinel to a
// value that no real per-packet offset can collide with. Offsets
// are non-negative and bounded by ScratchBufSize, so a u64 of -1
// (= 0xFFFF...) is unambiguous.
func TestDynamicAuxSentinelOutsideValidRange(t *testing.T) {
	if dynamicAuxSentinel >= 0 {
		t.Errorf("dynamicAuxSentinel = %d, expected negative so it can't collide with a valid scratch offset", dynamicAuxSentinel)
	}
}

// TestDynamicAuxSlotForLayoutAllocates pins the per-layer-demand-
// sized stride: a single-layer program with one queried option at
// layerPos 2 still gets slot -280 (= dynamicAuxOffsetSlotBase),
// because no prior layer adds to the cumulative offset. Under the
// previous fixed-stride allocator the same slot was -360 (= -280 -
// 2×5×8); the new allocator skips empty layers entirely.
func TestDynamicAuxSlotForLayoutAllocates(t *testing.T) {
	specs, err := dslvocab.Bundled()
	if err != nil {
		t.Fatalf("Bundled: %v", err)
	}
	layer, mss := auxRefForOption(t, specs, "tcp", "mss")
	layer.LayerPos = 2
	p := &ir.Program{
		Layers: []*ir.LayerInstance{layer},
		Where:  &ir.Condition{ArithL: &ir.ArithExpr{Kind: ast.ArithField, Field: mss}},
	}
	qo := collectQueriedOptions(p)
	mssLayout := specs["tcp"].ParseStateMachine.AuxLayouts["mss"]
	slot, ok := qo.dynamicAuxSlotForLayout(layer, mssLayout)
	if !ok {
		t.Fatal("dynamicAuxSlotForLayout returned !ok for queried mss")
	}
	if slot != dynamicAuxOffsetSlotBase {
		t.Errorf("slot = %d, want %d (no prior-layer demand)", slot, dynamicAuxOffsetSlotBase)
	}
}

// TestDynamicAuxSlotCumulativeOffset pins the stride pack: when
// layer 0 has 2 queried options and layer 2 has 1, layer-2's first
// slot starts at `-280 - 2×8 = -296` (after layer-0's 2 slots) —
// not at the previous fixed-stride `-280 - 2×5×8 = -360`.
func TestDynamicAuxSlotCumulativeOffset(t *testing.T) {
	specs, err := dslvocab.Bundled()
	if err != nil {
		t.Fatalf("Bundled: %v", err)
	}
	tcpSpec := specs["tcp"]
	priorLayer := &ir.LayerInstance{Spec: tcpSpec, LayerPos: 0}
	currentLayer := &ir.LayerInstance{Spec: tcpSpec, LayerPos: 2}
	mssLayout := tcpSpec.ParseStateMachine.AuxLayouts["mss"]
	tsLayout := tcpSpec.ParseStateMachine.AuxLayouts["ts"]
	sackPermLayout := tcpSpec.ParseStateMachine.AuxLayouts["sack_perm"]

	qo := queriedOptions{
		priorLayer:   {tsLayout, sackPermLayout},
		currentLayer: {mssLayout},
	}
	slot, ok := qo.dynamicAuxSlotForLayout(currentLayer, mssLayout)
	if !ok {
		t.Fatal("dynamicAuxSlotForLayout returned !ok")
	}
	want := dynamicAuxOffsetSlotBase - int16(2)*8 // 2 prior demand entries
	if slot != want {
		t.Errorf("slot = %d, want %d (cumulative = 2 × 8)", slot, want)
	}
}
