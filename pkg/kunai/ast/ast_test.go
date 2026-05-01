package ast

import "testing"

func TestPositionString(t *testing.T) {
	if got := (Position{Line: 3, Col: 15}).String(); got != "3:15" {
		t.Errorf("Position.String() = %q, want 3:15", got)
	}
}

func TestFieldPathString(t *testing.T) {
	cases := []struct {
		parts []string
		want  string
	}{
		{[]string{"tcp", "dport"}, "tcp.dport"},
		{[]string{"outer", "total_length"}, "outer.total_length"},
		{[]string{"solo"}, "solo"},
	}
	for _, tc := range cases {
		f := &FieldPath{Parts: tc.parts}
		if got := f.String(); got != tc.want {
			t.Errorf("parts==%v: got %q, want %q", tc.parts, got, tc.want)
		}
	}
	var nilPath *FieldPath
	if got := nilPath.String(); got != "<nil>" {
		t.Errorf("nil.String() = %q, want <nil>", got)
	}
}

func TestKindStrings(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{LayerProto.String(), "proto"},
		{LayerAltGroup.String(), "alt"},
		{QuantOne.String(), "one"},
		{QuantOpt.String(), "?"},
		{QuantPlus.String(), "+"},
		{QuantStar.String(), "*"},
		{QuantRange.String(), "{n,m}"},
		{CmpEq.String(), "=="},
		{CmpNeq.String(), "!="},
		{CmpLt.String(), "<"},
		{CmpLe.String(), "<="},
		{CmpGt.String(), ">"},
		{CmpGe.String(), ">="},
		{ArithAdd.String(), "+"},
		{ArithSub.String(), "-"},
		{ArithMul.String(), "*"},
		{ArithDiv.String(), "/"},
		{ArithMod.String(), "%"},
		{ArithConst.String(), "const"},
		{ArithField.String(), "field"},
		{ArithBinOp.String(), "binop"},
		{WOr.String(), "or"},
		{WAnd.String(), "and"},
		{WNot.String(), "not"},
		{WAtomArith.String(), "arith"},
		{WAtomAction.String(), "action"},
		{WAtomFlow.String(), "flow"},
		{PredCmp.String(), "cmp"},
		{PredIn.String(), "in"},
		{PredHas.String(), "has"},
		{CapAll.String(), "all"},
		{CapHeaders.String(), "headers"},
		{CapHeadersPlus.String(), "headers+N"},
		{CapFields.String(), "fields"},
		{ValInt.String(), "int"},
		{ValIPv4.String(), "ipv4"},
		{ValIPv6.String(), "ipv6"},
		{ValMAC.String(), "mac"},
		{ValCIDR.String(), "cidr"},
		{ValRange.String(), "range"},
		{ValString.String(), "string"},
		{ValIdent.String(), "ident"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
}

func TestUnknownKindStrings(t *testing.T) {
	cases := []string{
		LayerKind(99).String(),
		QuantKind(99).String(),
		CmpOp(99).String(),
		ArithOp(99).String(),
		ArithKind(99).String(),
		WhereKind(99).String(),
		PredKind(99).String(),
		CaptureKind(99).String(),
		ValueKind(99).String(),
	}
	for i, s := range cases {
		if s == "" {
			t.Errorf("case %d returned empty string", i)
		}
	}
}

// TestBuildBasicFilter exercises a hand-built AST that matches the
// shape the parser should produce for "eth/ipv4/tcp[dport==443]".
func TestBuildBasicFilter(t *testing.T) {
	f := &Filter{
		Pos: Position{Line: 1, Col: 1},
		Layers: []*Layer{
			{Kind: LayerProto, ProtoName: "eth"},
			{Kind: LayerProto, ProtoName: "ipv4"},
			{
				Kind:      LayerProto,
				ProtoName: "tcp",
				Predicates: []*Predicate{
					{
						Kind:  PredCmp,
						Field: &FieldPath{Parts: []string{"dport"}},
						Op:    CmpEq,
						Value: &Value{Kind: ValInt, Int: 443, Raw: "443"},
					},
				},
			},
		},
	}
	if len(f.Layers) != 3 {
		t.Fatalf("Layers = %d, want 3", len(f.Layers))
	}
	tcp := f.Layers[2]
	if tcp.ProtoName != "tcp" || len(tcp.Predicates) != 1 {
		t.Fatalf("tcp layer = %+v", tcp)
	}
	p := tcp.Predicates[0]
	if p.Field.String() != "dport" || p.Op != CmpEq || p.Value.Int != 443 {
		t.Errorf("predicate = %+v", p)
	}
}

// TestBuildWhereArith builds the AST for
// "... where outer.total_length == inner.total_length + 36".
func TestBuildWhereArith(t *testing.T) {
	w := &WhereExpr{
		Kind: WAtomArith,
		ArithL: &ArithExpr{
			Kind:  ArithField,
			Field: &FieldPath{Parts: []string{"outer", "total_length"}},
		},
		Op: CmpEq,
		ArithR: &ArithExpr{
			Kind: ArithBinOp,
			Op:   ArithAdd,
			Left: &ArithExpr{
				Kind:  ArithField,
				Field: &FieldPath{Parts: []string{"inner", "total_length"}},
			},
			Right: &ArithExpr{Kind: ArithConst, Const: 36},
		},
	}
	if w.ArithR.Op != ArithAdd || w.ArithR.Right.Const != 36 {
		t.Fatalf("arith shape wrong: %+v", w)
	}
	if w.ArithL.Field.String() != "outer.total_length" {
		t.Errorf("left field = %q", w.ArithL.Field.String())
	}
}

// TestUnsupportedMarker confirms that the Unsupported flag lives in the
// expected places. If either flag drifts to another type, codegen's
// "not yet implemented" detection would break silently.
func TestUnsupportedMarker(t *testing.T) {
	w := &WhereExpr{Kind: WAtomFlow, FlowKind: "is_new", Unsupported: true}
	if !w.Unsupported || w.Kind != WAtomFlow || w.FlowKind != "is_new" {
		t.Fatalf("WhereExpr shape wrong: %+v", w)
	}
	c := &CaptureClause{
		Kind: CapFields,
		Fields: []*FieldPath{
			{Parts: []string{"ipv4", "src"}},
		},
		Unsupported: true,
	}
	if !c.Unsupported || c.Kind != CapFields || len(c.Fields) != 1 {
		t.Fatalf("CaptureClause shape wrong: %+v", c)
	}
}
