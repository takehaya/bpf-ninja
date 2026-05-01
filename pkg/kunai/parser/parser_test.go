package parser

import (
	"strings"
	"testing"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
)

func mustParse(t *testing.T, expr string) *ast.Filter {
	t.Helper()
	f, err := Parse(expr, "t.dsl", nil)
	if err != nil {
		t.Fatalf("Parse(%q): %v", expr, err)
	}
	return f
}

func mustFail(t *testing.T, expr string, wantContains string) {
	t.Helper()
	_, err := Parse(expr, "t.dsl", nil)
	if err == nil {
		t.Fatalf("Parse(%q): expected error", expr)
	}
	if wantContains != "" && !strings.Contains(err.Error(), wantContains) {
		t.Errorf("Parse(%q) error = %v; want to contain %q", expr, err, wantContains)
	}
}

// mustFailWithReserved checks that the parser rejects an expression
// when given a reserved-label set — covers cases (e.g. @XDP_DROP)
// that depend on host-supplied reservations.
func mustFailWithReserved(t *testing.T, expr string, reserved map[string]bool, wantContains string) {
	t.Helper()
	_, err := Parse(expr, "t.dsl", reserved)
	if err == nil {
		t.Fatalf("Parse(%q): expected error", expr)
	}
	if wantContains != "" && !strings.Contains(err.Error(), wantContains) {
		t.Errorf("Parse(%q) error = %v; want to contain %q", expr, err, wantContains)
	}
}

func protoNames(layers []*ast.Layer) []string {
	out := make([]string, 0, len(layers))
	for _, l := range layers {
		if l.Kind == ast.LayerAltGroup {
			out = append(out, "(alt)")
		} else {
			out = append(out, l.ProtoName)
		}
	}
	return out
}

func TestParseSimpleChain(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp")
	if got, want := len(f.Layers), 3; got != want {
		t.Fatalf("layers==%d, want %d", got, want)
	}
	if got := protoNames(f.Layers); got[0] != "eth" || got[1] != "ipv4" || got[2] != "tcp" {
		t.Errorf("protos = %v", got)
	}
	for _, l := range f.Layers {
		if l.Quant != ast.QuantOne {
			t.Errorf("layer %q quant %v", l.ProtoName, l.Quant)
		}
	}
}

func TestParsePredicateInteger(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp[dport==443]")
	tcp := f.Layers[2]
	if len(tcp.Predicates) != 1 {
		t.Fatalf("preds==%d", len(tcp.Predicates))
	}
	p := tcp.Predicates[0]
	if p.Kind != ast.PredCmp || p.Op != ast.CmpEq || p.Field.String() != "dport" {
		t.Fatalf("pred = %+v", p)
	}
	if p.Value == nil || p.Value.Kind != ast.ValInt || p.Value.Int != 443 {
		t.Errorf("value = %+v", p.Value)
	}
}

func TestParsePredicateCIDR(t *testing.T) {
	f := mustParse(t, "eth/ipv4[src==10.0.0.0/8]/tcp")
	ipv4 := f.Layers[1]
	v := ipv4.Predicates[0].Value
	if v == nil || v.Kind != ast.ValCIDR || v.AF != 4 || v.Prefix != 8 {
		t.Fatalf("value = %+v", v)
	}
	if v.V4 != [4]byte{10, 0, 0, 0} {
		t.Errorf("V4 = %v", v.V4)
	}
}

func TestParseMultiplePredicates(t *testing.T) {
	f := mustParse(t, "eth/ipv4[src==10.0.0.0/8,dst==192.168.0.0/16]/tcp")
	preds := f.Layers[1].Predicates
	if len(preds) != 2 {
		t.Fatalf("preds==%d", len(preds))
	}
	if preds[0].Field.String() != "src" || preds[1].Field.String() != "dst" {
		t.Errorf("fields = %v / %v", preds[0].Field.String(), preds[1].Field.String())
	}
}

func TestParseInList(t *testing.T) {
	f := mustParse(t, "eth/ipv4[src in [10.0.0.1, 10.0.0.2]]/tcp")
	pred := f.Layers[1].Predicates[0]
	if pred.Kind != ast.PredIn || len(pred.List) != 2 {
		t.Fatalf("pred = %+v", pred)
	}
	if pred.List[0].V4 != [4]byte{10, 0, 0, 1} || pred.List[1].V4 != [4]byte{10, 0, 0, 2} {
		t.Errorf("list = %+v, %+v", pred.List[0], pred.List[1])
	}
}

func TestParseHas(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp[flags has SYN]")
	pred := f.Layers[2].Predicates[0]
	if pred.Kind != ast.PredHas || pred.FlagName != "SYN" {
		t.Errorf("pred = %+v", pred)
	}
}

func TestParseLabel(t *testing.T) {
	f := mustParse(t, "eth/ipv4@outer/udp/vxlan[vni==100]/ipv4@inner/tcp[dport==80]")
	if got := f.Layers[1].Label; got != "outer" {
		t.Errorf("outer label = %q", got)
	}
	if got := f.Layers[4].Label; got != "inner" {
		t.Errorf("inner label = %q", got)
	}
}

func TestParseLabelReserved(t *testing.T) {
	// XDP_DROP is reserved when the caller (e.g. an XDP host) supplies
	// it via the reservedLabels argument. With no reservations the
	// label is accepted — the parser is target-agnostic.
	xdpReserved := map[string]bool{"XDP_DROP": true}
	mustFailWithReserved(t, "eth/ipv4@XDP_DROP/tcp", xdpReserved, "reserved action symbol")
}

func TestParseQuantOpt(t *testing.T) {
	f := mustParse(t, "eth/vlan?/ipv4/tcp")
	if f.Layers[1].Quant != ast.QuantOpt {
		t.Errorf("vlan quant = %v", f.Layers[1].Quant)
	}
}

func TestParseQuantPlus(t *testing.T) {
	f := mustParse(t, "eth/mpls+/ipv4/tcp")
	if f.Layers[1].Quant != ast.QuantPlus {
		t.Errorf("mpls quant = %v", f.Layers[1].Quant)
	}
}

func TestParseQuantStar(t *testing.T) {
	f := mustParse(t, "eth/mpls*/ipv4/tcp")
	if f.Layers[1].Quant != ast.QuantStar {
		t.Errorf("mpls quant = %v", f.Layers[1].Quant)
	}
}

func TestParseQuantRange(t *testing.T) {
	f := mustParse(t, "eth/mpls{1,8}/ipv4/tcp")
	mpls := f.Layers[1]
	if mpls.Quant != ast.QuantRange || mpls.RangeMin != 1 || mpls.RangeMax != 8 {
		t.Errorf("mpls = %+v", mpls)
	}
}

func TestParseQuantOpenRange(t *testing.T) {
	f := mustParse(t, "eth/mpls{2,}/ipv4/tcp")
	mpls := f.Layers[1]
	if mpls.Quant != ast.QuantRange || mpls.RangeMin != 2 || mpls.RangeMax != -1 {
		t.Errorf("mpls = %+v", mpls)
	}
}

func TestParseQuantChainRejected(t *testing.T) {
	mustFail(t, "eth/ipv4+?/tcp", "chain quantifiers")
}

func TestParseQuantRangeInverted(t *testing.T) {
	mustFail(t, "eth/mpls{5,3}/ipv4", "less than min")
}

func TestParseAlternation(t *testing.T) {
	f := mustParse(t, "eth/(vlan|qinq)/ipv4/tcp")
	alt := f.Layers[1]
	if alt.Kind != ast.LayerAltGroup || len(alt.Alternatives) != 2 {
		t.Fatalf("alt = %+v", alt)
	}
	if alt.Alternatives[0].ProtoName != "vlan" || alt.Alternatives[1].ProtoName != "qinq" {
		t.Errorf("alts = %+v", alt.Alternatives)
	}
}

func TestParseAlternationRequiresMultiple(t *testing.T) {
	mustFail(t, "eth/(vlan)/ipv4", "at least two alternatives")
}

func TestParseCaptureAll(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp capture all")
	if len(f.Captures) != 1 || f.Captures[0].Kind != ast.CapAll {
		t.Fatalf("captures = %+v", f.Captures)
	}
}

func TestParseCaptureHeaders(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp capture headers")
	if f.Captures[0].Kind != ast.CapHeaders {
		t.Errorf("kind = %v", f.Captures[0].Kind)
	}
}

func TestParseCaptureHeadersPlus(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp capture headers+64")
	c := f.Captures[0]
	if c.Kind != ast.CapHeadersPlus || c.Extra != 64 {
		t.Errorf("capture = %+v", c)
	}
}

func TestParseCaptureFieldsUnsupported(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp capture ipv4.src, tcp.dport")
	c := f.Captures[0]
	if c.Kind != ast.CapFields || !c.Unsupported || len(c.Fields) != 2 {
		t.Fatalf("capture = %+v", c)
	}
	if c.Fields[0].String() != "ipv4.src" || c.Fields[1].String() != "tcp.dport" {
		t.Errorf("fields = %v, %v", c.Fields[0].String(), c.Fields[1].String())
	}
}

func TestParseCaptureToLayerByLabel(t *testing.T) {
	f := mustParse(t, "eth/ipv4@outer/udp/gtp/ipv4@inner/tcp capture inner")
	c := f.Captures[0]
	if c.Kind != ast.CapToLayer || c.LayerName != "inner" || c.Extra != 0 {
		t.Fatalf("capture = %+v", c)
	}
}

func TestParseCaptureToLayerByLabelPlus(t *testing.T) {
	f := mustParse(t, "eth/ipv4@outer/udp/gtp/ipv4@inner/tcp capture inner+64")
	c := f.Captures[0]
	if c.Kind != ast.CapToLayer || c.LayerName != "inner" || c.Extra != 64 {
		t.Fatalf("capture = %+v", c)
	}
}

func TestParseCaptureToLayerByProto(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp capture ipv4")
	c := f.Captures[0]
	if c.Kind != ast.CapToLayer || c.LayerName != "ipv4" || c.Extra != 0 {
		t.Fatalf("capture = %+v", c)
	}
}

func TestParseCaptureAbsolute(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp capture absolute 96")
	c := f.Captures[0]
	if c.Kind != ast.CapAbsolute || c.Extra != 96 {
		t.Fatalf("capture = %+v", c)
	}
}

// TestParseCaptureAbsoluteAsLabelFallback documents the contextual-
// keyword design: bare `capture absolute` (no INT, no `+N`) parses
// as a CapToLayer reference to a label literally named "absolute"
// rather than erroring. Catching this at the resolver (unknown
// label) gives a clearer diagnostic than a parser-level rejection.
func TestParseCaptureAbsoluteAsLabelFallback(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp capture absolute")
	c := f.Captures[0]
	if c.Kind != ast.CapToLayer || c.LayerName != "absolute" {
		t.Fatalf("capture = %+v", c)
	}
}

func TestParseCaptureLabelPlusRequiresInt(t *testing.T) {
	mustFail(t, "eth/ipv4/tcp capture ipv4+", "expected")
}

func TestParseMultipleCaptures(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp capture all capture headers+32")
	if len(f.Captures) != 2 {
		t.Fatalf("captures==%d", len(f.Captures))
	}
	if f.Captures[0].Kind != ast.CapAll || f.Captures[1].Kind != ast.CapHeadersPlus {
		t.Errorf("captures = %+v", f.Captures)
	}
}

func TestParseRejectsEmpty(t *testing.T) {
	mustFail(t, "", "empty filter")
}

func TestParseRejectsTrailingSlash(t *testing.T) {
	mustFail(t, "eth/ipv4/", "")
}

func TestParseRejectsMissingLabel(t *testing.T) {
	mustFail(t, "eth/ipv4@/tcp", "")
}

func TestParseRejectsUnclosedPredicate(t *testing.T) {
	mustFail(t, "eth/ipv4[src==10.0.0.0/8", "")
}

// --- Where clause coverage ---

func TestParseWhereActionAtom(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp where action == XDP_DROP")
	w := f.Where
	if w == nil || w.Kind != ast.WAtomAction || w.ActionValue != "XDP_DROP" {
		t.Fatalf("where = %+v", w)
	}
}

func TestParseWhereArithEquality(t *testing.T) {
	expr := "eth/ipv4@outer/udp/vxlan/ipv4@inner/tcp where outer.total_length == inner.total_length + 36"
	f := mustParse(t, expr)
	w := f.Where
	if w == nil || w.Kind != ast.WAtomArith || w.Op != ast.CmpEq {
		t.Fatalf("where = %+v", w)
	}
	if w.ArithL.Kind != ast.ArithField || w.ArithL.Field.String() != "outer.total_length" {
		t.Errorf("left = %+v", w.ArithL)
	}
	if w.ArithR.Kind != ast.ArithBinOp || w.ArithR.Op != ast.ArithAdd {
		t.Errorf("right = %+v", w.ArithR)
	}
	if w.ArithR.Left.Field.String() != "inner.total_length" || w.ArithR.Right.Const != 36 {
		t.Errorf("right inner = %+v / %+v", w.ArithR.Left, w.ArithR.Right)
	}
}

func TestParseWhereAndOrNot(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp where not action == XDP_DROP and tcp.dport == 443 or tcp.dport == 80")
	// Expected shape: or(and(not(action), dport==443), dport==80)
	if f.Where.Kind != ast.WOr {
		t.Fatalf("top = %v", f.Where.Kind)
	}
	if f.Where.Left.Kind != ast.WAnd {
		t.Errorf("left = %v", f.Where.Left.Kind)
	}
	if f.Where.Left.Left.Kind != ast.WNot {
		t.Errorf("not branch = %v", f.Where.Left.Left.Kind)
	}
	if f.Where.Left.Left.Inner.Kind != ast.WAtomAction {
		t.Errorf("not inner = %v", f.Where.Left.Left.Inner.Kind)
	}
}

func TestParseWhereParen(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp where (tcp.dport == 80 or tcp.dport == 443) and tcp.sport > 1024")
	if f.Where.Kind != ast.WAnd {
		t.Fatalf("top = %v", f.Where.Kind)
	}
	if f.Where.Left.Kind != ast.WOr {
		t.Errorf("left branch = %v", f.Where.Left.Kind)
	}
}

func TestParseWhereChainedComparisonRejected(t *testing.T) {
	mustFail(t, "eth/ipv4/tcp where tcp.sport < tcp.dport < 1024", "chained comparison")
}

func TestParseWhereRejectsLeadingOr(t *testing.T) {
	mustFail(t, "eth/ipv4/tcp where or tcp.dport == 80", "")
}

func TestParseWhereActionRejectsNonEq(t *testing.T) {
	mustFail(t, "eth/ipv4/tcp where action != XDP_DROP", "expected '=='")
}

// --- Per-capture where ---

func TestParseWhereBoolLiteralTrue(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp where true")
	if f.Where == nil || f.Where.Kind != ast.WAtomBoolLit || f.Where.BoolLitValue != true {
		t.Fatalf("where = %+v", f.Where)
	}
}

func TestParseWhereBoolLiteralFalse(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp where false")
	if f.Where == nil || f.Where.Kind != ast.WAtomBoolLit || f.Where.BoolLitValue != false {
		t.Fatalf("where = %+v", f.Where)
	}
}

func TestParseWhereBareBoolFieldDecay(t *testing.T) {
	// `where tcp.syn` should parse as `tcp.syn != 0` (Int<N> -> Bool decay).
	f := mustParse(t, "eth/ipv4/tcp where tcp.syn")
	if f.Where == nil || f.Where.Kind != ast.WAtomArith {
		t.Fatalf("where kind = %v, want WAtomArith decay", f.Where.Kind)
	}
	if f.Where.Op != ast.CmpNeq {
		t.Errorf("op = %v, want !=", f.Where.Op)
	}
	if f.Where.ArithR == nil || f.Where.ArithR.Kind != ast.ArithConst || f.Where.ArithR.Const != 0 {
		t.Errorf("RHS = %+v, want literal 0", f.Where.ArithR)
	}
}

func TestParseWhereBareBoolExists(t *testing.T) {
	// `where gtp.opt.exists` should produce a WAtomBoolExists with the
	// trailing `.exists` segment stripped.
	f := mustParse(t, "eth/ipv4/tcp where gtp.opt.exists")
	if f.Where == nil || f.Where.Kind != ast.WAtomBoolExists {
		t.Fatalf("where kind = %v, want WAtomBoolExists", f.Where.Kind)
	}
	if f.Where.BoolField == nil {
		t.Fatalf("BoolField is nil")
	}
	got := f.Where.BoolField.String()
	if got != "gtp.opt" {
		t.Errorf("BoolField path = %q, want %q", got, "gtp.opt")
	}
}

func TestParseWhereBoolEqIff(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp where true == true")
	if f.Where == nil || f.Where.Kind != ast.WAtomBoolEq {
		t.Fatalf("where kind = %v, want WAtomBoolEq", f.Where.Kind)
	}
	if f.Where.BoolEqOp != ast.CmpEq {
		t.Errorf("op = %v, want ==", f.Where.BoolEqOp)
	}
}

func TestParseWhereBoolEqWithParens(t *testing.T) {
	// `(<cmp>) == <bool-atom>` triggers BoolEq via parens path.
	f := mustParse(t, "eth/ipv4/tcp where (tcp.dport == 443) == gtp.opt.exists")
	if f.Where == nil || f.Where.Kind != ast.WAtomBoolEq {
		t.Fatalf("where kind = %v, want WAtomBoolEq", f.Where.Kind)
	}
	if f.Where.BoolEqOp != ast.CmpEq {
		t.Errorf("op = %v, want ==", f.Where.BoolEqOp)
	}
	if f.Where.BoolL == nil || f.Where.BoolR == nil {
		t.Errorf("BoolL/BoolR missing: L=%+v R=%+v", f.Where.BoolL, f.Where.BoolR)
	}
}

func TestParseWhereBoolOrderedRejected(t *testing.T) {
	mustFail(t, "eth/ipv4/tcp where true < false", "ordered comparison")
}

func TestParseWhereCIDRHostBitsRejected(t *testing.T) {
	mustFail(t, "eth/ipv4[src==10.0.0.5/24]/tcp", "host bits set")
}

// TestParseWhereIPv6BracketRejected pins the dsl-types.md §4.3 spec
// rule that IPv6 literals cannot use the URL-style bracket form
// (`[fe80::1]`). The actual rejection is structural: the opening `[`
// is consumed by the parser as the start of a bracket predicate
// while the next token is not a field name. The exact message
// depends on the parse path, so we only require that *some* error
// surfaces.
func TestParseWhereIPv6BracketRejected(t *testing.T) {
	mustFail(t, "eth/ipv6/tcp where [fe80::1] == ipv6.dst", "")
}

func TestParseWhereNegativeLiteralWhere(t *testing.T) {
	// `-1` in a where clause is parsed as unary minus over an integer
	// literal; the AST stores it as 0xffff..ff (2's complement).
	f := mustParse(t, "eth/ipv4/tcp where tcp.dport == -1")
	if f.Where == nil || f.Where.Kind != ast.WAtomArith {
		t.Fatalf("where = %+v", f.Where)
	}
	if f.Where.ArithR == nil || f.Where.ArithR.Kind != ast.ArithConst {
		t.Fatalf("RHS arith = %+v", f.Where.ArithR)
	}
	if f.Where.ArithR.Const != ^uint64(0) {
		t.Errorf("RHS = %#x, want %#x", f.Where.ArithR.Const, ^uint64(0))
	}
}

func TestParseWhereNegativeLiteralBracket(t *testing.T) {
	// `-1` in a bracket predicate is consumed via lexer value mode and
	// the buildInt helper recognises the leading minus.
	f := mustParse(t, "eth/ipv4/tcp[dport==-1]")
	tcpLayer := f.Layers[len(f.Layers)-1]
	if len(tcpLayer.Predicates) != 1 {
		t.Fatalf("got %d predicates", len(tcpLayer.Predicates))
	}
	v := tcpLayer.Predicates[0].Value
	if v == nil || v.Kind != ast.ValInt {
		t.Fatalf("value = %+v", v)
	}
	if v.Int != ^uint64(0) {
		t.Errorf("Int = %#x, want %#x", v.Int, ^uint64(0))
	}
}

func TestParseWhereNegativeLiteralAfterUnaryRejectsNonInt(t *testing.T) {
	mustFail(t, "eth/ipv4/tcp where tcp.dport == -tcp.sport", "expected integer literal after unary")
}

func TestParseWhereNetworkLiteralOnLHS(t *testing.T) {
	cases := []struct {
		expr     string
		litKind  ast.ValueKind
		fieldStr string
	}{
		{"eth/ipv4/tcp where 10.0.0.1 == ipv4.dst", ast.ValIPv4, "ipv4.dst"},
		{"eth/ipv4/tcp where 10.0.0.0/8 != ipv4.dst", ast.ValCIDR, "ipv4.dst"},
		{"eth/ipv6/tcp where fe80::1 == ipv6.src", ast.ValIPv6, "ipv6.src"},
		{"eth/ipv4/tcp where aa:bb:cc:dd:ee:ff == eth.dst", ast.ValMAC, "eth.dst"},
	}
	for _, c := range cases {
		t.Run(c.expr, func(t *testing.T) {
			f := mustParse(t, c.expr)
			if f.Where == nil || f.Where.Kind != ast.WAtomLiteralCmp {
				t.Fatalf("where kind = %v, want WAtomLiteralCmp", f.Where.Kind)
			}
			if f.Where.LiteralValue == nil || f.Where.LiteralValue.Kind != c.litKind {
				t.Errorf("literal value = %+v, want kind %v", f.Where.LiteralValue, c.litKind)
			}
			if f.Where.LiteralField == nil || f.Where.LiteralField.String() != c.fieldStr {
				t.Errorf("literal field = %v, want %q", f.Where.LiteralField, c.fieldStr)
			}
		})
	}
}

func TestParseWhereNetworkLiteralLHSOrderedRejected(t *testing.T) {
	// Per dsl-types.md §6.2 network literals only support ==/!=. The
	// ordered comparison falls through to the arith path which then
	// fails because `10.0.0.1` is not a valid arith expression head.
	mustFail(t, "eth/ipv4/tcp where 10.0.0.1 < ipv4.dst", "")
}

func TestParseCaptureWithConditional(t *testing.T) {
	f := mustParse(t, "eth/ipv4/tcp[dport==443] capture headers where action == XDP_PASS capture all where action == XDP_DROP")
	if len(f.Captures) != 2 {
		t.Fatalf("captures==%d", len(f.Captures))
	}
	c0, c1 := f.Captures[0], f.Captures[1]
	if c0.Kind != ast.CapHeaders || c0.Where == nil || c0.Where.ActionValue != "XDP_PASS" {
		t.Errorf("c0 = %+v", c0)
	}
	if c1.Kind != ast.CapAll || c1.Where == nil || c1.Where.ActionValue != "XDP_DROP" {
		t.Errorf("c1 = %+v", c1)
	}
}

// --- All 13 examples end-to-end ---

func TestParseAllExamples(t *testing.T) {
	examples := []string{
		"eth/ipv4/tcp[dport==443]",
		"eth/ipv4[src==10.0.0.0/8]/tcp",
		"eth/vlan?/ipv4/tcp",
		"eth/mpls{1,8}/ipv4/tcp",
		"eth/ipv4@outer/udp/vxlan[vni==100]/ipv4@inner/tcp[dport==80]",
		"eth/ipv6@transit/srv6/ipv6@service/srv6/ipv6@user/tcp",
		"eth/ipv4/udp/gtp[teid==0x12345]/ipv4/tcp[dport==443]",
		"eth/mpls+/ipv4/tcp",
		"eth/mpls+/eth@inner/ipv4/tcp",
		"eth/mpls+/cw?/eth@inner/ipv4/tcp",
		"eth/ipv4@outer/udp/vxlan/ipv4@inner/tcp where outer.total_length == inner.total_length + 36",
		"eth/ipv4/tcp where action == XDP_DROP",
		"eth/ipv4/tcp[dport==443] capture headers+64",
		"eth/ipv4/tcp[dport==443] capture headers where action == XDP_PASS capture all where action == XDP_DROP",
	}
	for i, ex := range examples {
		if _, err := Parse(ex, "ex.dsl", nil); err != nil {
			t.Errorf("example %d %q: %v", i, ex, err)
		}
	}
}
