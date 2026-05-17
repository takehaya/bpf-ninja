package p4lite

import (
	"strings"
	"testing"
)

func TestParseHeaderMultipleFields(t *testing.T) {
	src := `
header eth_h {
    bit<48> dst;
    bit<48> src;
    bit<16> ethertype;
}
`
	f, err := Parse([]byte(src), "eth.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Headers) != 1 {
		t.Fatalf("headers=%d, want 1", len(f.Headers))
	}
	h := f.Headers[0]
	if h.Name != "eth_h" {
		t.Errorf("name %q", h.Name)
	}
	if len(h.Fields) != 3 {
		t.Fatalf("fields=%d, want 3", len(h.Fields))
	}
	want := []Field{
		{Name: "dst", Bits: 48},
		{Name: "src", Bits: 48},
		{Name: "ethertype", Bits: 16},
	}
	for i, w := range want {
		if h.Fields[i].Name != w.Name || h.Fields[i].Bits != w.Bits {
			t.Errorf("field %d = %+v, want %+v", i, h.Fields[i], w)
		}
	}
}

func TestParseConstBoolAndBits(t *testing.T) {
	src := `
const bool ETH_MPLS_NO_CHECK = true;
const bit<8> TCP_IPV4_PROTOCOL = 6;
const bit<16> IPV4_ETH_ETHERTYPE = 0x0800;
const bit<4> IPV4_MPLS_SANITY_NIBBLE = 4;
`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Consts) != 4 {
		t.Fatalf("consts=%d, want 4", len(f.Consts))
	}
	if !f.Consts[0].IsBool || !f.Consts[0].Bool {
		t.Errorf("const[0] = %+v", f.Consts[0])
	}
	if f.Consts[1].IsBool || f.Consts[1].Bits != 8 || f.Consts[1].Int != 6 {
		t.Errorf("const[1] = %+v", f.Consts[1])
	}
	if f.Consts[2].Int != 0x0800 {
		t.Errorf("const[2].Int = %#x", f.Consts[2].Int)
	}
	if f.Consts[3].Bits != 4 || f.Consts[3].Int != 4 {
		t.Errorf("const[3] = %+v", f.Consts[3])
	}
}

func TestParseSimpleParser(t *testing.T) {
	src := `
parser EthParser(packet_in pkt, out eth_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
`
	f, err := Parse([]byte(src), "eth.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Parsers) != 1 {
		t.Fatalf("parsers=%d", len(f.Parsers))
	}
	par := f.Parsers[0]
	if par.Name != "EthParser" {
		t.Errorf("name %q", par.Name)
	}
	if len(par.Params) != 2 {
		t.Fatalf("params=%d", len(par.Params))
	}
	if !par.Params[0].IsPacketIn || par.Params[0].VarName != "pkt" {
		t.Errorf("param[0] = %+v", par.Params[0])
	}
	if !par.Params[1].IsOut || par.Params[1].TypeName != "eth_h" || par.Params[1].VarName != "hdr" {
		t.Errorf("param[1] = %+v", par.Params[1])
	}
	if len(par.States) != 1 {
		t.Fatalf("states=%d", len(par.States))
	}
	st := par.States[0]
	if st.Name != "start" {
		t.Errorf("state name %q", st.Name)
	}
	if len(st.Stmts) != 1 {
		t.Fatalf("stmts=%d", len(st.Stmts))
	}
	ext, ok := st.Stmts[0].(*ExtractStmt)
	if !ok {
		t.Fatalf("stmt[0] is %T, want *ExtractStmt", st.Stmts[0])
	}
	if ext.Object != "pkt" || ext.Target != "hdr" || ext.IsNext {
		t.Errorf("extract = %+v", ext)
	}
	if st.Transition.Kind != TransAccept {
		t.Errorf("transition kind = %v", st.Transition.Kind)
	}
}

func TestParseSelectWithTupleAndDefault(t *testing.T) {
	src := `
parser P(packet_in pkt, out h_t hdr) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.a, hdr.b, hdr.c) {
            (0, 0, 0): accept;
            default:   next_state;
        }
    }
    state next_state {
        transition reject;
    }
}
`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sel := f.Parsers[0].States[0].Transition.Select
	if sel == nil {
		t.Fatal("transition.select is nil")
	}
	gotPaths := make([]string, len(sel.Keys))
	for i, k := range sel.Keys {
		if k.Kind != SelectKeyField {
			t.Fatalf("key[%d] kind = %d, want SelectKeyField", i, k.Kind)
		}
		gotPaths[i] = k.Path
	}
	if want := []string{"hdr.a", "hdr.b", "hdr.c"}; !equalStrs(gotPaths, want) {
		t.Errorf("keys = %v, want %v", gotPaths, want)
	}
	if len(sel.Cases) != 2 {
		t.Fatalf("cases=%d", len(sel.Cases))
	}
	c0 := sel.Cases[0]
	if c0.IsDefault || len(c0.Values) != 3 || c0.Target != "accept" {
		t.Errorf("case[0] = %+v", c0)
	}
	for i, m := range c0.Values {
		if m.IsWildcard || m.Value != 0 {
			t.Errorf("case[0].Values[%d] = %+v", i, m)
		}
	}
	c1 := sel.Cases[1]
	if !c1.IsDefault || c1.Target != "next_state" {
		t.Errorf("case[1] = %+v", c1)
	}
}

func TestParseChainSelfReference(t *testing.T) {
	src := `
parser GtpParser(packet_in pkt, out gtp_h gtp, out gtp_opt_h opt, out gtp_ext_h[8] exts) {
    state start {
        pkt.extract(gtp);
        transition select(gtp.e, gtp.s, gtp.pn) {
            (0, 0, 0): accept;
            default:   parse_opt;
        }
    }
    state parse_opt {
        pkt.extract(opt);
        transition select(opt.next_ext) {
            0: accept;
            _: parse_ext;
        }
    }
    state parse_ext {
        pkt.extract(exts.next);
        transition select(exts.last.next_ext) {
            0: accept;
            _: parse_ext;
        }
    }
}
`
	f, err := Parse([]byte(src), "gtp.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	par := f.Parsers[0]
	if len(par.States) != 3 {
		t.Fatalf("states=%d", len(par.States))
	}
	// exts is an 8-slot array
	arr := par.Params[3]
	if !arr.IsArray || arr.ArraySize != 8 || arr.TypeName != "gtp_ext_h" {
		t.Errorf("exts param = %+v", arr)
	}
	// parse_ext has exts.next extract
	ext := par.States[2]
	if ext.Name != "parse_ext" {
		t.Fatalf("state[2].Name = %q", ext.Name)
	}
	es := ext.Stmts[0].(*ExtractStmt)
	if !es.IsNext || es.Target != "exts" {
		t.Errorf("parse_ext extract = %+v", es)
	}
	// self-referencing transition: wildcard case targets parse_ext
	var foundSelf bool
	for _, c := range ext.Transition.Select.Cases {
		if c.Target == "parse_ext" {
			foundSelf = true
			if len(c.Values) != 1 || !c.Values[0].IsWildcard {
				t.Errorf("self-ref case not wildcard-matched: %+v", c)
			}
		}
	}
	if !foundSelf {
		t.Error("parse_ext does not self-reference")
	}
}

func TestParseRejectsReservedKeywords(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"action", "action foo() { }"},
		{"table", "table t { }"},
		{"control", "control C() { }"},
		{"apply", "apply { }"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.src), "t.p4")
			if err == nil {
				t.Fatalf("expected error for %q", tc.src)
			}
			if !strings.Contains(err.Error(), tc.name) {
				t.Errorf("error should mention %q: %v", tc.name, err)
			}
		})
	}
}

func TestParseRejectsBitWidthOutOfRange(t *testing.T) {
	for _, src := range []string{
		"header h { bit<0> x; }",
		"header h { bit<2049> x; }",
		"const bit<0> X = 0;",
		"const bit<65> X = 1;",
	} {
		if _, err := Parse([]byte(src), "t.p4"); err == nil {
			t.Errorf("expected error for %q", src)
		}
	}
}

func TestParseAcceptsWideHeaderField(t *testing.T) {
	// IPv6 addresses are 128-bit; make sure header fields accept that.
	_, err := Parse([]byte("header h { bit<128> addr; }"), "t.p4")
	if err != nil {
		t.Fatalf("expected bit<128> in header to parse, got %v", err)
	}
}

func TestParseRejectsConstOverflow(t *testing.T) {
	// bit<8> max is 255; 256 overflows.
	_, err := Parse([]byte("const bit<8> X = 256;"), "t.p4")
	if err == nil {
		t.Fatal("expected overflow error")
	}
	if !strings.Contains(err.Error(), "fit") {
		t.Errorf("error should mention fit: %v", err)
	}
}

func TestParseRejectsNonNextAccessor(t *testing.T) {
	src := `
parser P(packet_in pkt, out h_t hdr) {
    state start {
        pkt.extract(hdr.bogus);
        transition accept;
    }
}
`
	if _, err := Parse([]byte(src), "t.p4"); err == nil {
		t.Fatal("expected error for .bogus accessor")
	}
}

func TestParseRejectsSingleValueForTupleKeys(t *testing.T) {
	src := `
parser P(packet_in pkt, out h_t hdr) {
    state start {
        transition select(hdr.a, hdr.b) {
            0: accept;
            default: reject;
        }
    }
}
`
	_, err := Parse([]byte(src), "t.p4")
	if err == nil {
		t.Fatal("expected mismatched tuple arity error")
	}
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- EOF / unterminated-block diagnostics ---
//
// The list-parsing loops in parser.go (parseHeader / parseParser /
// parseSelect / parseCase) used to spin until the closing token,
// relying on inner expect() calls to fail on EOF. That meant a
// missing `}` or `)` would surface as e.g. "expected 'bit', got EOF"
// — the message points at the next token kind, not at the missing
// brace. Each loop now also breaks on TokEOF, so the post-loop
// expect() emits the right "expected '}' / ')' " diagnostic.

func TestParseHeaderUnterminatedBrace(t *testing.T) {
	_, err := Parse([]byte("header foo { bit<8> x;"), "t.p4")
	if err == nil {
		t.Fatal("expected error for unterminated header brace")
	}
	if !strings.Contains(err.Error(), "expected '}'") {
		t.Errorf("error = %q; want substring \"expected '}'\"", err.Error())
	}
}

func TestParseParserUnterminatedParenInParams(t *testing.T) {
	_, err := Parse([]byte("parser P(packet_in pkt"), "t.p4")
	if err == nil {
		t.Fatal("expected error for unterminated parser param paren")
	}
	if !strings.Contains(err.Error(), "expected ')'") {
		t.Errorf("error = %q; want substring \"expected ')'\"", err.Error())
	}
}

func TestParseParserUnterminatedBraceInBody(t *testing.T) {
	src := `parser P(packet_in pkt) {
		state start { transition accept; }`
	_, err := Parse([]byte(src), "t.p4")
	if err == nil {
		t.Fatal("expected error for unterminated parser body brace")
	}
	if !strings.Contains(err.Error(), "expected '}'") {
		t.Errorf("error = %q; want substring \"expected '}'\"", err.Error())
	}
}

func TestParseSelectUnterminatedKeys(t *testing.T) {
	src := `parser P(packet_in pkt) {
		state s {
			transition select(a, b
		}
	}`
	_, err := Parse([]byte(src), "t.p4")
	if err == nil {
		t.Fatal("expected error for unterminated select key list")
	}
	if !strings.Contains(err.Error(), "expected ')'") && !strings.Contains(err.Error(), "expected ','") {
		t.Errorf("error = %q; want substring \"expected ')'\" or \"expected ','\"", err.Error())
	}
}

func TestParseSelectUnterminatedCases(t *testing.T) {
	src := `parser P(packet_in pkt) {
		state s {
			transition select(a) { 0: accept;
		}
	}`
	_, err := Parse([]byte(src), "t.p4")
	if err == nil {
		t.Fatal("expected error for unterminated select cases brace")
	}
	if !strings.Contains(err.Error(), "expected '}'") {
		t.Errorf("error = %q; want substring \"expected '}'\"", err.Error())
	}
}

func TestParseCaseUnterminatedTuple(t *testing.T) {
	src := `parser P(packet_in pkt) {
		state s {
			transition select(a, b) {
				(1, 2`
	_, err := Parse([]byte(src), "t.p4")
	if err == nil {
		t.Fatal("expected error for unterminated case tuple")
	}
	// Either "expected ')'" (loop terminated cleanly on EOF) or
	// "expected ','" (parseMatch saw EOF inside the tuple) is
	// acceptable — both point at a closing-token issue, not the
	// previous misleading "expected 'bit'".
	msg := err.Error()
	if !strings.Contains(msg, "expected ')'") && !strings.Contains(msg, "expected ','") && !strings.Contains(msg, "expected ':'") {
		t.Errorf("error = %q; want a closing-token diagnostic", msg)
	}
}

// --- Param array-size validation ---

func TestParseParamRejectsZeroArraySize(t *testing.T) {
	src := `parser P(packet_in pkt, out gtp_ext_h[0] exts) {
		state start { transition accept; }
	}`
	_, err := Parse([]byte(src), "t.p4")
	if err == nil {
		t.Fatal("expected error for array size 0")
	}
	if !strings.Contains(err.Error(), "array size 0") {
		t.Errorf("error = %q; want substring \"array size 0\"", err.Error())
	}
}

// --- pkt.advance template ---

func TestParseAdvanceTemplateRoundTrip(t *testing.T) {
	src := `parser P(packet_in pkt, out tcp_h hdr) {
	state start {
		pkt.extract(hdr);
		pkt.advance(((bit<32>)(hdr.data_offset - 5)) << 5);
		transition accept;
	}
}`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Parsers) != 1 || len(f.Parsers[0].States) != 1 {
		t.Fatalf("unexpected shape: %+v", f.Parsers)
	}
	stmts := f.Parsers[0].States[0].Stmts
	if len(stmts) != 2 {
		t.Fatalf("stmts=%d, want 2 (extract + advance)", len(stmts))
	}
	adv, ok := stmts[1].(*AdvanceStmt)
	if !ok {
		t.Fatalf("stmt[1] is %T, want *AdvanceStmt", stmts[1])
	}
	want := AdvanceStmt{
		Object:    "pkt",
		Kind:      AdvanceField,
		BitWidth:  32,
		Target:    "hdr",
		FieldName: "data_offset",
		BaseWords: 5,
		ScaleLog2: 5,
	}
	if adv.Object != want.Object || adv.Kind != want.Kind || adv.BitWidth != want.BitWidth ||
		adv.Target != want.Target || adv.FieldName != want.FieldName ||
		adv.BaseWords != want.BaseWords || adv.ScaleLog2 != want.ScaleLog2 {
		t.Errorf("AdvanceStmt = %+v, want %+v", *adv, want)
	}
}

func TestParseAdvanceMaskFormRoundTrip(t *testing.T) {
	// Mask form `(hdr.<F> & MASK) << S` — extension-header variable
	// trailer template used by IPv6 / SRv6 hdr_ext_len.
	src := `parser P(packet_in pkt, out srv6_h hdr) {
	state start {
		pkt.extract(hdr);
		pkt.advance(((bit<32>)(hdr.hdr_ext_len & 0x0F)) << 3);
		transition accept;
	}
}`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	stmts := f.Parsers[0].States[0].Stmts
	if len(stmts) != 2 {
		t.Fatalf("stmts=%d, want 2", len(stmts))
	}
	adv, ok := stmts[1].(*AdvanceStmt)
	if !ok {
		t.Fatalf("stmt[1] is %T, want *AdvanceStmt", stmts[1])
	}
	want := AdvanceStmt{
		Object:    "pkt",
		Kind:      AdvanceField,
		BitWidth:  32,
		Target:    "hdr",
		FieldName: "hdr_ext_len",
		BaseWords: 0,
		Mask:      0x0F,
		ScaleLog2: 3,
	}
	if adv.Object != want.Object || adv.Kind != want.Kind || adv.BitWidth != want.BitWidth ||
		adv.Target != want.Target || adv.FieldName != want.FieldName ||
		adv.BaseWords != want.BaseWords || adv.Mask != want.Mask || adv.ScaleLog2 != want.ScaleLog2 {
		t.Errorf("AdvanceStmt = %+v, want %+v", *adv, want)
	}
}

func TestParseAdvanceMaskRejectsBadOperands(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"mask_zero", `pkt.advance(((bit<32>)(hdr.hdr_ext_len & 0)) << 3);`, "mask MASK=0"},
		// 0x100 > 0xFF for an 8-bit field — caught at parse time by the
		// uint64 → int32 range guard if it overflows, otherwise by the
		// lowering's "exceeds the N-bit field" check (loader_test).
		// Here we just test the parse-time MASK=0 rejection lives in the
		// parser.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `parser P(packet_in pkt, out srv6_h hdr) {
	state start {
		pkt.extract(hdr);
		` + tc.body + `
		transition accept;
	}
}`
			_, err := Parse([]byte(src), "t.p4")
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.body)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q; want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestParseAdvanceLiteralRoundTrip(t *testing.T) {
	src := `parser P(packet_in pkt, out tcp_h hdr) {
	state s {
		pkt.advance(8);
		transition accept;
	}
}`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	stmts := f.Parsers[0].States[0].Stmts
	adv := stmts[0].(*AdvanceStmt)
	if adv.Kind != AdvanceLiteral {
		t.Errorf("Kind = %d, want AdvanceLiteral (%d)", adv.Kind, AdvanceLiteral)
	}
	if adv.LiteralBits != 8 {
		t.Errorf("LiteralBits = %d, want 8", adv.LiteralBits)
	}
}

func TestParseAdvanceLookaheadRoundTrip(t *testing.T) {
	src := `parser P(packet_in pkt, out tcp_h hdr) {
	state s {
		pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3);
		transition accept;
	}
}`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	adv := f.Parsers[0].States[0].Stmts[0].(*AdvanceStmt)
	want := AdvanceStmt{
		Kind:          AdvanceLookahead,
		BitWidth:      32,
		LookaheadBits: 16,
		SliceLo:       0,
		SliceHi:       7,
		ScaleLog2:     3,
	}
	if adv.Kind != want.Kind || adv.BitWidth != want.BitWidth ||
		adv.LookaheadBits != want.LookaheadBits ||
		adv.SliceLo != want.SliceLo || adv.SliceHi != want.SliceHi ||
		adv.ScaleLog2 != want.ScaleLog2 {
		t.Errorf("AdvanceStmt = %+v, want %+v", *adv, want)
	}
}

func TestParseSelectKeyLookaheadRoundTrip(t *testing.T) {
	src := `parser P(packet_in pkt, out tcp_h hdr) {
	state s {
		pkt.extract(hdr);
		transition select(pkt.lookahead<bit<8>>()) {
			0: accept;
			default: reject;
		}
	}
}`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	keys := f.Parsers[0].States[0].Transition.Select.Keys
	if len(keys) != 1 {
		t.Fatalf("keys=%d, want 1", len(keys))
	}
	if keys[0].Kind != SelectKeyLookahead {
		t.Errorf("Kind = %d, want SelectKeyLookahead (%d)", keys[0].Kind, SelectKeyLookahead)
	}
	if keys[0].Bits != 8 {
		t.Errorf("Bits = %d, want 8", keys[0].Bits)
	}
}

func TestParseAdvanceRejectsNonTemplateForms(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		// Note: unsupported method dispatch is exercised separately by
		// TestParseRejectsUnknownMethodCall below. Tokens the lexer
		// doesn't recognise (e.g. `+`) trip a lexer-level error before
		// the template matcher runs and aren't covered here. The
		// literal-int form `pkt.advance(8);` is the AdvanceLiteral
		// template, intentionally accepted — exercised by the
		// round-trip test below.
		{"missing_paren_count", `pkt.advance((bit<32>)(hdr.data_offset - 5) << 5);`},
		{"missing_cast", `pkt.advance(((hdr.data_offset - 5)) << 5);`},
		{"shift_right_instead_of_left", `pkt.advance(((bit<32>)(hdr.data_offset - 5)) >> 5);`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `parser P(packet_in pkt, out tcp_h hdr) {
	state start {
		pkt.extract(hdr);
		` + tc.body + `
		transition accept;
	}
}`
			_, err := Parse([]byte(src), "t.p4")
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.body)
			}
			if !strings.Contains(err.Error(), "pkt.advance must use one of") {
				t.Errorf("err = %q; want template-form hint", err.Error())
			}
		})
	}
}

func TestParseAdvanceRejectsOutOfRangeOperands(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		// S >= N: shifting a `bit<N>` value left by N or more bits is
		// implementation-defined per P4-16 §8.7 — caught here so codegen
		// doesn't have to.
		{"shift_eq_width", `pkt.advance(((bit<32>)(hdr.data_offset - 5)) << 32);`, "shift S=32 must be smaller than the cast width N=32"},
		{"shift_gt_width", `pkt.advance(((bit<32>)(hdr.data_offset - 5)) << 64);`, "shift S=64 must be smaller than the cast width N=32"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `parser P(packet_in pkt, out tcp_h hdr) {
	state start {
		pkt.extract(hdr);
		` + tc.body + `
		transition accept;
	}
}`
			_, err := Parse([]byte(src), "t.p4")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want containing %q", err, tc.want)
			}
		})
	}
}

func TestParseRejectsUnknownMethodCall(t *testing.T) {
	src := `parser P(packet_in pkt, out tcp_h hdr) {
	state start {
		pkt.lookahead(hdr);
		transition accept;
	}
}`
	_, err := Parse([]byte(src), "t.p4")
	if err == nil {
		t.Fatal("expected error for unsupported method")
	}
	if !strings.Contains(err.Error(), "unsupported method") {
		t.Errorf("err = %q; want unsupported-method hint", err.Error())
	}
}

// --- ParserCounter (extern + instance + ops + select key) ---

func TestParseExternRoundTrip(t *testing.T) {
	src := `extern ParserCounter {
		ParserCounter();
		void set(in bit<8> value);
		void decrement(in bit<8> value);
		bool is_zero();
	}

	parser P(packet_in pkt, out h_t hdr) {
		state start { transition accept; }
	}`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Externs) != 1 {
		t.Fatalf("externs=%d, want 1", len(f.Externs))
	}
	if f.Externs[0].Name != "ParserCounter" {
		t.Errorf("name = %q, want ParserCounter", f.Externs[0].Name)
	}
	if len(f.Parsers) != 1 {
		t.Fatalf("parsers=%d, want 1", len(f.Parsers))
	}
}

func TestParseExternUnterminated(t *testing.T) {
	_, err := Parse([]byte("extern ParserCounter { void set(in bit<8> v);"), "t.p4")
	if err == nil {
		t.Fatal("expected error for unterminated extern body")
	}
	if !strings.Contains(err.Error(), "unterminated extern") {
		t.Errorf("err = %q; want 'unterminated extern' hint", err.Error())
	}
}

func TestParseCounterInstanceRoundTrip(t *testing.T) {
	src := `parser P(packet_in pkt, out h_t hdr) {
		ParserCounter() pc;
		state start { transition accept; }
	}`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	par := f.Parsers[0]
	if len(par.Counters) != 1 {
		t.Fatalf("counters=%d, want 1", len(par.Counters))
	}
	if par.Counters[0].Name != "pc" {
		t.Errorf("name = %q, want pc", par.Counters[0].Name)
	}
}

func TestParseCounterInstanceRejectsDuplicate(t *testing.T) {
	src := `parser P(packet_in pkt, out h_t hdr) {
		ParserCounter() pc;
		ParserCounter() pc;
		state start { transition accept; }
	}`
	_, err := Parse([]byte(src), "t.p4")
	if err == nil {
		t.Fatal("expected duplicate-counter error")
	}
	if !strings.Contains(err.Error(), "already declared") {
		t.Errorf("err = %q; want duplicate hint", err.Error())
	}
}

func TestParseCounterSetRoundTrip(t *testing.T) {
	src := `parser P(packet_in pkt, out h_t hdr) {
		ParserCounter() pc;
		state s {
			pc.set(((bit<8>)(hdr.ihl - 5)) << 2);
			transition accept;
		}
	}`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	stmts := f.Parsers[0].States[0].Stmts
	if len(stmts) != 1 {
		t.Fatalf("stmts=%d, want 1", len(stmts))
	}
	cs, ok := stmts[0].(*CounterCallStmt)
	if !ok {
		t.Fatalf("stmt[0] is %T, want *CounterCallStmt", stmts[0])
	}
	want := CounterCallStmt{
		Counter:   "pc",
		Op:        CounterSet,
		BitWidth:  8,
		Target:    "hdr",
		FieldName: "ihl",
		BaseWords: 5,
		ScaleLog2: 2,
	}
	if cs.Counter != want.Counter || cs.Op != want.Op || cs.BitWidth != want.BitWidth ||
		cs.Target != want.Target || cs.FieldName != want.FieldName ||
		cs.BaseWords != want.BaseWords || cs.ScaleLog2 != want.ScaleLog2 {
		t.Errorf("CounterCallStmt = %+v, want %+v", *cs, want)
	}
}

func TestParseCounterDecrementRoundTrip(t *testing.T) {
	src := `parser P(packet_in pkt, out h_t hdr) {
		ParserCounter() pc;
		state s {
			pc.decrement(4);
			transition accept;
		}
	}`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cs := f.Parsers[0].States[0].Stmts[0].(*CounterCallStmt)
	if cs.Op != CounterDecrement || cs.LiteralBytes != 4 || cs.Counter != "pc" {
		t.Errorf("CounterCallStmt = %+v, want decrement(pc, 4)", *cs)
	}
}

func TestParseCounterDecrementFieldExpr(t *testing.T) {
	src := `parser P(packet_in pkt, out h_t hdr, out o_t opt) {
		ParserCounter() pc;
		state s {
			pc.decrement(opt.length);
			transition accept;
		}
	}`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cs := f.Parsers[0].States[0].Stmts[0].(*CounterCallStmt)
	if cs.Op != CounterDecrement {
		t.Fatalf("Op = %v, want CounterDecrement", cs.Op)
	}
	if cs.DecrementTarget != "opt" || cs.DecrementFieldName != "length" {
		t.Errorf("decrement field-expr = (%q, %q), want (opt, length)", cs.DecrementTarget, cs.DecrementFieldName)
	}
	if cs.LiteralBytes != 0 {
		t.Errorf("LiteralBytes = %d, want 0 for field-expr form", cs.LiteralBytes)
	}
}

func TestParseCounterDecrementRejectsBareNumber(t *testing.T) {
	// Negative form: `pc.decrement(opt)` — bare ident with no `.field`
	// — must reject so the parser doesn't silently accept a partial
	// path expression.
	src := `parser P(packet_in pkt, out h_t hdr, out o_t opt) {
		ParserCounter() pc;
		state s {
			pc.decrement(opt);
			transition accept;
		}
	}`
	_, err := Parse([]byte(src), "t.p4")
	if err == nil {
		t.Fatal("expected error for bare-ident decrement operand")
	}
}

func TestParseCounterDecrementRejectsZero(t *testing.T) {
	src := `parser P(packet_in pkt, out h_t hdr) {
		ParserCounter() pc;
		state s {
			pc.decrement(0);
			transition accept;
		}
	}`
	_, err := Parse([]byte(src), "t.p4")
	if err == nil {
		t.Fatal("expected error for decrement(0)")
	}
	if !strings.Contains(err.Error(), "no-op") {
		t.Errorf("err = %q; want no-op hint", err.Error())
	}
}

func TestParseCounterSetRejectsLookaheadOperand(t *testing.T) {
	// Counter set deliberately accepts only the field cast-shift form;
	// the lookahead operand is meaningful for trailer skips but not for
	// loading a header-derived byte count.
	src := `parser P(packet_in pkt, out h_t hdr) {
		ParserCounter() pc;
		state s {
			pc.set(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3);
			transition accept;
		}
	}`
	_, err := Parse([]byte(src), "t.p4")
	if err == nil {
		t.Fatal("expected error for lookahead operand in pc.set")
	}
	if !strings.Contains(err.Error(), "lookahead form not supported") {
		t.Errorf("err = %q; want lookahead-form hint", err.Error())
	}
}

func TestParseCounterIsZeroSelectKey(t *testing.T) {
	src := `parser P(packet_in pkt, out h_t hdr) {
		ParserCounter() pc;
		state s {
			transition select(pc.is_zero()) {
				true:  accept;
				false: reject;
			}
		}
	}`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tr := f.Parsers[0].States[0].Transition
	if tr.Kind != TransSelect {
		t.Fatalf("transition kind = %d, want TransSelect", tr.Kind)
	}
	keys := tr.Select.Keys
	if len(keys) != 1 || keys[0].Kind != SelectKeyCounterIsZero || keys[0].Counter != "pc" {
		t.Fatalf("keys = %+v, want one SelectKeyCounterIsZero(pc)", keys)
	}
	cs := tr.Select.Cases
	if len(cs) != 2 {
		t.Fatalf("cases=%d, want 2", len(cs))
	}
	if !cs[0].Values[0].IsBool || !cs[0].Values[0].Bool {
		t.Errorf("case[0] match = %+v, want true", cs[0].Values[0])
	}
	if !cs[1].Values[0].IsBool || cs[1].Values[0].Bool {
		t.Errorf("case[1] match = %+v, want false", cs[1].Values[0])
	}
}

func TestParseCounterIsZeroFallthroughOnPlainPath(t *testing.T) {
	// `ihl.foo` is a regular dotted path, NOT a counter is_zero — ensure
	// the speculative counter-key match rewinds cleanly when `.is_zero`
	// is not present.
	src := `parser P(packet_in pkt, out h_t hdr) {
		state s {
			transition select(hdr.foo) {
				0: accept;
				default: reject;
			}
		}
	}`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	keys := f.Parsers[0].States[0].Transition.Select.Keys
	if len(keys) != 1 || keys[0].Kind != SelectKeyField || keys[0].Path != "hdr.foo" {
		t.Errorf("keys = %+v, want one SelectKeyField(hdr.foo)", keys)
	}
}

func TestParseAnnotationOnHeaderEmpty(t *testing.T) {
	src := `@kunai_marker[]
header foo_h { bit<8> a; }`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Headers) != 1 {
		t.Fatalf("headers=%d, want 1", len(f.Headers))
	}
	anns := f.Headers[0].Annotations
	if len(anns) != 1 {
		t.Fatalf("annotations=%d, want 1", len(anns))
	}
	if anns[0].Name != "kunai_marker" {
		t.Errorf("Name=%q, want kunai_marker", anns[0].Name)
	}
	if len(anns[0].KVs) != 0 {
		t.Errorf("KVs=%v, want empty", anns[0].KVs)
	}
}

func TestParseAnnotationValueShapes(t *testing.T) {
	// Pins each AnnotationValueKind round-trip end-to-end:
	// int / ident / proto.field. Together they cover every kv-pair
	// shape kunai annotations actually use today.
	src := `@kunai_variable_tail[len_field=hdr_ext_len, scale=8, mask=15]
@kunai_writeback[source=next_header, parent=ipv6.next_header]
header ipv6_ext_h { bit<8> next_header; bit<8> hdr_ext_len; }`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Headers) != 1 || len(f.Headers[0].Annotations) != 2 {
		t.Fatalf("annotations=%d, want 2 on one header", len(f.Headers[0].Annotations))
	}
	vt := f.Headers[0].Annotations[0]
	if vt.Name != "kunai_variable_tail" {
		t.Errorf("vt.Name=%q", vt.Name)
	}
	if vt.KVs["len_field"].Kind != AnnotationIdent || vt.KVs["len_field"].Ident != "hdr_ext_len" {
		t.Errorf("len_field = %+v, want ident 'hdr_ext_len'", vt.KVs["len_field"])
	}
	if vt.KVs["scale"].Kind != AnnotationInt || vt.KVs["scale"].Int != 8 {
		t.Errorf("scale = %+v, want int 8", vt.KVs["scale"])
	}
	if vt.KVs["mask"].Kind != AnnotationInt || vt.KVs["mask"].Int != 15 {
		t.Errorf("mask = %+v, want int 15", vt.KVs["mask"])
	}
	wb := f.Headers[0].Annotations[1]
	if wb.Name != "kunai_writeback" {
		t.Errorf("wb.Name=%q", wb.Name)
	}
	if wb.KVs["source"].Kind != AnnotationIdent || wb.KVs["source"].Ident != "next_header" {
		t.Errorf("source = %+v, want ident 'next_header'", wb.KVs["source"])
	}
	parent := wb.KVs["parent"]
	if parent.Kind != AnnotationFieldRef || parent.Proto != "ipv6" || parent.Field != "next_header" {
		t.Errorf("parent = %+v, want fieldref 'ipv6.next_header'", parent)
	}
}

func TestParseAnnotationOnConstAndParser(t *testing.T) {
	src := `@kunai_dispatch[order=1]
const bit<8> FOO_TCP = 6;
@kunai_loop_cap[iters=8]
parser P(packet_in pkt, out foo_h hdr) {
	state start {
		pkt.extract(hdr);
		transition accept;
	}
}
header foo_h { bit<8> a; }`
	f, err := Parse([]byte(src), "t.p4")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Consts) != 1 || len(f.Consts[0].Annotations) != 1 {
		t.Fatalf("const annotations=%d, want 1", len(f.Consts[0].Annotations))
	}
	if f.Consts[0].Annotations[0].Name != "kunai_dispatch" {
		t.Errorf("const annotation name=%q", f.Consts[0].Annotations[0].Name)
	}
	if len(f.Parsers) != 1 || len(f.Parsers[0].Annotations) != 1 {
		t.Fatalf("parser annotations=%d, want 1", len(f.Parsers[0].Annotations))
	}
	if f.Parsers[0].Annotations[0].Name != "kunai_loop_cap" {
		t.Errorf("parser annotation name=%q", f.Parsers[0].Annotations[0].Name)
	}
}

func TestParseAnnotationRejects(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"positional_form", `@foo(1, 2) header h { bit<8> a; }`, "positional annotation form"},
		{"bare_no_args", `@foo header h { bit<8> a; }`, "expected '[' to start structured annotation"},
		{"duplicate_key", `@foo[a=1, a=2] header h { bit<8> a; }`, "duplicate annotation key"},
		{"missing_value", `@foo[a=] header h { bit<8> a; }`, "expected int literal, identifier"},
		{"dangling_eof", `@foo[a=1]`, "has no following declaration"},
		{"before_extern", `@foo[a=1] extern ParserCounter { }`, "annotations are not supported on extern"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.src), "t.p4")
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q; want substring %q", err.Error(), tc.want)
			}
		})
	}
}
