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
parser EthFragment(packet_in pkt, out eth_h hdr) {
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
	if par.Name != "EthFragment" {
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
	if got, want := sel.Keys, []string{"hdr.a", "hdr.b", "hdr.c"}; !equalStrs(got, want) {
		t.Errorf("keys = %v, want %v", got, want)
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
parser GtpFragment(packet_in pkt, out gtp_h gtp, out gtp_opt_h opt, out gtp_ext_h[8] exts) {
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
		{"extern", "extern e;"},
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
