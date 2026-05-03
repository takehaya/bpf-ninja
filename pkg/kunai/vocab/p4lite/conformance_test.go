package p4lite

import (
	"strings"
	"testing"
)

// Conformance tests pin the p4lite subset boundary: each case
// exercises a P4-16 construct that p4lite deliberately rejects
// (typically because it has no meaning for the vocabulary loader).
// If any of these starts to pass, the implementation has drifted
// from the strict-subset contract — restore the rejection or revisit
// the boundary.

func TestSubsetRejectsNonBitFieldTypes(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		// Real P4-16 admits all three; p4lite accepts only bit<N>.
		{"bool field", "header h { bool x; }"},
		{"int field", "header h { int<8> x; }"},
		{"varbit field", "header h { varbit<128> x; }"},
		{"named type field", "header h { addr_t x; }"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.src), "t.p4"); err == nil {
				t.Fatalf("expected p4lite to reject %s, but %q parsed", tc.name, tc.src)
			}
		})
	}
}

func TestSubsetRejectsTopLevelDeclsBeyondMVP(t *testing.T) {
	// P4-16 has many top-level declaration kinds; p4lite only knows
	// header / const / parser. Everything else must error.
	cases := []struct {
		name string
		src  string
	}{
		{"struct", "struct s_t { bit<8> a; }"},
		{"header_union", "header_union u_t { h_t a; }"},
		{"enum", "enum E { A, B }"},
		{"typedef", "typedef bit<8> Foo;"},
		{"type_alias", "type bit<8> Foo;"},
		{"package", "package P();"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.src), "t.p4"); err == nil {
				t.Fatalf("expected p4lite to reject %s, but %q parsed", tc.name, tc.src)
			}
		})
	}
}

func TestSubsetRejectsAtSignAnnotation(t *testing.T) {
	// `@name` and `@name(args)` are valid P4-16 annotations on every
	// declaration. p4lite has no `@` lexer rule, so it must error.
	cases := []string{
		"@version header h { bit<8> x; }",
		"@name(\"foo\") const bit<8> X = 0;",
	}
	for _, src := range cases {
		if _, err := Parse([]byte(src), "t.p4"); err == nil {
			t.Errorf("expected p4lite to reject annotation, but %q parsed", src)
		}
	}
}

func TestSubsetRejectsParserDirectionsBeyondMVP(t *testing.T) {
	// p4lite accepts only `packet_in` and `out`; `in`, `inout`,
	// and the no-direction form are MVP-out-of-scope.
	cases := []struct {
		name string
		src  string
	}{
		{"in direction", "parser P(in bit<8> x) { state start { transition accept; } }"},
		{"inout direction", "parser P(inout bit<8> x) { state start { transition accept; } }"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.src), "t.p4"); err == nil {
				t.Fatalf("expected p4lite to reject %s, but %q parsed", tc.name, tc.src)
			}
		})
	}
}

func TestSubsetRejectsParserStatementsBeyondExtract(t *testing.T) {
	// Real P4 lets parser states do `verify(...)`, `var = expr`, and
	// conditional / block statements. p4lite knows only extract and
	// advance.
	cases := []struct {
		name string
		stmt string
	}{
		{"verify", "verify(true, error.NoError);"},
		{"assignment", "x = 1;"},
		{"conditional", "if (true) {}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `parser P(packet_in pkt, out h_t hdr) {
				state start {
					` + tc.stmt + `
					transition accept;
				}
			}`
			if _, err := Parse([]byte(src), "t.p4"); err == nil {
				t.Fatalf("expected p4lite to reject %s, but it parsed", tc.name)
			}
		})
	}
}

func TestSubsetRejectsSelectMaskAndRange(t *testing.T) {
	// Mask (`val &&& mask`) and range (`a .. b`) keysets are valid
	// P4-16 select cases; p4lite supports only literal-or-wildcard.
	cases := []struct {
		name string
		key  string
	}{
		{"mask", "0x0800 &&& 0xFF00"},
		{"range", "1024 .. 2048"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `parser P(packet_in pkt, out h_t hdr) {
				state start {
					transition select(hdr.x) {
						` + tc.key + `: accept;
						default: reject;
					}
				}
			}`
			if _, err := Parse([]byte(src), "t.p4"); err == nil {
				t.Fatalf("expected p4lite to reject %s match, but it parsed", tc.name)
			}
		})
	}
}

func TestSubsetRejectsBinaryAndOctalLiterals(t *testing.T) {
	// P4-16 supports 0b binary and 0o octal integer literals; p4lite
	// only handles decimal and 0x hex.
	cases := []string{
		"const bit<8> X = 0b1010;",
		"const bit<8> X = 0o12;",
	}
	for _, src := range cases {
		if _, err := Parse([]byte(src), "t.p4"); err == nil {
			t.Errorf("expected p4lite to reject non-decimal/hex literal, but %q parsed", src)
		}
	}
}

func TestSubsetAcceptsSingleParserParamShape(t *testing.T) {
	// Real P4 architectures wire 3-4 parameters into the parser
	// (packet_in, out hdr, inout meta, …). p4lite intentionally
	// accepts the smaller shape — sanity-check that the (packet_in,
	// out hdr) pair we standardise on still parses.
	src := `parser P(packet_in pkt, out h_t hdr) {
		state start {
			pkt.extract(hdr);
			transition accept;
		}
	}`
	if _, err := Parse([]byte(src), "t.p4"); err != nil {
		t.Fatalf("two-param packet_in/out parser should parse: %v", err)
	}
}

func TestSubsetMVPKeywordRejectionIsTargeted(t *testing.T) {
	// The lexer's rejectedKeywords list raises a *targeted* error
	// rather than a generic "unexpected token" so vocab authors can
	// see which P4 feature is unsupported.
	for _, kw := range []string{"action", "table", "control", "apply", "extern"} {
		_, err := Parse([]byte(kw+" Foo {}"), "t.p4")
		if err == nil {
			t.Errorf("%s should be rejected", kw)
			continue
		}
		if !strings.Contains(err.Error(), kw) {
			t.Errorf("error for %q should name the keyword: %v", kw, err)
		}
	}
}
