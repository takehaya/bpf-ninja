package lexer

import (
	"testing"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
)

func lexAll(t *testing.T, src string) []Token {
	t.Helper()
	l := New([]byte(src), "t.dsl")
	var out []Token
	for {
		tok, err := l.Next()
		if err != nil {
			t.Fatalf("Next() at %d: %v", len(out), err)
		}
		out = append(out, tok)
		if tok.Kind == TokEOF {
			return out
		}
	}
}

func kinds(toks []Token) []TokenKind {
	ks := make([]TokenKind, len(toks))
	for i, t := range toks {
		ks[i] = t.Kind
	}
	return ks
}

func eqKinds(a, b []TokenKind) bool {
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

func TestLexSimpleLayerChain(t *testing.T) {
	got := kinds(lexAll(t, "eth/ipv4/tcp"))
	want := []TokenKind{TokIdent, TokSlash, TokIdent, TokSlash, TokIdent, TokEOF}
	if !eqKinds(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestLexKeywords(t *testing.T) {
	src := "where capture all headers and or not in has flow action"
	toks := lexAll(t, src)
	want := []TokenKind{
		TokWhere, TokCapture, TokAll, TokHeaders,
		TokAnd, TokOr, TokNot, TokIn, TokHas, TokFlow, TokAction,
		TokEOF,
	}
	if !eqKinds(kinds(toks), want) {
		t.Errorf("got %v, want %v", kinds(toks), want)
	}
}

func TestLexTwoCharOperators(t *testing.T) {
	toks := lexAll(t, "== != <= >= < >")
	want := []TokenKind{TokEqEq, TokNeq, TokLe, TokGe, TokLt, TokGt, TokEOF}
	if !eqKinds(kinds(toks), want) {
		t.Errorf("got %v, want %v", kinds(toks), want)
	}
}

func TestLexPunctuation(t *testing.T) {
	toks := lexAll(t, "/ @ [ ] ( ) { } , . | ? + * - %")
	want := []TokenKind{
		TokSlash, TokAt, TokLBracket, TokRBracket,
		TokLParen, TokRParen, TokLBrace, TokRBrace,
		TokComma, TokDot, TokPipe, TokQuestion,
		TokPlus, TokStar, TokMinus, TokPercent, TokEOF,
	}
	if !eqKinds(kinds(toks), want) {
		t.Errorf("got %v, want %v", kinds(toks), want)
	}
}

func TestLexIntegers(t *testing.T) {
	toks := lexAll(t, "0 443 0x1F4 0xFEEDFACE")
	want := []uint64{0, 443, 0x1F4, 0xFEEDFACE}
	if len(toks) != len(want)+1 {
		t.Fatalf("toks=%d, want %d", len(toks), len(want)+1)
	}
	for i, w := range want {
		if toks[i].Kind != TokInt {
			t.Errorf("tok %d kind %v", i, toks[i].Kind)
		}
		if toks[i].Int != w {
			t.Errorf("tok %d int %d, want %d", i, toks[i].Int, w)
		}
	}
}

func TestLexMalformedHex(t *testing.T) {
	_, err := New([]byte("0xG"), "t").Next()
	if err == nil {
		t.Fatal("expected error for 0xG")
	}
}

func TestLexUnexpectedChar(t *testing.T) {
	_, err := New([]byte("$"), "t").Next()
	if err == nil {
		t.Fatal("expected error for $")
	}
}

func TestLexPositionTracking(t *testing.T) {
	l := New([]byte("eth\n  /ipv4"), "t")
	ethTok, _ := l.Next()
	if ethTok.Pos.Line != 1 || ethTok.Pos.Col != 1 {
		t.Errorf("eth pos %v", ethTok.Pos)
	}
	slash, _ := l.Next()
	if slash.Pos.Line != 2 || slash.Pos.Col != 3 {
		t.Errorf("/ pos %v, want 2:3", slash.Pos)
	}
}

func TestLexIdentDistinguishesKeyword(t *testing.T) {
	toks := lexAll(t, "wheres capture headers_x")
	if toks[0].Kind != TokIdent || toks[0].Text != "wheres" {
		t.Errorf("toks[0] = %+v", toks[0])
	}
	if toks[1].Kind != TokCapture {
		t.Errorf("toks[1] = %+v", toks[1])
	}
	if toks[2].Kind != TokIdent || toks[2].Text != "headers_x" {
		t.Errorf("toks[2] = %+v", toks[2])
	}
}

// --- Value mode tests ---

// nextValueAt exercises NextValue() at a specific source offset. It is
// the parser's responsibility to call NextValue only when positioned on
// a value; here we construct that state explicitly.
func nextValueAt(t *testing.T, src string) Token {
	t.Helper()
	l := New([]byte(src), "t")
	tok, err := l.NextValue()
	if err != nil {
		t.Fatalf("NextValue(%q): %v", src, err)
	}
	return tok
}

func TestValueInteger(t *testing.T) {
	tok := nextValueAt(t, "443]")
	if tok.Value == nil || tok.Value.Kind != ast.ValInt || tok.Value.Int != 443 {
		t.Fatalf("value = %+v", tok.Value)
	}
}

func TestValueHexInteger(t *testing.T) {
	tok := nextValueAt(t, "0x12345]")
	if tok.Value == nil || tok.Value.Kind != ast.ValInt || tok.Value.Int != 0x12345 {
		t.Fatalf("value = %+v", tok.Value)
	}
}

func TestValueIPv4(t *testing.T) {
	tok := nextValueAt(t, "10.0.0.1]")
	v := tok.Value
	if v == nil || v.Kind != ast.ValIPv4 {
		t.Fatalf("value = %+v", v)
	}
	if v.V4 != [4]byte{10, 0, 0, 1} {
		t.Errorf("V4 = %v", v.V4)
	}
}

func TestValueIPv4CIDR(t *testing.T) {
	tok := nextValueAt(t, "10.0.0.0/8]")
	v := tok.Value
	if v == nil || v.Kind != ast.ValCIDR || v.AF != 4 || v.Prefix != 8 {
		t.Fatalf("value = %+v", v)
	}
	if v.V4 != [4]byte{10, 0, 0, 0} {
		t.Errorf("V4 = %v", v.V4)
	}
}

func TestValueIPv6(t *testing.T) {
	tok := nextValueAt(t, "2001:db8::1]")
	v := tok.Value
	if v == nil || v.Kind != ast.ValIPv6 {
		t.Fatalf("value = %+v", v)
	}
	// 2001:db8:: prefix bytes
	if v.V6[0] != 0x20 || v.V6[1] != 0x01 || v.V6[2] != 0x0d || v.V6[3] != 0xb8 || v.V6[15] != 1 {
		t.Errorf("V6 = %v", v.V6)
	}
}

func TestValueIPv6CIDR(t *testing.T) {
	tok := nextValueAt(t, "2001:db8::/32]")
	v := tok.Value
	if v == nil || v.Kind != ast.ValCIDR || v.AF != 6 || v.Prefix != 32 {
		t.Fatalf("value = %+v", v)
	}
}

func TestValueMAC(t *testing.T) {
	tok := nextValueAt(t, "aa:bb:cc:dd:ee:ff]")
	v := tok.Value
	if v == nil || v.Kind != ast.ValMAC {
		t.Fatalf("value = %+v", v)
	}
	if v.MAC != [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} {
		t.Errorf("MAC = %v", v.MAC)
	}
}

func TestValueRange(t *testing.T) {
	tok := nextValueAt(t, "3000..4000]")
	v := tok.Value
	if v == nil || v.Kind != ast.ValRange || v.RangeLo != 3000 || v.RangeHi != 4000 {
		t.Fatalf("value = %+v", v)
	}
}

func TestValueIdentifier(t *testing.T) {
	tok := nextValueAt(t, "XDP_DROP]")
	v := tok.Value
	if v == nil || v.Kind != ast.ValIdent || v.Ident != "XDP_DROP" {
		t.Fatalf("value = %+v", v)
	}
}

func TestValueStopsAtComma(t *testing.T) {
	// First value mode run stops at comma; the remaining source is
	// available via subsequent Next()/NextValue() calls.
	l := New([]byte("10.0.0.1, 10.0.0.2]"), "t")
	tok, err := l.NextValue()
	if err != nil {
		t.Fatalf("value 1: %v", err)
	}
	if tok.Value.Kind != ast.ValIPv4 {
		t.Fatalf("value 1 kind %v", tok.Value.Kind)
	}
	// Structural comma
	tok2, err := l.Next()
	if err != nil || tok2.Kind != TokComma {
		t.Fatalf("expected comma, got %v (err=%v)", tok2, err)
	}
	tok3, err := l.NextValue()
	if err != nil {
		t.Fatalf("value 2: %v", err)
	}
	if tok3.Value.V4 != [4]byte{10, 0, 0, 2} {
		t.Errorf("value 2 V4 = %v", tok3.Value.V4)
	}
}

func TestValueEmpty(t *testing.T) {
	// NextValue at `]` immediately returns an error (no value).
	l := New([]byte("]"), "t")
	_, err := l.NextValue()
	if err == nil {
		t.Fatal("expected error for empty value")
	}
}

func TestValueSkipsLeadingWhitespace(t *testing.T) {
	tok := nextValueAt(t, "   443]")
	if tok.Value == nil || tok.Value.Int != 443 {
		t.Errorf("value = %+v", tok.Value)
	}
}

func TestValueBadIPv4(t *testing.T) {
	_, err := New([]byte("10.0.0.999]"), "t").NextValue()
	if err == nil {
		t.Fatal("expected out-of-range error")
	}
}

func TestValueBadCIDRPrefix(t *testing.T) {
	_, err := New([]byte("10.0.0.0/33]"), "t").NextValue()
	if err == nil {
		t.Fatal("expected IPv4 prefix out-of-range error")
	}
}

func TestValueRangeInverted(t *testing.T) {
	_, err := New([]byte("100..50]"), "t").NextValue()
	if err == nil {
		t.Fatal("expected inverted-range error")
	}
}

func TestValueUnrecognized(t *testing.T) {
	// Garbage that isn't int/IP/MAC/range/ident.
	_, err := New([]byte("12.3.4]"), "t").NextValue()
	if err == nil {
		t.Fatal("expected error for 3-octet IPv4-like input")
	}
}
