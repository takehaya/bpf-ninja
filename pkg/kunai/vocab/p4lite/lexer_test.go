package p4lite

import (
	"strings"
	"testing"
)

func lexAll(t *testing.T, src string) []Token {
	t.Helper()
	l := NewLexer([]byte(src), "test.p4")
	var tokens []Token
	for {
		tok, err := l.Next()
		if err != nil {
			t.Fatalf("lex error: %v", err)
		}
		tokens = append(tokens, tok)
		if tok.Kind == TokEOF {
			return tokens
		}
	}
}

func kinds(tokens []Token) []TokenKind {
	ks := make([]TokenKind, len(tokens))
	for i, t := range tokens {
		ks[i] = t.Kind
	}
	return ks
}

func equalKinds(a, b []TokenKind) bool {
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

func TestLexerBasicDecl(t *testing.T) {
	src := "header Foo { bit<16> x; }"
	got := kinds(lexAll(t, src))
	want := []TokenKind{
		TokHeader, TokIdent, TokLBrace,
		TokBit, TokLAngle, TokInt, TokRAngle, TokIdent, TokSemi,
		TokRBrace, TokEOF,
	}
	if !equalKinds(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestLexerIntegerLiterals(t *testing.T) {
	tokens := lexAll(t, "0 0x1234 255 0xABCDEF")
	if len(tokens) != 5 {
		t.Fatalf("expected 4 int + EOF, got %d", len(tokens))
	}
	want := []uint64{0, 0x1234, 255, 0xABCDEF}
	for i, w := range want {
		if tokens[i].Kind != TokInt {
			t.Errorf("token %d kind %v", i, tokens[i].Kind)
		}
		if tokens[i].Int != w {
			t.Errorf("token %d int %d, want %d", i, tokens[i].Int, w)
		}
	}
}

func TestLexerCommentsSkipped(t *testing.T) {
	src := "// line comment\n/* block\ncomment */ header /* inline */ Foo"
	got := kinds(lexAll(t, src))
	want := []TokenKind{TokHeader, TokIdent, TokEOF}
	if !equalKinds(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestLexerRejectsReservedKeywords(t *testing.T) {
	for _, kw := range []string{"action", "table", "control", "apply", "extern"} {
		_, err := NewLexer([]byte(kw), "test.p4").Next()
		if err == nil {
			t.Errorf("expected error for reserved keyword %q", kw)
			continue
		}
		if !strings.Contains(err.Error(), kw) {
			t.Errorf("error for %q should mention keyword: %v", kw, err)
		}
	}
}

func TestLexerUnterminatedBlockComment(t *testing.T) {
	_, err := NewLexer([]byte("/* never closed"), "t").Next()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unterminated") {
		t.Errorf("error should mention 'unterminated': %v", err)
	}
}

func TestLexerPositionTracking(t *testing.T) {
	l := NewLexer([]byte("header\n  bit"), "t.p4")
	h, err := l.Next()
	if err != nil {
		t.Fatalf("lex: %v", err)
	}
	if h.Pos.Line != 1 || h.Pos.Col != 1 {
		t.Errorf("header pos %v, want 1:1", h.Pos)
	}
	b, err := l.Next()
	if err != nil {
		t.Fatalf("lex: %v", err)
	}
	if b.Pos.Line != 2 || b.Pos.Col != 3 {
		t.Errorf("bit pos %v, want 2:3", b.Pos)
	}
}

func TestLexerKeywordsVsIdents(t *testing.T) {
	tokens := lexAll(t, "header headerx _x x_y")
	want := []TokenKind{TokHeader, TokIdent, TokIdent, TokIdent, TokEOF}
	if !equalKinds(kinds(tokens), want) {
		t.Errorf("got %v, want %v", kinds(tokens), want)
	}
	if tokens[1].Value != "headerx" {
		t.Errorf("tokens[1].Value=%q", tokens[1].Value)
	}
	if tokens[2].Value != "_x" {
		t.Errorf("tokens[2].Value=%q", tokens[2].Value)
	}
}

func TestLexerUnexpectedCharacter(t *testing.T) {
	_, err := NewLexer([]byte("@"), "t.p4").Next()
	if err == nil {
		t.Fatal("expected error for '@'")
	}
}

func TestLexerMalformedHex(t *testing.T) {
	_, err := NewLexer([]byte("0xG"), "t.p4").Next()
	if err == nil {
		t.Fatal("expected error for malformed hex literal")
	}
}

// TestLexerLeadingZeroDecimal pins P4-16 Section 6.4.3 "Literal constants":
// a literal like `010`
// is decimal 10, not octal 8. Earlier the lexer used
// strconv.ParseUint(_, 0, 64) which auto-detected leading-`0` as
// octal and returned 8; we now pass an explicit base 10.
func TestLexerLeadingZeroDecimal(t *testing.T) {
	tokens := lexAll(t, "010 007")
	if len(tokens) != 3 || tokens[0].Kind != TokInt || tokens[1].Kind != TokInt {
		t.Fatalf("tokens = %+v", tokens)
	}
	if tokens[0].Int != 10 {
		t.Errorf("`010` parsed as %d, want 10 (P4-16 leading zeros are decimal, not octal)", tokens[0].Int)
	}
	if tokens[1].Int != 7 {
		t.Errorf("`007` parsed as %d, want 7", tokens[1].Int)
	}
}

// TestLexerOverflowMessage pins the friendlier wrap around
// strconv.ErrRange so users see "overflows uint64" rather than the
// raw NumError prose.
func TestLexerOverflowMessage(t *testing.T) {
	_, err := NewLexer([]byte("0xFFFFFFFFFFFFFFFFF"), "t.p4").Next()
	if err == nil {
		t.Fatal("expected overflow error")
	}
	if !strings.Contains(err.Error(), "overflows uint64") {
		t.Errorf("error = %q; want substring %q", err.Error(), "overflows uint64")
	}
}

// TestLexerCRLFColumnTracking pins that a CRLF newline reports the
// post-newline col as 1 — earlier the \r incremented col before the
// \n reset, which left the first column of every CRLF line off-by-one.
func TestLexerCRLFColumnTracking(t *testing.T) {
	tokens := lexAll(t, "header\r\nFoo")
	if len(tokens) < 2 {
		t.Fatalf("tokens = %+v", tokens)
	}
	if tokens[1].Pos.Line != 2 || tokens[1].Pos.Col != 1 {
		t.Errorf("Foo at line=%d col=%d, want line=2 col=1", tokens[1].Pos.Line, tokens[1].Pos.Col)
	}
}
