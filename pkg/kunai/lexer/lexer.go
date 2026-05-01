// Package lexer tokenises xdp-ninja's one-liner DSL.
//
// The lexer has two modes:
//
//   - Structural mode (Next): identifiers/keywords, integers, single and
//     double-character operators, and punctuation. This is the default.
//   - Value mode (NextValue): called by the parser when it is about to
//     read a value inside "[...]" (predicate or "in" list). The lexer
//     greedily consumes bytes until a delimiter (`]`, `,`, whitespace,
//     `)`, `}`) and classifies the run as IPv4/IPv6/MAC/CIDR/Range/Int
//     or an identifier. This keeps IPv4 CIDR "10.0.0.0/8" from
//     colliding with the layer separator "/".
package lexer

import (
	"fmt"
	"strconv"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
)

// Lexer is a single-threaded byte-level scanner over DSL source.
type Lexer struct {
	src  []byte
	pos  int
	line int
	col  int
	file string
}

// New returns a Lexer that reads from src. The file name is attached to
// any SyntaxError produced during scanning.
func New(src []byte, file string) *Lexer {
	return &Lexer{src: src, line: 1, col: 1, file: file}
}

// Snapshot captures enough state to rewind the lexer to a previous
// scan position. Used by the parser's value-mode lookahead in where
// clauses: the parser tries `Next()` (structural), and if the result
// doesn't fit the structural slot, restores the snapshot and calls
// `NextValue()` from the same byte offset.
type Snapshot struct {
	pos  int
	line int
	col  int
}

// Save returns a snapshot of the lexer's current scan position so
// callers can roll back later via Restore.
func (l *Lexer) Save() Snapshot {
	return Snapshot{pos: l.pos, line: l.line, col: l.col}
}

// Restore rewinds the lexer to the given snapshot. The caller is
// responsible for re-syncing any one-token-lookahead it has cached
// (re-call Next or NextValue afterwards).
func (l *Lexer) Restore(s Snapshot) {
	l.pos, l.line, l.col = s.pos, s.line, s.col
}

// Next returns the next structural-mode token.
func (l *Lexer) Next() (Token, error) {
	l.skipTrivia()
	if l.pos >= len(l.src) {
		return Token{Kind: TokEOF, Pos: l.currentPos()}, nil
	}
	pos := l.currentPos()
	b := l.src[l.pos]

	if isIdentStart(b) {
		return l.readIdent(pos), nil
	}
	if b >= '0' && b <= '9' {
		return l.readInt(pos)
	}

	// Two-character operators
	if l.pos+1 < len(l.src) {
		n := l.src[l.pos+1]
		switch {
		case b == '=' && n == '=':
			l.advance()
			l.advance()
			return Token{Kind: TokEqEq, Text: "==", Pos: pos}, nil
		case b == '!' && n == '=':
			l.advance()
			l.advance()
			return Token{Kind: TokNeq, Text: "!=", Pos: pos}, nil
		case b == '<' && n == '=':
			l.advance()
			l.advance()
			return Token{Kind: TokLe, Text: "<=", Pos: pos}, nil
		case b == '>' && n == '=':
			l.advance()
			l.advance()
			return Token{Kind: TokGe, Text: ">=", Pos: pos}, nil
		}
	}

	// Single-character punctuation
	l.advance()
	switch b {
	case '/':
		return Token{Kind: TokSlash, Text: "/", Pos: pos}, nil
	case '@':
		return Token{Kind: TokAt, Text: "@", Pos: pos}, nil
	case '[':
		return Token{Kind: TokLBracket, Text: "[", Pos: pos}, nil
	case ']':
		return Token{Kind: TokRBracket, Text: "]", Pos: pos}, nil
	case '(':
		return Token{Kind: TokLParen, Text: "(", Pos: pos}, nil
	case ')':
		return Token{Kind: TokRParen, Text: ")", Pos: pos}, nil
	case '{':
		return Token{Kind: TokLBrace, Text: "{", Pos: pos}, nil
	case '}':
		return Token{Kind: TokRBrace, Text: "}", Pos: pos}, nil
	case ',':
		return Token{Kind: TokComma, Text: ",", Pos: pos}, nil
	case '.':
		return Token{Kind: TokDot, Text: ".", Pos: pos}, nil
	case '|':
		return Token{Kind: TokPipe, Text: "|", Pos: pos}, nil
	case '?':
		return Token{Kind: TokQuestion, Text: "?", Pos: pos}, nil
	case '+':
		return Token{Kind: TokPlus, Text: "+", Pos: pos}, nil
	case '*':
		return Token{Kind: TokStar, Text: "*", Pos: pos}, nil
	case '-':
		return Token{Kind: TokMinus, Text: "-", Pos: pos}, nil
	case '%':
		return Token{Kind: TokPercent, Text: "%", Pos: pos}, nil
	case '=':
		return Token{Kind: TokEq, Text: "=", Pos: pos}, nil
	case '<':
		return Token{Kind: TokLt, Text: "<", Pos: pos}, nil
	case '>':
		return Token{Kind: TokGt, Text: ">", Pos: pos}, nil
	}
	return Token{}, l.syntaxErr(pos, "unexpected character %q", b)
}

// NextValue returns the next token in value mode. Leading whitespace is
// consumed; scanning stops at `]`, `,`, whitespace, `)`, `}`, or EOF.
// The consumed run is then classified into a typed ast.Value.
func (l *Lexer) NextValue() (Token, error) {
	l.skipTrivia()
	if l.pos >= len(l.src) {
		return Token{Kind: TokEOF, Pos: l.currentPos()}, nil
	}
	pos := l.currentPos()
	start := l.pos
	for l.pos < len(l.src) && isValueByte(l.src[l.pos]) {
		l.advance()
	}
	if l.pos == start {
		return Token{}, l.syntaxErr(pos, "expected a value, got %q", l.src[l.pos])
	}
	raw := string(l.src[start:l.pos])
	v, err := classifyValue(raw, pos)
	if err != nil {
		return Token{}, l.syntaxErr(pos, "%v", err)
	}
	return Token{Kind: TokValue, Text: raw, Value: v, Pos: pos}, nil
}

func (l *Lexer) currentPos() ast.Position { return ast.Position{Line: l.line, Col: l.col} }

func (l *Lexer) advance() {
	if l.pos >= len(l.src) {
		return
	}
	if l.src[l.pos] == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	l.pos++
}

func (l *Lexer) skipTrivia() {
	for l.pos < len(l.src) {
		b := l.src[l.pos]
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			l.advance()
			continue
		}
		break
	}
}

func (l *Lexer) syntaxErr(pos ast.Position, format string, args ...any) error {
	return &SyntaxError{File: l.file, Pos: pos, Message: fmt.Sprintf(format, args...)}
}

func (l *Lexer) readIdent(pos ast.Position) Token {
	start := l.pos
	for l.pos < len(l.src) && isIdentCont(l.src[l.pos]) {
		l.advance()
	}
	text := string(l.src[start:l.pos])
	if kw, ok := keywords[text]; ok {
		return Token{Kind: kw, Text: text, Pos: pos}
	}
	return Token{Kind: TokIdent, Text: text, Pos: pos}
}

func (l *Lexer) readInt(pos ast.Position) (Token, error) {
	start := l.pos
	if l.src[l.pos] == '0' && l.pos+1 < len(l.src) && (l.src[l.pos+1] == 'x' || l.src[l.pos+1] == 'X') {
		l.advance()
		l.advance()
		if !l.atHex() {
			return Token{}, l.syntaxErr(pos, "malformed hex integer literal")
		}
		for l.atHex() {
			l.advance()
		}
	} else {
		for l.pos < len(l.src) && l.src[l.pos] >= '0' && l.src[l.pos] <= '9' {
			l.advance()
		}
	}
	text := string(l.src[start:l.pos])
	v, err := strconv.ParseUint(text, 0, 64)
	if err != nil {
		return Token{}, l.syntaxErr(pos, "invalid integer literal %q: %v", text, err)
	}
	return Token{Kind: TokInt, Text: text, Int: v, Pos: pos}, nil
}

func (l *Lexer) atHex() bool {
	if l.pos >= len(l.src) {
		return false
	}
	return isHexChar(l.src[l.pos])
}

func isIdentStart(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isIdentCont(b byte) bool {
	return isIdentStart(b) || (b >= '0' && b <= '9')
}

func isHexChar(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// isValueByte reports whether b may appear in a value-mode token.
// Whitespace, `]`, `,`, `)`, `}` all terminate a value run.
func isValueByte(b byte) bool {
	if b >= '0' && b <= '9' {
		return true
	}
	if b >= 'a' && b <= 'z' {
		return true
	}
	if b >= 'A' && b <= 'Z' {
		return true
	}
	return b == '.' || b == ':' || b == '/' || b == '_'
}
