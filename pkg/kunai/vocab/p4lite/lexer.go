// p4lite/lexer.go — tokeniser for the strict subset of P4-16 the
// xdp-ninja vocab loader consumes.
//
// Spec reference: P4-16 Language Specification v1.2.5
//
//	https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html
//
// Sections this implementation aligns with (verified against the v1.2.5 ToC):
//   - Appendix G "Appendix: P4 grammar" — formal lexer / parser BNF
//     (token shapes, identifiers).
//   - Section 6.4.3 "Literal constants" — decimal and 0x hex are
//     accepted; 0b binary and 0o octal are rejected at the parser
//     (TestSubsetRejectsBinaryAndOctalLiterals).
//   - Section 13.4 "Parser states" — token set the lexer needs for
//     parser bodies (`state`, `transition`, `select`, `accept`,
//     `reject`).
package p4lite

import (
	"errors"
	"fmt"
	"strconv"
)

type TokenKind int

const (
	TokEOF TokenKind = iota
	TokIdent
	TokInt
	TokHeader
	TokConst
	TokParser
	TokState
	TokTransition
	TokSelect
	TokDefault
	TokAccept
	TokReject
	TokBit
	TokBool
	TokPacketIn
	TokOut
	TokExtract
	TokAdvance
	TokLookahead
	TokExtern
	TokParserCounter
	TokTrue
	TokFalse
	TokLBrace
	TokRBrace
	TokLParen
	TokRParen
	TokLBracket
	TokRBracket
	TokLAngle
	TokRAngle
	TokSemi
	TokComma
	TokColon
	TokEquals
	TokDot
	TokMinus
	TokPlus
	TokLShift
	TokAmp
	TokAt
)

func (k TokenKind) String() string {
	switch k {
	case TokEOF:
		return "EOF"
	case TokIdent:
		return "identifier"
	case TokInt:
		return "integer"
	case TokHeader:
		return "'header'"
	case TokConst:
		return "'const'"
	case TokParser:
		return "'parser'"
	case TokState:
		return "'state'"
	case TokTransition:
		return "'transition'"
	case TokSelect:
		return "'select'"
	case TokDefault:
		return "'default'"
	case TokAccept:
		return "'accept'"
	case TokReject:
		return "'reject'"
	case TokBit:
		return "'bit'"
	case TokBool:
		return "'bool'"
	case TokPacketIn:
		return "'packet_in'"
	case TokOut:
		return "'out'"
	case TokExtract:
		return "'extract'"
	case TokAdvance:
		return "'advance'"
	case TokLookahead:
		return "'lookahead'"
	case TokExtern:
		return "'extern'"
	case TokParserCounter:
		return "'ParserCounter'"
	case TokTrue:
		return "'true'"
	case TokFalse:
		return "'false'"
	case TokLBrace:
		return "'{'"
	case TokRBrace:
		return "'}'"
	case TokLParen:
		return "'('"
	case TokRParen:
		return "')'"
	case TokLBracket:
		return "'['"
	case TokRBracket:
		return "']'"
	case TokLAngle:
		return "'<'"
	case TokRAngle:
		return "'>'"
	case TokSemi:
		return "';'"
	case TokComma:
		return "','"
	case TokColon:
		return "':'"
	case TokEquals:
		return "'='"
	case TokDot:
		return "'.'"
	case TokMinus:
		return "'-'"
	case TokPlus:
		return "'+'"
	case TokLShift:
		return "'<<'"
	case TokAmp:
		return "'&'"
	case TokAt:
		return "'@'"
	}
	return fmt.Sprintf("TokenKind(%d)", int(k))
}

var keywords = map[string]TokenKind{
	"header":        TokHeader,
	"const":         TokConst,
	"parser":        TokParser,
	"state":         TokState,
	"transition":    TokTransition,
	"select":        TokSelect,
	"default":       TokDefault,
	"accept":        TokAccept,
	"reject":        TokReject,
	"bit":           TokBit,
	"bool":          TokBool,
	"packet_in":     TokPacketIn,
	"out":           TokOut,
	"extract":       TokExtract,
	"advance":       TokAdvance,
	"lookahead":     TokLookahead,
	"extern":        TokExtern,
	"ParserCounter": TokParserCounter,
	"true":          TokTrue,
	"false":         TokFalse,
}

// rejectedKeywords names full-P4-16 constructs that p4lite has no
// model for. `extern` is accepted (its body is opaque-skipped) so
// vocab files can declare ParserCounter for p4c parse-check.
var rejectedKeywords = map[string]bool{
	"action":  true,
	"table":   true,
	"control": true,
	"apply":   true,
}

type Token struct {
	Kind  TokenKind
	Value string
	Int   uint64
	Pos   Position
}

type Lexer struct {
	src  []byte
	pos  int
	line int
	col  int
	file string
}

func NewLexer(src []byte, file string) *Lexer {
	return &Lexer{src: src, line: 1, col: 1, file: file}
}

// LexerSnapshot captures a Lexer's mutable state so the parser can
// rewind after a speculative read. Used to disambiguate forms that
// share a prefix (`pkt.lookahead<...>()` vs `pkt.<field>...`).
type LexerSnapshot struct {
	pos, line, col int
}

func (l *Lexer) Save() LexerSnapshot { return LexerSnapshot{l.pos, l.line, l.col} }

func (l *Lexer) Restore(s LexerSnapshot) {
	l.pos, l.line, l.col = s.pos, s.line, s.col
}

func (l *Lexer) syntaxErr(pos Position, format string, args ...any) error {
	return &SyntaxError{File: l.file, Pos: pos, Message: fmt.Sprintf(format, args...)}
}

func (l *Lexer) currentPos() Position { return Position{Line: l.line, Col: l.col} }

func (l *Lexer) peekByte() byte {
	if l.pos >= len(l.src) {
		return 0
	}
	return l.src[l.pos]
}

func (l *Lexer) advance() byte {
	if l.pos >= len(l.src) {
		return 0
	}
	b := l.src[l.pos]
	l.pos++
	switch b {
	case '\n':
		l.line++
		l.col = 1
	case '\r':
		// Skip CR for column tracking. CRLF newlines (Windows-saved
		// files) increment col on \r and reset on \n otherwise, which
		// shifts every error position by one column.
	default:
		l.col++
	}
	return b
}

func (l *Lexer) skipTrivia() error {
	for l.pos < len(l.src) {
		b := l.peekByte()
		switch {
		case b == ' ' || b == '\t' || b == '\n' || b == '\r':
			l.advance()
		case b == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/':
			for l.pos < len(l.src) && l.peekByte() != '\n' {
				l.advance()
			}
		case b == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '*':
			start := l.currentPos()
			l.advance()
			l.advance()
			closed := false
			for l.pos < len(l.src) {
				if l.peekByte() == '*' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/' {
					l.advance()
					l.advance()
					closed = true
					break
				}
				l.advance()
			}
			if !closed {
				return l.syntaxErr(start, "unterminated block comment")
			}
		default:
			return nil
		}
	}
	return nil
}

func (l *Lexer) Next() (Token, error) {
	if err := l.skipTrivia(); err != nil {
		return Token{}, err
	}
	if l.pos >= len(l.src) {
		return Token{Kind: TokEOF, Pos: l.currentPos()}, nil
	}
	pos := l.currentPos()
	b := l.peekByte()
	switch {
	case isIdentStart(b):
		return l.readIdent(pos)
	case b >= '0' && b <= '9':
		return l.readInt(pos)
	}
	l.advance()
	switch b {
	case '{':
		return Token{Kind: TokLBrace, Value: "{", Pos: pos}, nil
	case '}':
		return Token{Kind: TokRBrace, Value: "}", Pos: pos}, nil
	case '(':
		return Token{Kind: TokLParen, Value: "(", Pos: pos}, nil
	case ')':
		return Token{Kind: TokRParen, Value: ")", Pos: pos}, nil
	case '[':
		return Token{Kind: TokLBracket, Value: "[", Pos: pos}, nil
	case ']':
		return Token{Kind: TokRBracket, Value: "]", Pos: pos}, nil
	case '<':
		if l.pos < len(l.src) && l.src[l.pos] == '<' {
			l.advance()
			return Token{Kind: TokLShift, Value: "<<", Pos: pos}, nil
		}
		return Token{Kind: TokLAngle, Value: "<", Pos: pos}, nil
	case '>':
		return Token{Kind: TokRAngle, Value: ">", Pos: pos}, nil
	case ';':
		return Token{Kind: TokSemi, Value: ";", Pos: pos}, nil
	case ',':
		return Token{Kind: TokComma, Value: ",", Pos: pos}, nil
	case ':':
		return Token{Kind: TokColon, Value: ":", Pos: pos}, nil
	case '=':
		return Token{Kind: TokEquals, Value: "=", Pos: pos}, nil
	case '.':
		return Token{Kind: TokDot, Value: ".", Pos: pos}, nil
	case '-':
		return Token{Kind: TokMinus, Value: "-", Pos: pos}, nil
	case '+':
		return Token{Kind: TokPlus, Value: "+", Pos: pos}, nil
	case '&':
		return Token{Kind: TokAmp, Value: "&", Pos: pos}, nil
	case '@':
		return Token{Kind: TokAt, Value: "@", Pos: pos}, nil
	}
	return Token{}, l.syntaxErr(pos, "unexpected character %q", b)
}

func (l *Lexer) readIdent(pos Position) (Token, error) {
	start := l.pos
	for l.pos < len(l.src) && isIdentCont(l.src[l.pos]) {
		l.advance()
	}
	value := string(l.src[start:l.pos])
	if rejectedKeywords[value] {
		return Token{}, l.syntaxErr(pos, "p4lite does not support %q (MVP subset accepts only header/const/parser/state/transition/select)", value)
	}
	if kw, ok := keywords[value]; ok {
		return Token{Kind: kw, Value: value, Pos: pos}, nil
	}
	return Token{Kind: TokIdent, Value: value, Pos: pos}, nil
}

func (l *Lexer) readInt(pos Position) (Token, error) {
	start := l.pos
	base := 10
	digitsStart := start
	if l.src[l.pos] == '0' && l.pos+1 < len(l.src) && (l.src[l.pos+1] == 'x' || l.src[l.pos+1] == 'X') {
		l.advance()
		l.advance()
		if !isHexDigit(l.peekByte()) {
			return Token{}, l.syntaxErr(pos, "malformed hex integer literal")
		}
		for l.pos < len(l.src) && isHexDigit(l.src[l.pos]) {
			l.advance()
		}
		base = 16
		digitsStart = start + 2
	} else {
		for l.pos < len(l.src) && l.src[l.pos] >= '0' && l.src[l.pos] <= '9' {
			l.advance()
		}
	}
	lit := string(l.src[start:l.pos])
	// Pass an explicit base rather than strconv's auto-detect (base 0)
	// so leading-zero decimals like `010` parse as 10 (P4-16 Section 6.4.3:
	// implicit octal is not part of the spec — only `0o12` is octal,
	// and that prefix is rejected by the lexer's hex-only branch
	// above). digitsStart strips the "0x" prefix for the hex case.
	val, err := strconv.ParseUint(string(l.src[digitsStart:l.pos]), base, 64)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return Token{}, l.syntaxErr(pos, "integer literal %q overflows uint64", lit)
		}
		return Token{}, l.syntaxErr(pos, "invalid integer literal %q", lit)
	}
	return Token{Kind: TokInt, Value: lit, Int: val, Pos: pos}, nil
}

func isIdentStart(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isIdentCont(b byte) bool {
	return isIdentStart(b) || (b >= '0' && b <= '9')
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}
