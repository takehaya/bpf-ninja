package lexer

import (
	"fmt"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
)

// TokenKind enumerates the token varieties produced by the one-liner lexer.
type TokenKind int

const (
	TokEOF TokenKind = iota
	TokIdent
	TokInt   // structural-mode integer literal (e.g. "{1,8}", "443", "headers + 64")
	TokValue // value-mode classified literal (wraps *ast.Value)

	// Keywords
	TokWhere
	TokCapture
	TokAll
	TokAny
	TokHeaders
	TokAnd
	TokOr
	TokNot
	TokIn
	TokHas
	TokAction
	TokTrue  // bool literal: true
	TokFalse // bool literal: false

	// Punctuation
	TokSlash    // /
	TokAt       // @
	TokLBracket // [
	TokRBracket // ]
	TokLParen   // (
	TokRParen   // )
	TokLBrace   // {
	TokRBrace   // }
	TokComma    // ,
	TokDot      // .
	TokPipe     // |
	TokQuestion // ?
	TokPlus     // +
	TokStar     // *
	TokMinus    // -
	TokPercent  // %
	TokAmp      // &  (bitwise AND; logical AND is the `and` keyword)
	TokCaret    // ^  (bitwise XOR)
	TokShl      // << (bitwise shift left)
	TokShr      // >> (bitwise shift right)
	TokColon    // :  (bit-slice separator inside `[lo:hi]`)
	TokEq       // =  (standalone; "==" is TokEqEq)

	// Comparison
	TokEqEq // ==
	TokNeq  // !=
	TokLt   // <
	TokLe   // <=
	TokGt   // >
	TokGe   // >=
)

func (k TokenKind) String() string {
	switch k {
	case TokEOF:
		return "EOF"
	case TokIdent:
		return "identifier"
	case TokInt:
		return "integer"
	case TokValue:
		return "value"
	case TokWhere:
		return "'where'"
	case TokCapture:
		return "'capture'"
	case TokAll:
		return "'all'"
	case TokAny:
		return "'any'"
	case TokHeaders:
		return "'headers'"
	case TokAnd:
		return "'and'"
	case TokOr:
		return "'or'"
	case TokNot:
		return "'not'"
	case TokIn:
		return "'in'"
	case TokHas:
		return "'has'"
	case TokAction:
		return "'action'"
	case TokTrue:
		return "'true'"
	case TokFalse:
		return "'false'"
	case TokSlash:
		return "'/'"
	case TokAt:
		return "'@'"
	case TokLBracket:
		return "'['"
	case TokRBracket:
		return "']'"
	case TokLParen:
		return "'('"
	case TokRParen:
		return "')'"
	case TokLBrace:
		return "'{'"
	case TokRBrace:
		return "'}'"
	case TokComma:
		return "','"
	case TokDot:
		return "'.'"
	case TokPipe:
		return "'|'"
	case TokQuestion:
		return "'?'"
	case TokPlus:
		return "'+'"
	case TokStar:
		return "'*'"
	case TokMinus:
		return "'-'"
	case TokPercent:
		return "'%'"
	case TokAmp:
		return "'&'"
	case TokCaret:
		return "'^'"
	case TokShl:
		return "'<<'"
	case TokShr:
		return "'>>'"
	case TokColon:
		return "':'"
	case TokEq:
		return "'='"
	case TokEqEq:
		return "'=='"
	case TokNeq:
		return "'!='"
	case TokLt:
		return "'<'"
	case TokLe:
		return "'<='"
	case TokGt:
		return "'>'"
	case TokGe:
		return "'>='"
	}
	return fmt.Sprintf("TokenKind(%d)", int(k))
}

// Token is one lexeme together with its position and (when applicable)
// its decoded value.
type Token struct {
	Kind  TokenKind
	Text  string       // raw source text
	Int   uint64       // valid when Kind == TokInt
	Value *ast.Value   // valid when Kind == TokValue
	Pos   ast.Position
}

// keywords maps reserved identifier spellings to their token kinds.
var keywords = map[string]TokenKind{
	"where":   TokWhere,
	"capture": TokCapture,
	"all":     TokAll,
	"any":     TokAny,
	"headers": TokHeaders,
	"and":     TokAnd,
	"or":      TokOr,
	"not":     TokNot,
	"in":      TokIn,
	"has":     TokHas,
	"action":  TokAction,
	"true":    TokTrue,
	"false":   TokFalse,
}
