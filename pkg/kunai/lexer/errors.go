package lexer

import (
	"fmt"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
)

// SyntaxError is the error returned by the lexer (and re-used by the
// parser) on malformed DSL input. It carries enough context to point
// users at the offending character.
//
// Hint is an optional caller-side suggestion (e.g. "did you mean ==?")
// that an upstream layer may attach to provide a remediation tip. It
// is intentionally NOT folded into Error() — formatting is left to
// the caller so it can render hints with its own style (colour, prefix
// indentation, etc.). Existing call sites that build SyntaxError
// without setting Hint are unaffected (zero value preserves the
// previous Error() output verbatim).
type SyntaxError struct {
	File    string
	Pos     ast.Position
	Message string
	Hint    string
}

func (e *SyntaxError) Error() string {
	if e.File != "" {
		return fmt.Sprintf("%s:%s: %s", e.File, e.Pos, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Pos, e.Message)
}
