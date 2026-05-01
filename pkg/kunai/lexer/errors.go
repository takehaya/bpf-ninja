package lexer

import (
	"fmt"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
)

// SyntaxError is the error returned by the lexer (and re-used by the
// parser) on malformed DSL input. It carries enough context to point
// users at the offending character.
type SyntaxError struct {
	File    string
	Pos     ast.Position
	Message string
}

func (e *SyntaxError) Error() string {
	if e.File != "" {
		return fmt.Sprintf("%s:%s: %s", e.File, e.Pos, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Pos, e.Message)
}
