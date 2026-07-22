package resolve

import (
	"fmt"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/lexer"
)

// ResolveError is emitted for semantic problems (unknown protocol,
// missing dispatch constant, label collisions, etc.). Structurally
// identical to lexer.SyntaxError — aliasing keeps callers' type
// assertions uniform across the parse → resolve pipeline.
type ResolveError = lexer.SyntaxError

func errorf(pos ast.Position, format string, args ...any) error {
	return &ResolveError{Pos: pos, Message: fmt.Sprintf(format, args...)}
}
