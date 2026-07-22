package parser

import "github.com/takehaya/bpf-ninja/pkg/kunai/lexer"

// SyntaxError is re-exported from the lexer package so callers of
// parser.Parse can type-assert against one consistent error type.
type SyntaxError = lexer.SyntaxError
